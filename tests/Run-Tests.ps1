#requires -Version 7.2
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../Collector.psm1') -Force
$root = Join-Path ([io.path]::GetTempPath()) ('coverage-tests-' + [guid]::NewGuid().ToString('N'))
[io.directory]::CreateDirectory($root) | Out-Null
$config = @{ StartUtc='2025-01-01T00:00:00Z'; PageSize=2; RecordCap=4; Channels=@(@{Name='Synthetic';Predicate='EventID>=0'}) }
$end = '2025-01-01T01:00:00Z'
$snapshot = { param($c) @{OldestId=1; NewestId=10; OldestUtc='2024-12-31T23:00:00Z'} }
$empty = { param($c,$a,$b,$cursor,$high,$limit,$predicate) }
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
function Run($Name, $Test) { & $Test; Write-Output "PASS $Name" }
function Invoke-Test($Name, $Page=$empty, $Snapshot=$snapshot) {
    Invoke-EventCoverage -Config $config -StateDirectory (Join-Path $root $Name) -ThroughUtc $end -Snapshot $Snapshot -Page $Page
}
function Row($Id, $Time='2025-01-01T00:30:00Z') { @{RecordId=$Id;TimeUtc=$Time;Id=1;Level=4;Provider='Synthetic'} }
Run 'empty successful window advances' {
    $r = Invoke-Test empty
    Assert ($r.Channels[0].Status -eq 'complete') 'Empty failed'
}
Run 'pagination and inclusive end' {
    $r = Invoke-Test pages { param($c,$a,$b,$cursor,$high,$limit,$predicate) 1..4 | Where-Object { $_ -gt $cursor } | Select-Object -First $limit | ForEach-Object { Row $_ '2025-01-01T01:00:00Z' } }
    Assert ($r.Events.Count -eq 4 -and $r.Channels[0].Status -eq 'complete') 'Pagination failed'
}
Run 'exclusive start and outside bounds reject entire channel' {
    foreach ($time in @('2025-01-01T00:00:00Z','2025-01-01T01:00:00.0000001Z','2024-12-31T23:59:59Z')) {
        $page = { param($c,$a,$b,$cursor,$high,$limit,$predicate) Row 1 $time }.GetNewClosure()
        $r = Invoke-Test ('boundary-'+[guid]::NewGuid()) $page
        Assert ($r.Events.Count -eq 0 -and $r.Channels[0].Status -eq 'failed') 'Bounds accepted'
    }
}
Run 'cap overflow preserves checkpoint' {
    $r = Invoke-Test cap { param($c,$a,$b,$cursor,$high,$limit,$predicate) 1..5 | Where-Object { $_ -gt $cursor } | Select-Object -First $limit | ForEach-Object { Row $_ } }
    $cp = Get-Content (Join-Path $root 'cap/checkpoint.json') -Raw | ConvertFrom-Json -AsHashtable
    Assert ($r.Events.Count -eq 0 -and $cp.Channels.Count -eq 0) 'Cap advanced state'
}
Run 'denied and disabled are retried' {
    foreach ($kind in @('denied','disabled')) {
        $snap = if ($kind -eq 'denied') { { throw [UnauthorizedAccessException]::new('Synthetic denial') } } else { { throw 'DISABLED' } }
        $r = Invoke-Test $kind $empty $snap
        Assert ($r.Channels[0].Status -eq $kind) 'Wrong failure status'
        $r = Invoke-Test $kind
        Assert ($r.Channels[0].Status -eq 'complete') 'Retry skipped'
    }
}
Run 'rollover is an explicit gap' {
    $r = Invoke-Test rollover $empty { @{OldestId=5;NewestId=10;OldestUtc='2025-01-01T00:10:00Z'} }
    Assert ($r.Channels[0].Status -eq 'complete-with-gaps') 'Missing rollover gap'
}
Run 'record reset detected across runs' {
    $null = Invoke-Test reset
    $r = Invoke-Test reset $empty { @{OldestId=1;NewestId=3;OldestUtc='2024-12-31T23:00:00Z'} }
    Assert ($r.Channels[0].Gaps -contains 'record-id-decreased') 'Reset undetected'
}
Run 'interrupted page preserves progress and retries' {
    $null = Invoke-Test interruption
    $path = Join-Path $root 'interruption/checkpoint.json'
    $prior = (Get-Content $path -Raw | ConvertFrom-Json -AsHashtable).Channels.Synthetic.ThroughUtc
    $r = Invoke-EventCoverage -Config $config -StateDirectory (Split-Path $path) -ThroughUtc '2025-01-01T02:00:00Z' -Snapshot $snapshot -Page { throw 'Synthetic interruption' }
    $now = (Get-Content $path -Raw | ConvertFrom-Json -AsHashtable).Channels.Synthetic.ThroughUtc
    Assert ($prior -eq $now -and $r.Events.Count -eq 0) 'Interrupted window advanced'
}
Run 'lock excludes another writer' {
    $dir = Join-Path $root 'locked'; [io.directory]::CreateDirectory($dir) | Out-Null
    $lock = [io.file]::Open((Join-Path $dir '.lock'), 'OpenOrCreate','ReadWrite','None')
    $rejected = $false
    try { try { $null = Invoke-Test locked } catch { $rejected = $true } } finally { $lock.Dispose() }
    Assert $rejected 'Concurrent writer accepted'
}
Run 'atomic-write interruption retains old file' {
    $module = Get-Module Collector
    & $module {
        param($root)
        $path = Join-Path $root 'atomic.json'
        Write-AtomicJson $path @{Value='old'}
        $reader = [io.file]::Open($path,'Open','Read','Read')
        try {
            # Windows refuses replacement of an open file without delete sharing.
            if ($IsWindows) {
                $blocked = $false
                try { Write-AtomicJson $path @{Value='new'} } catch { $blocked = $true }
                if (-not $blocked) { throw 'Replacement unexpectedly succeeded' }
            }
        } finally { $reader.Dispose() }
        if ($IsWindows -and (Get-Content $path -Raw | ConvertFrom-Json).Value -ne 'old') { throw 'Old checkpoint lost' }
        Write-AtomicJson $path @{Value='committed'}
        if ((Get-Content $path -Raw | ConvertFrom-Json).Value -ne 'committed') { throw 'Commit failed' }
    } $root
}
Run 'duplicate cursor fails' {
    $r = Invoke-Test cursor { Row 1; Row 1 }
    Assert ($r.Channels[0].Status -eq 'failed') 'Duplicate accepted'
}
Run 'configuration change rejected' {
    $null = Invoke-Test config
    $config.PageSize = 3
    $rejected = $false
    try { $null = Invoke-Test config } catch { $rejected = $true } finally { $config.PageSize = 2 }
    Assert $rejected 'Configuration silently changed'
}
Run 'retention changes during read preserve checkpoint' {
    $script:snapshotCalls = 0
    $r = Invoke-Test moving $empty {
        $script:snapshotCalls++
        @{OldestId=$script:snapshotCalls;NewestId=10;OldestUtc='2024-12-31T23:00:00Z'}
    }
    Assert ($r.Channels[0].Status -eq 'failed') 'Retention race accepted'
}
Run 'channel checkpoints advance independently' {
    $config.Channels += @{Name='Denied';Predicate='EventID>=0'}
    try {
        $r = Invoke-Test independent $empty {
            param($c)
            if ($c -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic denial') }
            @{OldestId=1;NewestId=10;OldestUtc='2024-12-31T23:00:00Z'}
        }
        $cp = Get-Content (Join-Path $root 'independent/checkpoint.json') -Raw | ConvertFrom-Json -AsHashtable
        Assert ($cp.Channels.Count -eq 1 -and $cp.Channels.ContainsKey('Synthetic')) 'Channel states coupled'
    } finally { $config.Channels = @($config.Channels[0]) }
}
Write-Output "All synthetic tests passed. Temporary fixtures: $root"
