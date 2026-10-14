Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-Utc($Value) {
    if ($Value -is [datetime] -and $Value.Kind -eq [DateTimeKind]::Utc) { return [datetimeoffset]$Value }
    if ($Value -is [datetimeoffset] -and $Value.Offset -eq [timespan]::Zero) { return $Value }
    if ([string]$Value -notmatch '(Z|\+00:00)$') { throw 'Use an explicit UTC timestamp ending in Z or +00:00' }
    return [datetimeoffset]::Parse($Value, [cultureinfo]::InvariantCulture)
}

function Write-AtomicJson($Path, $Value) {
    $temp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $bytes = [text.encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 30))
        $stream = [io.file]::Open($temp, 'CreateNew', 'Write', 'None')
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        [io.file]::Move($temp, $Path, $true)
    } finally { if ([io.file]::Exists($temp)) { [io.file]::Delete($temp) } }
}

function Get-ChannelSnapshot($Channel) {
    $log = Get-WinEvent -ListLog $Channel -ErrorAction Stop
    if (-not $log.IsEnabled) { throw 'DISABLED' }
    $first = $null; $last = $null
    if ($log.RecordCount -gt 0) {
        $first = Get-WinEvent -LogName $Channel -Oldest -MaxEvents 1 -ErrorAction Stop
        $last = Get-WinEvent -LogName $Channel -MaxEvents 1 -ErrorAction Stop
    }
    return @{
        OldestId = if ($first) { [long]$first.RecordId } else { 0L }
        NewestId = if ($last) { [long]$last.RecordId } else { 0L }
        OldestUtc = if ($first) { $first.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
    }
}

function Read-EventPage($Channel, $From, $Through, $Cursor, $High, $Limit, $Predicate) {
    $a = $From.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $b = $Through.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ')
    $query = "*[System[TimeCreated[@SystemTime>'$a' and @SystemTime<='$b'] and EventRecordID>$Cursor and EventRecordID<=$High and ($Predicate)]]"
    try {
        Get-WinEvent -LogName $Channel -FilterXPath $query -Oldest -MaxEvents $Limit -ErrorAction Stop | ForEach-Object {
            @{ RecordId = [long]$_.RecordId; TimeUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); Id = $_.Id; Level = $_.Level; Provider = $_.ProviderName }
        }
    } catch { if ($_.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound') { throw } }
}

function Invoke-EventCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$StateDirectory,
        [Parameter(Mandatory)][string]$ThroughUtc,
        [scriptblock]$Snapshot = { param($c) Get-ChannelSnapshot $c },
        [scriptblock]$Page = { param($c,$a,$b,$cursor,$high,$limit,$predicate) Read-EventPage $c $a $b $cursor $high $limit $predicate }
    )
    $end = ConvertTo-Utc $ThroughUtc
    $start = ConvertTo-Utc $Config.StartUtc
    if ($end -le $start) { throw 'ThroughUtc must be after StartUtc' }
    if ($Config.PageSize -lt 1 -or $Config.PageSize -gt 10000 -or $Config.RecordCap -lt 1) { throw 'Invalid page size or record cap' }
    $names = @($Config.Channels | ForEach-Object { $_.Name })
    if (-not $names.Count -or @($names | Select-Object -Unique).Count -ne $names.Count) { throw 'Channel names must be nonempty and unique' }
    foreach ($channel in $Config.Channels) { if (-not $channel.Name -or -not $channel.Predicate) { throw 'Name and Predicate are required' } }
    # Bind state to the complete selection configuration. A changed selection needs a fresh directory.
    $identity = ConvertTo-Json -InputObject $Config -Depth 10 -Compress
    $directory = [io.path]::GetFullPath($StateDirectory)
    [io.directory]::CreateDirectory($directory) | Out-Null
    $lock = [io.file]::Open((Join-Path $directory '.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    try {
        $statePath = Join-Path $directory 'checkpoint.json'
        $state = @{ SchemaVersion = 1; Configuration = $identity; Channels = @{}; LastRun = $null }
        if (Test-Path -LiteralPath $statePath) {
            $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json -AsHashtable
            if ($state.SchemaVersion -ne 1 -or $state.Configuration -cne $identity) { throw 'Checkpoint schema/configuration mismatch; use a new state directory' }
        }
        $run = @{ SchemaVersion = 1; ThroughUtc = $end.UtcDateTime.ToString('o'); Channels = @(); Events = @() }
        foreach ($channel in $Config.Channels) {
            $name = $channel.Name
            $old = $state.Channels[$name]
            $from = if ($old) { ConvertTo-Utc $old.ThroughUtc } else { $start }
            if ($end -lt $from) { throw 'ThroughUtc precedes a saved channel checkpoint' }
            $coverage = @{ Channel = $name; FromUtc = $from.UtcDateTime.ToString('o'); ThroughUtc = $end.UtcDateTime.ToString('o'); Status = 'failed'; SelectedRecords = 0; Gaps = @(); Error = $null; Snapshot = $null }
            try {
                $before = & $Snapshot $name
                $coverage.Snapshot = $before
                if ($before.OldestUtc -and (ConvertTo-Utc $before.OldestUtc) -gt $from) { $coverage.Gaps += 'retention-start-after-window-start' }
                if ($old -and $before.NewestId -lt $old.NewestId) { $coverage.Gaps += 'record-id-decreased' }
                $rows = [collections.generic.list[object]]::new()
                $cursor = 0L
                do {
                    $limit = [int][math]::Min($Config.PageSize, $Config.RecordCap - $rows.Count + 1)
                    $batch = @(& $Page $name $from $end $cursor $before.NewestId $limit $channel.Predicate)
                    if ($batch.Count -gt $limit) { throw 'Page exceeded requested size' }
                    foreach ($row in $batch) {
                        $time = ConvertTo-Utc $row.TimeUtc
                        if ($time -le $from -or $time -gt $end) { throw 'Out-of-window event rejected' }
                        if ($row.RecordId -le $cursor -or $row.RecordId -gt $before.NewestId) { throw 'Invalid record cursor' }
                        $cursor = [long]$row.RecordId
                        $rows.Add(@{ Channel = $name; RecordId = $cursor; TimeUtc = $time.UtcDateTime.ToString('o'); Id = $row.Id; Level = $row.Level; Provider = $row.Provider })
                        if ($rows.Count -gt $Config.RecordCap) { throw 'Record cap exceeded' }
                    }
                } while ($batch.Count -eq $limit)
                $after = & $Snapshot $name
                if ($after.OldestId -ne $before.OldestId -or $after.NewestId -lt $before.NewestId) { throw 'Retention changed during collection; retry required' }
                $coverage.Status = if ($coverage.Gaps.Count) { 'complete-with-gaps' } else { 'complete' }
                $coverage.SelectedRecords = $rows.Count
                $run.Events += $rows.ToArray()
                $state.Channels[$name] = @{ ThroughUtc = $end.UtcDateTime.ToString('o'); NewestId = $before.NewestId }
            } catch {
                $coverage.Error = $_.Exception.Message
                if ($_.Exception.Message -eq 'DISABLED') { $coverage.Status = 'disabled' }
                elseif ($_.Exception -is [UnauthorizedAccessException] -or $_.Exception.InnerException -is [UnauthorizedAccessException] -or $_.Exception.HResult -eq -2147024891) { $coverage.Status = 'denied' }
            }
            $run.Channels += $coverage
        }
        # Immutable evidence first; checkpoint is the commit point. Orphans never advance state.
        $runName = 'run-' + [guid]::NewGuid().ToString('N') + '.json'
        Write-AtomicJson (Join-Path $directory $runName) $run
        $state.LastRun = $runName
        Write-AtomicJson $statePath $state
        return $run
    } finally { $lock.Dispose() }
}

Export-ModuleMember -Function Invoke-EventCoverage
