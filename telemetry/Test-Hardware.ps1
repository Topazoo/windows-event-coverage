#Requires -Version 7.2
$ErrorActionPreference = 'Stop'
$global:telemetryTestQueries = 0
$global:telemetryTestFailGraphics = $false
function Get-CimInstance {
    param($ClassName, $Property, $OperationTimeoutSec, $ErrorAction)
    $global:telemetryTestQueries++
    if ($global:telemetryTestFailGraphics -and $ClassName -eq 'Win32_VideoController') { throw 'Synthetic failure' }
    $row = @{}
    foreach ($name in $Property) { $row[$name] = 'synthetic' }
    $row['SerialNumber'] = 'must-not-escape'
    [pscustomobject]$row
}
$collector = Join-Path $PSScriptRoot 'Collect-Hardware.ps1'
& $collector | Out-Null
if ($global:telemetryTestQueries -ne 0) { throw 'Plan queried hardware' }
if (-not $IsWindows) { Write-Output 'Plan passed; mocked Windows collection cases require Windows.'; return }
$directory = Join-Path ([IO.Path]::GetTempPath()) ('telemetry-test-' + [guid]::NewGuid())
[IO.Directory]::CreateDirectory($directory) | Out-Null
try {
    $output = Join-Path $directory 'hardware.json'
    & $collector -Collect -OutputPath $output
    $data = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    if ($global:telemetryTestQueries -ne 4 -or $data.components.Count -ne 4) { throw 'Expected four mocked queries' }
    if ((Get-Content -LiteralPath $output -Raw) -match 'must-not-escape|SerialNumber') { throw 'Property allowlist failed' }
    $before = Get-Content -LiteralPath $output -Raw
    $rejected = $false
    try { & $collector -Collect -OutputPath $output } catch { $rejected = $true }
    if (-not $rejected -or $global:telemetryTestQueries -ne 4 -or (Get-Content -LiteralPath $output -Raw) -ne $before) { throw 'Existing output preservation failed' }
    $global:telemetryTestFailGraphics = $true
    $partial = Join-Path $directory 'partial.json'
    & $collector -Collect -OutputPath $partial
    $data = Get-Content -LiteralPath $partial -Raw | ConvertFrom-Json
    if (@($data.components | Where-Object status -eq 'failed').Count -ne 1) { throw 'Failure coverage missing' }
    Write-Output 'Passed: plan, four mocked queries, property allowlist, exclusive output, failed component.'
} finally {
    # Only exact files created by this test; no recursive deletion.
    foreach ($name in @('hardware.json', 'partial.json')) {
        $file = Join-Path $directory $name
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
    [IO.Directory]::Delete($directory)
}
exit 0
