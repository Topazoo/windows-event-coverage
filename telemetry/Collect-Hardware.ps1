#Requires -Version 7.2
[CmdletBinding()]
param([switch]$Collect, [string]$OutputPath)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $Collect) {
    Write-Output 'Plan only. -Collect -OutputPath NEW.json opts into read-only CPU, RAM, graphics and OS CIM inventory. No serial numbers, hostnames, firmware writes or sensor driver access.'
    return
}
if (-not $IsWindows) { throw 'Live inventory requires Windows.' }
if (-not $OutputPath) { throw 'OutputPath is required.' }
# Reserve a new output before querying. Never overwrite an existing artifact.
$stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $checks = @(
        @{ Name='cpu'; Class='Win32_Processor'; Properties=@('Name','NumberOfCores','NumberOfLogicalProcessors') },
        @{ Name='memory'; Class='Win32_PhysicalMemory'; Properties=@('Capacity','Speed','ConfiguredClockSpeed') },
        @{ Name='graphics'; Class='Win32_VideoController'; Properties=@('Name','DriverVersion') },
        @{ Name='os'; Class='Win32_OperatingSystem'; Properties=@('Caption','Version','BuildNumber') }
    )
    $started = [DateTime]::UtcNow.ToString('o')
    $results = foreach ($check in $checks) {
        try {
            $rows = @(Get-CimInstance -ClassName $check.Class -Property $check.Properties -OperationTimeoutSec 15 -ErrorAction Stop | Select-Object -Property $check.Properties)
            @{ component=$check.Name; status=$(if ($rows.Count) {'read'} else {'empty'}); rows=$rows }
        } catch {
            # Exception text can contain machine names and paths; retain only status.
            @{ component=$check.Name; status='failed'; rows=@() }
        }
    }
    $result = @{ schema='hardware-inventory-v1'; startedUTC=$started; completedUTC=[DateTime]::UtcNow.ToString('o'); components=@($results); limits='Inventory only. No sensors, health, stability or crash-cause verdict. Empty and failed components remain unknown.' }
    $bytes = [Text.Encoding]::UTF8.GetBytes(($result | ConvertTo-Json -Depth 8))
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
} finally { $stream.Dispose() }
if (@($results | Where-Object status -ne 'read').Count) { exit 2 }
