#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$StateDirectory,
    [Parameter(Mandatory)][string]$ThroughUtc
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'Live collection requires Windows PowerShell 7.2+ on Windows' }
Import-Module (Join-Path $PSScriptRoot 'Collector.psm1') -Force
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -AsHashtable
$result = Invoke-EventCoverage -Config $config -StateDirectory $StateDirectory -ThroughUtc $ThroughUtc
$result.Channels | Format-Table Channel, Status, SelectedRecords
if (@($result.Channels | Where-Object Status -ne 'complete').Count) { exit 2 }
