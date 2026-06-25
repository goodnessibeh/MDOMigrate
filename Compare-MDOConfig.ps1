#Requires -Version 7.0
<#
.SYNOPSIS
    Compares MDO/EOP configuration between a source export and a target tenant (parity check).

.DESCRIPTION
    Reports objects missing/extra in the target and per-property value differences, ignoring
    identity/UUID/timestamp fields. Compare against another export folder (-DifferencePath) or snapshot
    the currently connected target tenant on the fly (-ExportTarget).

.PARAMETER ReferencePath
    The SOURCE export folder produced by Export-MDOConfig.ps1.

.PARAMETER DifferencePath
    A TARGET export folder to compare against. Omit and use -ExportTarget to snapshot the live tenant.

.PARAMETER ExportTarget
    Connect to the target tenant and export it to a temporary folder, then compare.

.PARAMETER IncludeType
    Limit the comparison to specific types, e.g. SafeLinksPolicy.

.PARAMETER CsvPath
    Optional path to also write the drift report as CSV.

.EXAMPLE
    ./Compare-MDOConfig.ps1 -ExportTarget -CsvPath parity.csv     # latest Desktop export vs live target
    ./Compare-MDOConfig.ps1 -ReferencePath C:\backups\source -DifferencePath C:\backups\target
#>
[CmdletBinding()]
param(
    [string]$ReferencePath,
    [string]$DifferencePath,
    [switch]$ExportTarget,
    [string[]]$IncludeType,
    [string]$UserPrincipalName,
    [string]$CsvPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src/MDOCommon.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src/MDOExport.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src/MDOCompare.psm1') -Force

# Default the reference (source) to the most recent export on the Desktop.
$ReferencePath = Resolve-MDOImportPath -Path $ReferencePath
Write-Host "Reference (source): $ReferencePath" -ForegroundColor Cyan

if (-not $DifferencePath) {
    if (-not $ExportTarget) {
        throw 'Provide -DifferencePath (a target export folder) or -ExportTarget to snapshot the connected tenant.'
    }
    Connect-MDOTenant -UserPrincipalName $UserPrincipalName
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $DifferencePath = Join-Path ([System.IO.Path]::GetTempPath()) "mdo-target-$stamp"
    Write-Host "Snapshotting target tenant to $DifferencePath ..." -ForegroundColor Cyan
    Export-MDOConfiguration -Path $DifferencePath | Out-Null
}

$compareParams = @{ ReferencePath = $ReferencePath; DifferencePath = $DifferencePath }
if ($IncludeType) { $compareParams['IncludeType'] = $IncludeType }
$findings = Compare-MDOConfiguration @compareParams

if ($CsvPath) {
    $findings | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding utf8
    Write-Host "`nDrift report written to $CsvPath" -ForegroundColor Green
}
