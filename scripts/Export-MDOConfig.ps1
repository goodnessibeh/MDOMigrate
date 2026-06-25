#Requires -Version 7.0
<#
.SYNOPSIS
    Exports all Microsoft Defender for Office 365 / EOP policy configuration from the SOURCE tenant.

.DESCRIPTION
    Connects to Exchange Online + Security & Compliance PowerShell as a direct admin and writes one
    JSON file per policy type (plus a manifest) into a timestamped folder. Feed that folder to
    Import-MDOConfig.ps1 against the target tenant for configuration parity.

.PARAMETER OutputPath
    Base folder for the export. A timestamped sub-folder is created beneath it.
    Default: <Desktop>\MDOMigrate-Exports

.PARAMETER Domain
    The SOURCE tenant's domain (e.g. source.onmicrosoft.com). Used to verify the session is signed
    into the right tenant before exporting. Defaults to the Source.Domain in tenants.json.

.PARAMETER UserPrincipalName
    Admin UPN to pre-fill the sign-in prompt. Defaults to the Source.UserPrincipalName in tenants.json.

.PARAMETER ConfigPath
    Path to the tenant config file. Defaults to tenants.json in the repository root.

.EXAMPLE
    ./scripts/Export-MDOConfig.ps1
    ./scripts/Export-MDOConfig.ps1 -OutputPath C:\backups -UserPrincipalName admin@source.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$Domain,
    [string]$UserPrincipalName,
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $RepoRoot 'src/MDOCommon.psm1') -Force
Import-Module (Join-Path $RepoRoot 'src/MDOExport.psm1') -Force

if (-not $OutputPath) { $OutputPath = Get-MDODefaultExportRoot }

$source = Resolve-MDOTenant -Role Source -ConfigPath $ConfigPath -Domain $Domain -UserPrincipalName $UserPrincipalName
Connect-MDOTenant -UserPrincipalName $source.UserPrincipalName -TenantDomain $source.Domain

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$target = Join-Path $OutputPath $stamp

Export-MDOConfiguration -Path $target | Out-Null
Write-Host "`nDone. Source-tenant configuration saved under: $target" -ForegroundColor Green
Write-Host "Next: ./scripts/Import-MDOConfig.ps1 -Path '$target'   (dry run; add -Execute to apply)" -ForegroundColor Cyan
