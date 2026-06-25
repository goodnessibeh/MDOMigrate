#Requires -Version 7.0
<#
.SYNOPSIS
    Exports all Microsoft Defender for Office 365 / EOP policy configuration from the SOURCE tenant.

.DESCRIPTION
    Connects to Exchange Online + Security & Compliance PowerShell as a direct admin and writes one
    JSON file per policy type (plus a manifest) into a timestamped folder. Feed that folder to
    Import-MDOConfig.ps1 against the target tenant for configuration parity.

.PARAMETER OutputPath
    Base folder for the export. A timestamped sub-folder is created beneath it. Default: ./mdo-export

.PARAMETER UserPrincipalName
    Optional admin UPN to pre-fill the sign-in prompt.

.EXAMPLE
    ./Export-MDOConfig.ps1
    ./Export-MDOConfig.ps1 -OutputPath C:\backups -UserPrincipalName admin@source.onmicrosoft.com
#>
[CmdletBinding()]
param(
    [string]$OutputPath = './mdo-export',
    [string]$UserPrincipalName
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src/MDOCommon.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src/MDOExport.psm1') -Force

Connect-MDOTenant -UserPrincipalName $UserPrincipalName

$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$target = Join-Path $OutputPath $stamp

Export-MDOConfiguration -Path $target | Out-Null
Write-Host "`nDone. Source-tenant configuration saved under: $target" -ForegroundColor Green
Write-Host "Next: ./Import-MDOConfig.ps1 -Path '$target'   (dry run; add -Execute to apply)" -ForegroundColor Cyan
