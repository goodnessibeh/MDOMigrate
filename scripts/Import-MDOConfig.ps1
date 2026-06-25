#Requires -Version 7.0
<#
.SYNOPSIS
    Recreates exported Microsoft Defender for Office 365 / EOP configuration in the TARGET tenant.

.DESCRIPTION
    Reads an export folder produced by Export-MDOConfig.ps1 and recreates each policy/rule in the
    connected tenant. Runs as a DRY RUN by default (prints what it would do); add -Execute to apply.

.PARAMETER Path
    The export folder produced by Export-MDOConfig.ps1. If omitted, the most recent export under
    <Desktop>\MDOMigrate-Exports is used automatically. You may also pass the export root, in which
    case the latest timestamped export beneath it is selected.

.PARAMETER Execute
    Actually write changes to the tenant. Omit for a safe dry run.

.PARAMETER IncludeCategory
    Limit to one or more categories: Policy, Rule, Quarantine, Singleton, PresetRule, TABL, TABLSpoof.

.PARAMETER IncludeType
    Limit to one or more specific types, e.g. AntiPhishPolicy, SafeLinksRule.

.PARAMETER IgnoreRecipientScope
    Drop recipient conditions (RecipientDomainIs, SentToMemberOf, ...) from rules. These reference
    tenant-specific domains and group identities that do not exist in the target tenant; omitting them
    lets rules import cleanly, after which you re-scope them to the target's domains/groups.

.PARAMETER Domain
    Optional override for the DESTINATION (target) tenant's domain. The session is verified to serve
    this domain before anything is written, so a session still signed into the source tenant can never
    be written to. By default it is derived from the UPN (the part after '@').

.PARAMETER UserPrincipalName
    Admin UPN to sign in / pre-fill the prompt. Defaults to the Destination.UserPrincipalName in tenants.json.

.PARAMETER ConfigPath
    Path to the tenant config file. Defaults to tenants.json in the repository root.

.EXAMPLE
    ./scripts/Import-MDOConfig.ps1                          # dry run, latest export on Desktop
    ./scripts/Import-MDOConfig.ps1 -Execute                 # apply latest export
    ./scripts/Import-MDOConfig.ps1 -IncludeCategory Policy,Rule -Execute
    ./scripts/Import-MDOConfig.ps1 -IgnoreRecipientScope -Execute
    ./scripts/Import-MDOConfig.ps1 -Path 'C:\backups\20260625-120000' -Execute   # explicit export folder
#>
[CmdletBinding()]
param(
    [string]$Path,
    [switch]$Execute,
    [string[]]$IncludeCategory,
    [string[]]$IncludeType,
    [switch]$IgnoreRecipientScope,
    [string]$Domain,
    [string]$UserPrincipalName,
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $RepoRoot 'src/MDOCommon.psm1') -Force
Import-Module (Join-Path $RepoRoot 'src/MDOImport.psm1') -Force

$Path = Resolve-MDOImportPath -Path $Path
Write-Host "Importing from: $Path" -ForegroundColor Cyan

$dest = Resolve-MDOTenant -Role Destination -ConfigPath $ConfigPath -Domain $Domain -UserPrincipalName $UserPrincipalName
Connect-MDOTenant -UserPrincipalName $dest.UserPrincipalName -TenantDomain $dest.Domain

# Final hard guard right before writing: never apply to the wrong tenant.
if ($Execute) { Assert-MDOTenantDomain -Domain $dest.Domain }

$importParams = @{ Path = $Path; Execute = $Execute; IgnoreRecipientScope = $IgnoreRecipientScope }
if ($IncludeCategory) { $importParams['IncludeCategory'] = $IncludeCategory }
if ($IncludeType)     { $importParams['IncludeType']     = $IncludeType }

Import-MDOConfiguration @importParams | Out-Null
