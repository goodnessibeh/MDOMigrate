#Requires -Version 7.0
<#
.SYNOPSIS
    Recreates exported Microsoft Defender for Office 365 / EOP configuration in the TARGET tenant.

.DESCRIPTION
    Reads an export folder produced by Export-MDOConfig.ps1 and recreates each policy/rule in the
    connected tenant. Runs as a DRY RUN by default (prints what it would do); add -Execute to apply.

.PARAMETER Path
    The timestamped export folder produced by Export-MDOConfig.ps1.

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

.PARAMETER UserPrincipalName
    Optional admin UPN to pre-fill the sign-in prompt.

.EXAMPLE
    ./Import-MDOConfig.ps1 -Path ./mdo-export/20260625-120000                 # dry run, everything
    ./Import-MDOConfig.ps1 -Path ./mdo-export/20260625-120000 -Execute        # apply everything
    ./Import-MDOConfig.ps1 -Path ./mdo-export/20260625-120000 -IncludeCategory Policy,Rule -Execute
    ./Import-MDOConfig.ps1 -Path ./mdo-export/20260625-120000 -IgnoreRecipientScope -Execute
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Execute,
    [string[]]$IncludeCategory,
    [string[]]$IncludeType,
    [switch]$IgnoreRecipientScope,
    [string]$UserPrincipalName
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src/MDOCommon.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src/MDOImport.psm1') -Force

Connect-MDOTenant -UserPrincipalName $UserPrincipalName

$importParams = @{ Path = $Path; Execute = $Execute; IgnoreRecipientScope = $IgnoreRecipientScope }
if ($IncludeCategory) { $importParams['IncludeCategory'] = $IncludeCategory }
if ($IncludeType)     { $importParams['IncludeType']     = $IncludeType }

Import-MDOConfiguration @importParams | Out-Null
