#Requires -Version 7.0
<#
.SYNOPSIS
    Scopes a set of MDO threat-policy rules to every accepted domain in the tenant.

.DESCRIPTION
    For the named rule set, sets -RecipientDomainIs to all accepted domains. Uses Get-AcceptedDomain
    (Exchange Online) instead of Microsoft Graph, so no extra Graph sign-in/scopes are required.
    Runs as a dry run by default; add -Execute to apply.

    NOTE: For the built-in Standard/Strict *preset* security policies, scope is controlled through
    Set-EOPProtectionPolicyRule / Set-ATPProtectionPolicyRule rather than the per-type rules below.

.PARAMETER PolicyName
    The Identity shared by the per-type rules to update (e.g. "Standard Preset Security Policy - Contoso").

.PARAMETER Execute
    Apply the change. Omit for a dry run.

.EXAMPLE
    ./Set-DefenderForOffice365RulesForAllDomains.ps1 -PolicyName 'Contoso Standard'            # preview
    ./Set-DefenderForOffice365RulesForAllDomains.ps1 -PolicyName 'Contoso Standard' -Execute   # apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PolicyName,
    [switch]$Execute
)

Import-Module ExchangeOnlineManagement -DisableNameChecking
try { $null = Get-AcceptedDomain -ErrorAction Stop } catch { Connect-ExchangeOnline -ShowBanner:$false }

$domains = (Get-AcceptedDomain).DomainName
Write-Host "Scoping rules for '$PolicyName' to $($domains.Count) domain(s)." -ForegroundColor Cyan

$ruleTypes = 'AntiPhishRule', 'HostedContentFilterRule', 'MalwareFilterRule', 'SafeAttachmentRule', 'SafeLinksRule'

foreach ($ruleType in $ruleTypes) {
    $rule = & "Get-$ruleType" -Identity $PolicyName -ErrorAction SilentlyContinue
    if (-not $rule) {
        Write-Warning "No $ruleType named '$PolicyName' - skipping."
        continue
    }

    if ($Execute) {
        & "Set-$ruleType" -Identity $PolicyName -RecipientDomainIs $domains
        Write-Host "  [OK]     $ruleType" -ForegroundColor Green
    }
    else {
        Write-Host "  [DRYRUN] Set-$ruleType -Identity '$PolicyName' -RecipientDomainIs $($domains -join ',')" -ForegroundColor Yellow
    }
}
