#Requires -Version 7.0
<#
    MDOImport.psm1
    Recreates exported MDO/EOP objects in the connected (target) tenant for config parity.
    Defaults to a DRY RUN; pass -Execute to write changes. Requires MDOCommon.psm1 to be loaded.
#>

# Quarantine policies that exist in every tenant and must not be recreated.
$Script:MDOBuiltInQuarantine = @(
    'AdminOnlyAccessPolicy',
    'DefaultFullAccessPolicy',
    'DefaultFullAccessWithNotificationPolicy',
    'NotificationEnabledPolicy'
)

function Test-MDOObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)][string]$Identity)
    try { return ($null -ne (& "Get-$Type" -Identity $Identity -ErrorAction Stop)) }
    catch { return $false }
}

function Import-MDOPolicyObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)]$Object, [switch]$Execute)

    $name = Get-MDOProperty $Object 'Name'
    $isDefault = [bool](Get-MDOProperty $Object 'IsDefault' $false)

    # Preset / Evaluation policies (Standard, Strict, Evaluation) are created by the preset-security and
    # Defender-evaluation features and already exist in the target under a DIFFERENT auto-generated name.
    # Trying to New- a second one fails ("Already there is a 'Standard' recommended policy"), so match the
    # existing one by RecommendedPolicyType and update it in place (overwrite) instead.
    $preset = Get-MDOProperty $Object 'RecommendedPolicyType'
    if ($preset -in @('Standard', 'Strict', 'Evaluation')) {
        $existingPreset = @(& "Get-$Type" -ErrorAction SilentlyContinue) |
            Where-Object { (Get-MDOProperty $_ 'RecommendedPolicyType') -eq $preset } |
            Select-Object -First 1
        if ($existingPreset) {
            $presetName = Get-MDOProperty $existingPreset 'Name'
            $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "Set-$Type"
            $splat['Identity'] = $presetName
            return Invoke-MDOAction -Cmdlet "Set-$Type" -Parameters $splat -Description "update $preset preset '$presetName'" -Execute:$Execute
        }
        # No existing preset of this type in the target: fall through and create it (self-healing in
        # Invoke-MDOAction drops any parameters the New- cmdlet rejects, e.g. IntraOrgFilterState).
    }

    if ($isDefault -or $name -eq 'Default' -or (Test-MDOObject -Type $Type -Identity $name)) {
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "Set-$Type"
        $splat['Identity'] = $name
        return Invoke-MDOAction -Cmdlet "Set-$Type" -Parameters $splat -Description "update '$name'" -Execute:$Execute
    }

    $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "New-$Type"
    $splat['Name'] = $name
    return Invoke-MDOAction -Cmdlet "New-$Type" -Parameters $splat -Description "create '$name'" -Execute:$Execute
}

# Group predicates on a rule that reference a mail-enabled group by identity.
$Script:MDORuleGroupParam = @('SentToMemberOf', 'ExceptIfSentToMemberOf', 'FromMemberOf', 'ExceptIfFromMemberOf')

function Test-MDOGroupPresent {
    <# True if $Identity resolves to a mail-enabled group in the target tenant. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Identity)
    try { if (Get-DistributionGroup -Identity $Identity -ErrorAction Stop) { return $true } } catch { $null = $_ }
    try {
        $r = Get-Recipient -Identity $Identity -ErrorAction Stop
        if ($r -and ((Get-MDOProperty $r 'RecipientTypeDetails') -match 'Group')) { return $true }
    } catch { $null = $_ }
    return $false
}

function Initialize-MDOPlaceholderGroup {
    <#
        Creates an empty distribution group (no members) to stand in for a group a rule targets that does
        not exist in the destination tenant. Keeps the original SMTP address when its domain is accepted
        in the target; otherwise lets Exchange assign one. Returns the identity to reference in the rule
        plus a result record for the summary.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Identity, [switch]$Execute)

    $alias = ($Identity -replace '[^0-9A-Za-z]', '')
    if ($alias.Length -gt 60) { $alias = $alias.Substring(0, 60) }
    if (-not $alias) { $alias = 'mdoGroup' }

    # New-DistributionGroup creates a mail-enabled universal distribution group by default (Exchange
    # Online does not accept a -Type parameter here). Keep the original SMTP only if its domain is
    # accepted in the target; otherwise let Exchange assign one.
    $params = @{ Name = $Identity; Alias = $alias }
    if ($Identity -match '@') {
        $domain = ($Identity -split '@', 2)[1]
        if ((Get-MDOConnectedDomain) -contains $domain) { $params['PrimarySmtpAddress'] = $Identity }
    }

    $desc = "auto-create distribution group '$Identity' (no members)"
    if (-not $Execute) {
        Write-Host "  [DRYRUN] New-DistributionGroup  $desc" -ForegroundColor Yellow
        return [pscustomobject]@{ Target = $Identity; Result = [pscustomobject]@{ Success = $true; DryRun = $true; Cmdlet = 'New-DistributionGroup'; Description = $desc; Error = $null; Healed = $null } }
    }
    try {
        $group = New-DistributionGroup @params -ErrorAction Stop
        $target = Get-MDOProperty $group 'PrimarySmtpAddress'
        if (-not $target) { $target = $Identity }
        Write-Host "  [OK]     New-DistributionGroup  $desc" -ForegroundColor Green
        return [pscustomobject]@{ Target = $target; Result = [pscustomobject]@{ Success = $true; DryRun = $false; Cmdlet = 'New-DistributionGroup'; Description = $desc; Error = $null; Healed = $null } }
    }
    catch {
        Write-Host "  [FAIL]   New-DistributionGroup  $desc" -ForegroundColor Red
        Write-Host "           $($_.Exception.Message)" -ForegroundColor DarkRed
        return [pscustomobject]@{ Target = $null; Result = [pscustomobject]@{ Success = $false; DryRun = $false; Cmdlet = 'New-DistributionGroup'; Description = $desc; Error = $_.Exception.Message; Healed = $null } }
    }
}

function Resolve-MDORuleGroup {
    <#
        Ensures every group a rule targets (SentToMemberOf, etc.) exists in the destination, auto-creating
        an empty placeholder for any that do not. Returns a remap of original->target identity and the
        result records of any groups created. Group params already in $Skip (e.g. when -IgnoreRecipientScope
        is set) are left alone.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Object,
        [string[]]$Skip = @(),
        [ValidateSet('Ask', 'Always', 'Never')][string]$CreateMissingGroups = 'Ask',
        [switch]$Execute
    )

    # Map value semantics: identity string = use that identity; $null = group is missing and was NOT
    # created (drop it from the rule predicate).
    $map = @{}
    $results = @()
    foreach ($param in $Script:MDORuleGroupParam) {
        if ($Skip -contains $param) { continue }
        foreach ($member in @(Get-MDOProperty $Object $param)) {
            if ([string]::IsNullOrWhiteSpace($member) -or $map.ContainsKey($member)) { continue }
            if (Test-MDOGroupPresent -Identity $member) { $map[$member] = $member; continue }

            if (-not (Confirm-MDOCreateGroup -Identity $member -Mode $CreateMissingGroups)) {
                Write-Host "  [SKIP]   group '$member' not created; it will be dropped from the rule." -ForegroundColor DarkGray
                $map[$member] = $null
                continue
            }
            $created = Initialize-MDOPlaceholderGroup -Identity $member -Execute:$Execute
            $results += $created.Result
            $map[$member] = if ($created.Target) { $created.Target } else { $null }
        }
    }
    return [pscustomobject]@{ Map = $map; Results = $results }
}

# Per-run decisions about creating missing groups, so the user is asked at most once per group, with
# 'all' / 'skip all' answers honoured for the rest of the run. Reset by Import-MDOConfiguration.
$Script:MDOGroupDecision  = @{}
$Script:MDOGroupCreateAll = $null   # $true = yes-to-all, $false = no-to-all, $null = keep asking

function Confirm-MDOCreateGroup {
    <#
        Decides whether to create a missing group. 'Always'/'Never' answer without asking. 'Ask' prompts
        once per group (Yes/No/All/Skip-all); a non-interactive host defaults to not creating.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Identity, [ValidateSet('Ask', 'Always', 'Never')][string]$Mode = 'Ask')

    if ($Mode -eq 'Always') { return $true }
    if ($Mode -eq 'Never')  { return $false }
    if ($null -ne $Script:MDOGroupCreateAll)             { return $Script:MDOGroupCreateAll }
    if ($Script:MDOGroupDecision.ContainsKey($Identity)) { return $Script:MDOGroupDecision[$Identity] }

    $interactive = $true
    try { $interactive = -not [System.Console]::IsInputRedirected } catch { $interactive = $false }
    if (-not $interactive) {
        Write-Host "  Group '$Identity' is missing and input is non-interactive; not creating (use -CreateMissingGroups Always to force)." -ForegroundColor DarkGray
        $Script:MDOGroupDecision[$Identity] = $false
        return $false
    }

    $answer = Read-Host "Rule targets group '$Identity' which does not exist in the destination. Create it empty (no members)? [Y]es / [N]o / [A]ll / [S]kip all"
    switch -Regex ($answer.Trim()) {
        '^(a|all)$'        { $Script:MDOGroupCreateAll = $true;  return $true }
        '^(s|skip)$'       { $Script:MDOGroupCreateAll = $false; return $false }
        '^(y|yes)$'        { $Script:MDOGroupDecision[$Identity] = $true;  return $true }
        default            { $Script:MDOGroupDecision[$Identity] = $false; return $false }
    }
}

function Import-MDORuleObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)]$Object,
        [string[]]$ExcludeParam = @(),
        [string]$LinkParam,
        [ValidateSet('Ask', 'Always', 'Never')][string]$CreateMissingGroups = 'Ask',
        [switch]$Execute
    )

    $name = Get-MDOProperty $Object 'Name'
    $results = @()

    # Ensure the groups this rule targets exist. Missing ones are created only with consent
    # (-CreateMissingGroups Ask prompts; Always/Never answer up front). Groups the user declines are
    # dropped from the predicate so the rule still imports. Skipped entirely under -IgnoreRecipientScope.
    $groups = Resolve-MDORuleGroup -Object $Object -Skip $ExcludeParam -CreateMissingGroups $CreateMissingGroups -Execute:$Execute
    $results += $groups.Results

    if (Test-MDOObject -Type $Type -Identity $name) {
        # The policy link (e.g. -SafeLinksPolicy) is fixed at creation; re-sending it on an update fails
        # with "Policy X already has rule X associated with it", so drop it from the Set- splat.
        $setExclude = if ($LinkParam) { @($ExcludeParam) + $LinkParam } else { $ExcludeParam }
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "Set-$Type" -Exclude $setExclude
        $splat['Identity'] = $name
        $verb = 'Set'; $desc = "update rule '$name'"
    }
    else {
        # The link to the policy (e.g. -AntiPhishPolicy) is carried automatically: the rule object has a
        # same-named property which ConvertTo-MDOSplat maps onto the matching New- parameter.
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "New-$Type" -Exclude $ExcludeParam
        $splat['Name'] = $name
        $verb = 'New'; $desc = "create rule '$name'"
    }

    foreach ($param in $Script:MDORuleGroupParam) {
        if ($splat.ContainsKey($param)) {
            # Remap to created/target identities; drop members the user declined to create (mapped to $null).
            $remapped = @(foreach ($m in @($splat[$param])) {
                if ($groups.Map.ContainsKey($m)) { if ($null -ne $groups.Map[$m]) { $groups.Map[$m] } } else { $m }
            })
            if ($remapped.Count) { $splat[$param] = $remapped } else { $splat.Remove($param) }
        }
    }

    $action = Invoke-MDOAction -Cmdlet "$verb-$Type" -Parameters $splat -Description $desc -Execute:$Execute
    $results += $action

    # Rule state (Enabled/Disabled) is not a New-/Set- parameter; apply it with Enable-/Disable-.
    $state = Get-MDOProperty $Object 'State'
    if ($state -eq 'Disabled') {
        $results += Invoke-MDOAction -Cmdlet "Disable-$Type" -Parameters @{ Identity = $name } -Description "disable rule '$name'" -Execute:$Execute
    }
    return $results
}

function Import-MDOSingletonObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)]$Object, [switch]$Execute)

    $type = $Entry.Type
    $identity = Get-MDOProperty $Entry 'Identity'
    if (-not $identity) { $identity = Get-MDOProperty $Object 'Name' }
    if (-not $identity) { $identity = Get-MDOProperty $Object 'Identity' }

    $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "Set-$type"
    $splat['Identity'] = $identity
    return Invoke-MDOAction -Cmdlet "Set-$type" -Parameters $splat -Description "update '$identity'" -Execute:$Execute
}

function Import-MDOPresetRuleObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)]$Object, [string[]]$ExcludeParam = @(), [switch]$Execute)

    $name = Get-MDOProperty $Object 'Name'
    if (Test-MDOObject -Type $Type -Identity $name) {
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "Set-$Type" -Exclude $ExcludeParam
        $splat['Identity'] = $name
        return Invoke-MDOAction -Cmdlet "Set-$Type" -Parameters $splat -Description "update preset rule '$name'" -Execute:$Execute
    }
    $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "New-$Type" -Exclude $ExcludeParam
    $splat['Name'] = $name
    return Invoke-MDOAction -Cmdlet "New-$Type" -Parameters $splat -Description "create preset rule '$name'" -Execute:$Execute
}

function Import-MDOQuarantineObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Object, [switch]$Execute)

    $name = Get-MDOProperty $Object 'Name'
    $policyType = Get-MDOProperty $Object 'QuarantinePolicyType'

    if ($policyType -eq 'GlobalQuarantinePolicy' -or $name -eq 'DefaultGlobalTag') {
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet 'Set-QuarantinePolicy'
        $splat['Identity'] = $name
        return Invoke-MDOAction -Cmdlet 'Set-QuarantinePolicy' -Parameters $splat -Description "update global quarantine settings '$name'" -Execute:$Execute
    }

    if ($MDOBuiltInQuarantine -contains $name) {
        Write-Host "  [SKIP]   built-in quarantine policy '$name'" -ForegroundColor DarkGray
        return [pscustomobject]@{ Success = $true; DryRun = (-not $Execute); Cmdlet = '(skip)'; Description = "built-in quarantine '$name'"; Error = $null }
    }

    if (Test-MDOObject -Type 'QuarantinePolicy' -Identity $name) {
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet 'Set-QuarantinePolicy'
        $splat['Identity'] = $name
        return Invoke-MDOAction -Cmdlet 'Set-QuarantinePolicy' -Parameters $splat -Description "update quarantine policy '$name'" -Execute:$Execute
    }

    $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet 'New-QuarantinePolicy'
    $splat['Name'] = $name
    return Invoke-MDOAction -Cmdlet 'New-QuarantinePolicy' -Parameters $splat -Description "create quarantine policy '$name'" -Execute:$Execute
}

function Import-MDOTablObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Object, [switch]$Execute)

    $listType = Get-MDOProperty $Object '_ListType'
    $value    = Get-MDOProperty $Object 'Value'
    $action   = Get-MDOProperty $Object 'Action'
    $notes    = Get-MDOProperty $Object 'Notes'
    $expires  = Get-MDOProperty $Object 'ExpirationDate'
    # ListSubType distinguishes normal tenant entries from AdvancedDelivery (phishing-simulation) URLs/
    # senders; preserve it so those entries land in the right category instead of the default.
    $subType  = Get-MDOProperty $Object 'ListSubType'

    if (-not $listType -or -not $value) {
        return [pscustomobject]@{ Success = $false; DryRun = (-not $Execute); Cmdlet = 'New-TenantAllowBlockListItems'; Description = 'incomplete TABL record'; Error = 'missing ListType/Value' }
    }

    $splat = @{ ListType = $listType; Entries = @($value) }
    if ($notes) { $splat['Notes'] = $notes }
    if ($subType) { $splat['ListSubType'] = $subType }
    if ($action -eq 'Block') { $splat['Block'] = $true } else { $splat['Allow'] = $true }
    if ($expires) { $splat['ExpirationDate'] = [datetime]$expires } else { $splat['NoExpiration'] = $true }

    $label = if ($subType -and $subType -ne 'Tenant') { "$listType/$subType" } else { $listType }
    return Invoke-MDOAction -Cmdlet 'New-TenantAllowBlockListItems' -Parameters $splat -Description "$label $action '$value'" -Execute:$Execute
}

function Import-MDOTablSpoofObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Object, [switch]$Execute)

    $spoofedUser = Get-MDOProperty $Object 'SpoofedUser'
    $infra       = Get-MDOProperty $Object 'SendingInfrastructure'
    $spoofType   = Get-MDOProperty $Object 'SpoofType'
    $action      = Get-MDOProperty $Object 'Action'

    if (-not $spoofedUser -or -not $infra) {
        return [pscustomobject]@{ Success = $false; DryRun = (-not $Execute); Cmdlet = 'New-TenantAllowBlockListSpoofItems'; Description = 'incomplete spoof record'; Error = 'missing SpoofedUser/SendingInfrastructure' }
    }

    $splat = @{
        Identity              = 'Default'
        SpoofedUser           = $spoofedUser
        SendingInfrastructure = $infra
        SpoofType             = $spoofType
        Action                = $action
    }
    return Invoke-MDOAction -Cmdlet 'New-TenantAllowBlockListSpoofItems' -Parameters $splat -Description "spoof $action '$spoofedUser'" -Execute:$Execute
}

# Per-run state for provisioning the Tenant Allow/Block List. Reset by Import-MDOConfiguration.
$Script:MDOTablDecision        = $null    # $true = configure, $false = skip, $null = ask
$Script:MDOOrgCustomizationDone = $false   # Enable-OrganizationCustomization already attempted this run

function Confirm-MDOConfigureTabl {
    <#
        Decides whether to provision the tenant for the Tenant Allow/Block List when it is missing.
        'Always'/'Never' answer without asking; 'Ask' prompts once (Configure/Skip). Non-interactive
        hosts default to skipping.
    #>
    [CmdletBinding()]
    param([ValidateSet('Ask', 'Always', 'Never')][string]$Mode = 'Ask')

    if ($Mode -eq 'Always') { return $true }
    if ($Mode -eq 'Never')  { return $false }
    if ($null -ne $Script:MDOTablDecision) { return $Script:MDOTablDecision }

    $interactive = $true
    try { $interactive = -not [System.Console]::IsInputRedirected } catch { $interactive = $false }
    if (-not $interactive) {
        Write-Host "  Tenant Allow/Block List is not provisioned and input is non-interactive; skipping (use -ConfigureTenantAllowBlockList Always to provision)." -ForegroundColor DarkGray
        $Script:MDOTablDecision = $false
        return $false
    }

    $answer = Read-Host "The Tenant Allow/Block List requires organization customization on the destination tenant. Configure it now (runs Enable-OrganizationCustomization) or skip the Tenant Allow/Block List? [C]onfigure / [S]kip"
    $Script:MDOTablDecision = ($answer.Trim() -match '^(c|configure|y|yes)$')
    return $Script:MDOTablDecision
}

function Enable-MDOOrganizationCustomization {
    <#
        Provisions the tenant's organization customization, which the Tenant Allow/Block List requires.
        Treats an already-enabled tenant as success. Returns $true when provisioning is in place/started.
    #>
    [CmdletBinding()]
    param([switch]$Execute)

    if (-not $Execute) {
        Write-Host "  [DRYRUN] Enable-OrganizationCustomization  (provision tenant for Tenant Allow/Block List)" -ForegroundColor Yellow
        return $true
    }
    if (-not (Get-Command Enable-OrganizationCustomization -ErrorAction SilentlyContinue)) {
        Write-Host "  Cannot auto-provision here: 'Enable-OrganizationCustomization' is not available in this session." -ForegroundColor Yellow
        Write-Host "  Enable organization customization in the destination (run Enable-OrganizationCustomization from a full Exchange Online PowerShell session, or enable the Tenant Allow/Block List in the Microsoft Defender portal), then re-run with -IncludeType TenantAllowBlockListItems." -ForegroundColor DarkGray
        return $false
    }
    try {
        Enable-OrganizationCustomization -ErrorAction Stop
        Write-Host "  [OK]     Enable-OrganizationCustomization  - provisioning started (can take time to fully propagate)" -ForegroundColor Green
        return $true
    }
    catch {
        if ($_.Exception.Message -match 'already enabled|not required|already been enabled') {
            Write-Host "  Organization customization is already enabled." -ForegroundColor DarkGray
            return $true
        }
        Write-Host "  [FAIL]   Enable-OrganizationCustomization: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Write-MDOImportSummary {
    [CmdletBinding()]
    param([array]$Results)

    $applied = @($Results | Where-Object { $_.Success -and -not $_.DryRun }).Count
    $planned = @($Results | Where-Object { $_.DryRun }).Count
    $failed  = @($Results | Where-Object { -not $_.Success }).Count

    Write-Host "`n================ SUMMARY ================" -ForegroundColor Cyan
    Write-Host (" Total actions     : {0}" -f $Results.Count)
    Write-Host (" Applied           : {0}" -f $applied) -ForegroundColor Green
    Write-Host (" Planned (dry-run) : {0}" -f $planned) -ForegroundColor Yellow
    $failColour = if ($failed) { 'Red' } else { 'Gray' }
    Write-Host (" Failed            : {0}" -f $failed) -ForegroundColor $failColour

    $adjusted = @($Results | Where-Object { $_.Healed })
    if ($adjusted.Count) {
        Write-Host "`n Adjusted (dropped invalid parameter(s), then applied):" -ForegroundColor Yellow
        foreach ($result in $adjusted) {
            Write-Host ("  - {0} {1}: dropped {2}" -f $result.Cmdlet, $result.Description, ($result.Healed -join ', ')) -ForegroundColor DarkYellow
        }
    }

    if ($failed) {
        Write-Host "`n Failures:" -ForegroundColor Red
        foreach ($result in ($Results | Where-Object { -not $_.Success })) {
            Write-Host ("  - {0} {1}: {2}" -f $result.Cmdlet, $result.Description, $result.Error) -ForegroundColor DarkRed
        }
    }
}

function Import-MDOConfiguration {
    <#
        Reads an export folder and recreates each object in the connected tenant.
        DRY RUN by default; pass -Execute to apply. Optionally filter with -IncludeCategory / -IncludeType.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$Execute,
        [string[]]$IncludeCategory,
        [string[]]$IncludeType,
        [switch]$IgnoreRecipientScope,
        [ValidateSet('Ask', 'Always', 'Never')][string]$CreateMissingGroups = 'Ask',
        [ValidateSet('Ask', 'Always', 'Never')][string]$ConfigureTenantAllowBlockList = 'Ask'
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "Export folder not found: $Path" }
    # Reset per-run consent state for auto-creating missing groups and provisioning the TABL.
    $Script:MDOGroupDecision       = @{}
    $Script:MDOGroupCreateAll      = $null
    $Script:MDOTablDecision        = $null
    $Script:MDOOrgCustomizationDone = $false

    if (-not $Execute) {
        Write-Host '=== DRY RUN: no changes will be made. Re-run with -Execute to apply. ===' -ForegroundColor Yellow
    }
    else {
        Write-Host '=== EXECUTE MODE: changes WILL be written to the connected tenant. ===' -ForegroundColor Magenta
    }

    # Recipient conditions reference tenant-specific domains and group identities that do not exist in the
    # target tenant. -IgnoreRecipientScope drops them so rules import cleanly; re-scope them afterwards.
    $ruleExclude = @()
    if ($IgnoreRecipientScope) {
        $ruleExclude = @(
            'RecipientDomainIs', 'ExceptIfRecipientDomainIs',
            'SentTo', 'ExceptIfSentTo',
            'SentToMemberOf', 'ExceptIfSentToMemberOf'
        )
        Write-Host 'Recipient scope (domains / groups) will be omitted from rules (-IgnoreRecipientScope).' -ForegroundColor Yellow
    }

    # Proactively provision the destination for the Tenant Allow/Block List before importing its entries,
    # so propagation starts as early as possible (it can take a while). Only when entries exist in the
    # export, the TABL types are in scope, and we're actually writing. Confirm-MDOConfigureTabl honours
    # the -ConfigureTenantAllowBlockList mode (Always = no prompt, Ask = prompt once, Never = skip) and
    # caches the decision so the per-entry fallback never re-asks.
    $tablTypes   = @('TenantAllowBlockListItems', 'TenantAllowBlockListSpoofItems')
    $tablInScope = (-not $IncludeType     -or @($IncludeType     | Where-Object { $tablTypes -contains $_ }).Count -gt 0) -and
                   (-not $IncludeCategory -or @($IncludeCategory | Where-Object { @('TABL', 'TABLSpoof') -contains $_ }).Count -gt 0)
    $hasTablExport = ($tablTypes | Where-Object { Test-Path -LiteralPath (Join-Path $Path "$_.json") }).Count -gt 0
    if ($Execute -and $tablInScope -and $hasTablExport -and ($ConfigureTenantAllowBlockList -ne 'Never') -and (Confirm-MDOConfigureTabl -Mode $ConfigureTenantAllowBlockList)) {
        Write-Host "`nProvisioning the destination tenant for the Tenant Allow/Block List..." -ForegroundColor Cyan
        Enable-MDOOrganizationCustomization -Execute:$Execute | Out-Null
        $Script:MDOOrgCustomizationDone = $true
    }

    $registry = Get-MDOTypeRegistry | Sort-Object Order
    $results = @()

    foreach ($entry in $registry) {
        $type = $entry.Type
        if ($IncludeType     -and ($IncludeType     -notcontains $type))          { continue }
        if ($IncludeCategory -and ($IncludeCategory -notcontains $entry.Category)) { continue }

        $file = Join-Path $Path "$type.json"
        if (-not (Test-Path -LiteralPath $file)) { Write-Verbose "No export file for $type, skipping."; continue }

        $objects = @(Get-Content -LiteralPath $file -Raw | ConvertFrom-Json)
        if ($objects.Count -eq 0) { continue }
        Write-Host "`n--- $type ($($objects.Count)) ---" -ForegroundColor Cyan

        # Pre-flight: Exchange Online only exposes cmdlets the signed-in admin has an RBAC role for, and
        # the set is fixed at connection time. If the write cmdlet for this type isn't present, skip the
        # whole type cleanly (don't fail every object or abort the run).
        $writeCmdlet = switch ($entry.Category) {
            'Quarantine' { 'New-QuarantinePolicy' }
            'Singleton'  { "Set-$type" }
            'TABL'       { 'New-TenantAllowBlockListItems' }
            'TABLSpoof'  { 'New-TenantAllowBlockListSpoofItems' }
            default      { "New-$type" }
        }
        if (-not (Get-Command $writeCmdlet -ErrorAction SilentlyContinue)) {
            Write-Host "  [SKIP]   '$writeCmdlet' is not available in this session - skipping $type." -ForegroundColor Yellow
            Write-Host "           The signed-in admin can't manage $type here. If you just assigned the RBAC role (e.g. 'Transport Rules' for mail flow rules), it can take time to take effect - reconnect (the cmdlet set is fixed at sign-in) once it has, then re-run with -IncludeType $type." -ForegroundColor DarkGray
            continue
        }

        $index = 0
        foreach ($obj in $objects) {
            $index++
            $itemResult = switch ($entry.Category) {
                'Policy'     { Import-MDOPolicyObject     -Type $type -Object $obj -Execute:$Execute }
                'Rule'       { Import-MDORuleObject       -Type $type -Object $obj -ExcludeParam $ruleExclude -LinkParam (Get-MDOProperty $entry 'LinkParam') -CreateMissingGroups $CreateMissingGroups -Execute:$Execute }
                'TransportRule' { Import-MDORuleObject    -Type $type -Object $obj -ExcludeParam $ruleExclude -CreateMissingGroups $CreateMissingGroups -Execute:$Execute }
                'Quarantine' { Import-MDOQuarantineObject -Object $obj -Execute:$Execute }
                'Singleton'  { Import-MDOSingletonObject  -Entry $entry -Object $obj -Execute:$Execute }
                'PresetRule' { Import-MDOPresetRuleObject -Type $type -Object $obj -ExcludeParam $ruleExclude -Execute:$Execute }
                'TABL'       { Import-MDOTablObject       -Object $obj -Execute:$Execute }
                'TABLSpoof'  { Import-MDOTablSpoofObject  -Object $obj -Execute:$Execute }
            }
            $results += $itemResult

            # The Tenant Allow/Block List throws "Value cannot be null. Parameter name: exchangeConfigUnit"
            # on EVERY entry when the tenant isn't provisioned for it. On the first such failure, offer to
            # configure the tenant (Enable-OrganizationCustomization) and retry; otherwise skip the rest
            # instead of repeating the same failure for thousands of entries.
            if ($entry.Category -in @('TABL', 'TABLSpoof') -and $itemResult -and -not $itemResult.Success -and ($itemResult.Error -match 'exchangeConfigUnit')) {
                $retried = $false
                if (-not $Script:MDOOrgCustomizationDone -and (Confirm-MDOConfigureTabl -Mode $ConfigureTenantAllowBlockList)) {
                    $provisioned = Enable-MDOOrganizationCustomization -Execute:$Execute
                    $Script:MDOOrgCustomizationDone = $true
                    if ($provisioned) {
                        $retry = if ($entry.Category -eq 'TABL') { Import-MDOTablObject -Object $obj -Execute:$Execute } else { Import-MDOTablSpoofObject -Object $obj -Execute:$Execute }
                        $results += $retry
                        if ($retry.Success) { $retried = $true }
                    }
                }
                if (-not $retried) {
                    Write-Host ("  [SKIP]   Tenant Allow/Block List unavailable; skipping the remaining {0} {1} entr(y/ies)." -f ($objects.Count - $index), $type) -ForegroundColor Yellow
                    if ($Script:MDOOrgCustomizationDone) {
                        Write-Host "           Provisioning was started but can take time to propagate - re-run later with -IncludeType $type." -ForegroundColor DarkGray
                    }
                    break
                }
            }
        }
    }

    Write-MDOImportSummary -Results $results
    return $results
}

Export-ModuleMember -Function Import-MDOConfiguration
