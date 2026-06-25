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

    if ($isDefault -or $name -eq 'Default' -or (Test-MDOObject -Type $Type -Identity $name)) {
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "Set-$Type"
        $splat['Identity'] = $name
        return Invoke-MDOAction -Cmdlet "Set-$Type" -Parameters $splat -Description "update '$name'" -Execute:$Execute
    }

    $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "New-$Type"
    $splat['Name'] = $name
    return Invoke-MDOAction -Cmdlet "New-$Type" -Parameters $splat -Description "create '$name'" -Execute:$Execute
}

function Import-MDORuleObject {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)]$Object, [string[]]$ExcludeParam = @(), [switch]$Execute)

    $name = Get-MDOProperty $Object 'Name'

    if (Test-MDOObject -Type $Type -Identity $name) {
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "Set-$Type" -Exclude $ExcludeParam
        $splat['Identity'] = $name
        $action = Invoke-MDOAction -Cmdlet "Set-$Type" -Parameters $splat -Description "update rule '$name'" -Execute:$Execute
    }
    else {
        # The link to the policy (e.g. -AntiPhishPolicy) is carried automatically: the rule object has a
        # same-named property which ConvertTo-MDOSplat maps onto the matching New- parameter.
        $splat = ConvertTo-MDOSplat -InputObject $Object -TargetCmdlet "New-$Type" -Exclude $ExcludeParam
        $splat['Name'] = $name
        $action = Invoke-MDOAction -Cmdlet "New-$Type" -Parameters $splat -Description "create rule '$name'" -Execute:$Execute
    }

    # Rule state (Enabled/Disabled) is not a New-/Set- parameter; apply it with Enable-/Disable-.
    $state = Get-MDOProperty $Object 'State'
    if ($state -eq 'Disabled') {
        Invoke-MDOAction -Cmdlet "Disable-$Type" -Parameters @{ Identity = $name } -Description "disable rule '$name'" -Execute:$Execute | Out-Null
    }
    return $action
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

    if (-not $listType -or -not $value) {
        return [pscustomobject]@{ Success = $false; DryRun = (-not $Execute); Cmdlet = 'New-TenantAllowBlockListItems'; Description = 'incomplete TABL record'; Error = 'missing ListType/Value' }
    }

    $splat = @{ ListType = $listType; Entries = @($value) }
    if ($notes) { $splat['Notes'] = $notes }
    if ($action -eq 'Block') { $splat['Block'] = $true } else { $splat['Allow'] = $true }
    if ($expires) { $splat['ExpirationDate'] = [datetime]$expires } else { $splat['NoExpiration'] = $true }

    return Invoke-MDOAction -Cmdlet 'New-TenantAllowBlockListItems' -Parameters $splat -Description "$listType $action '$value'" -Execute:$Execute
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
        [switch]$IgnoreRecipientScope
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "Export folder not found: $Path" }

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

        foreach ($obj in $objects) {
            switch ($entry.Category) {
                'Policy'     { $results += Import-MDOPolicyObject     -Type $type -Object $obj -Execute:$Execute }
                'Rule'       { $results += Import-MDORuleObject       -Type $type -Object $obj -ExcludeParam $ruleExclude -Execute:$Execute }
                'Quarantine' { $results += Import-MDOQuarantineObject -Object $obj -Execute:$Execute }
                'Singleton'  { $results += Import-MDOSingletonObject  -Entry $entry -Object $obj -Execute:$Execute }
                'PresetRule' { $results += Import-MDOPresetRuleObject -Type $type -Object $obj -ExcludeParam $ruleExclude -Execute:$Execute }
                'TABL'       { $results += Import-MDOTablObject       -Object $obj -Execute:$Execute }
                'TABLSpoof'  { $results += Import-MDOTablSpoofObject  -Object $obj -Execute:$Execute }
            }
        }
    }

    Write-MDOImportSummary -Results $results
    return $results
}

Export-ModuleMember -Function Import-MDOConfiguration
