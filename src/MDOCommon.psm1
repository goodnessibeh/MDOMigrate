#Requires -Version 7.0
<#
    MDOCommon.psm1
    Shared building blocks for the MDO export/import tooling:
      - Connect-MDOTenant      : connect Exchange Online + Security & Compliance PowerShell (direct admin)
      - Get-MDOTypeRegistry    : catalogue of every policy/rule type we handle and how to handle it
      - ConvertTo-MDOSplat      : turn an exported object into a valid splat for a New-/Set- cmdlet
      - Invoke-MDOAction        : run (or dry-run) a single create/update action with consistent logging
      - Get-MDOProperty         : safe property access for objects deserialised from JSON
#>

# Read-only, tenant-specific, identity/UUID/timestamp properties. These must never be replayed into a
# New-/Set- cmdlet in another tenant (they cause "identity/uuid" errors) and are ignored by both the
# importer and the parity comparison.
$Script:MDOReadOnlyProperty = @(
    'Identity', 'Guid', 'Id', 'ObjectId', 'ImmutableId', 'ExchangeObjectId', 'ExchangeVersion',
    'OrganizationId', 'OriginatingServer', 'DistinguishedName', 'ObjectCategory', 'ObjectClass',
    'ObjectState', 'WhenChanged', 'WhenChangedUTC', 'WhenCreated', 'WhenCreatedUTC',
    'OrganizationalUnitRoot', 'IsValid', 'PolicyGuid', 'RuleGuid', 'BuildVersion',
    'MajorVersion', 'MinorVersion', 'CmdletResultSize',
    'RunspaceId', 'PSComputerName', 'PSShowComputerName', 'PSSourceJobInstanceId'
)

function Get-MDOReadOnlyProperty {
    <# Returns the list of read-only/identity/UUID properties that are never replayed or compared. #>
    [CmdletBinding()]
    param()
    return $Script:MDOReadOnlyProperty
}

function Get-MDOProperty {
    <# Safe property read: returns $Default when the property is absent (no StrictMode surprises). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Object,
        [Parameter(Mandatory)][string] $Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $Default
}

function Get-MDOTypeRegistry {
    <#
        Catalogue of MDO/EOP object types.
        Category drives how the importer recreates each object:
          Policy     - custom threat policy (New- or Set- for the built-in 'Default')
          Rule       - threat-policy rule (imported after policies; links to its policy by same-named param)
          Quarantine - quarantine policy (custom recreated; built-ins skipped; global is Set-only)
          Singleton  - one fixed object, Set- only (no New- cmdlet)
          PresetRule - Standard/Strict preset security-policy rule
          TABL/TABLSpoof - Tenant Allow/Block List entries (dedicated handlers)
        Order controls import sequence (policies before rules, singletons last).
    #>
    [CmdletBinding()]
    param()

    @(
        # --- Custom threat policies ---
        [pscustomobject]@{ Type = 'MalwareFilterPolicy';            Category = 'Policy';     Order = 10 }
        [pscustomobject]@{ Type = 'HostedContentFilterPolicy';      Category = 'Policy';     Order = 10 }
        [pscustomobject]@{ Type = 'HostedOutboundSpamFilterPolicy'; Category = 'Policy';     Order = 10 }
        [pscustomobject]@{ Type = 'AntiPhishPolicy';                Category = 'Policy';     Order = 10 }
        [pscustomobject]@{ Type = 'SafeAttachmentPolicy';           Category = 'Policy';     Order = 10 }
        [pscustomobject]@{ Type = 'SafeLinksPolicy';                Category = 'Policy';     Order = 10 }

        # --- Quarantine policies (imported FIRST: content-filter policies reference them by name) ---
        [pscustomobject]@{ Type = 'QuarantinePolicy';               Category = 'Quarantine'; Order = 5 }

        # --- Threat-policy rules (after policies) ---
        [pscustomobject]@{ Type = 'MalwareFilterRule';              Category = 'Rule'; LinkParam = 'MalwareFilterPolicy';            Order = 20 }
        [pscustomobject]@{ Type = 'HostedContentFilterRule';        Category = 'Rule'; LinkParam = 'HostedContentFilterPolicy';      Order = 20 }
        [pscustomobject]@{ Type = 'HostedOutboundSpamFilterRule';   Category = 'Rule'; LinkParam = 'HostedOutboundSpamFilterPolicy'; Order = 20 }
        [pscustomobject]@{ Type = 'AntiPhishRule';                  Category = 'Rule'; LinkParam = 'AntiPhishPolicy';                Order = 20 }
        [pscustomobject]@{ Type = 'SafeAttachmentRule';             Category = 'Rule'; LinkParam = 'SafeAttachmentPolicy';           Order = 20 }
        [pscustomobject]@{ Type = 'SafeLinksRule';                  Category = 'Rule'; LinkParam = 'SafeLinksPolicy';                Order = 20 }

        # --- Singletons (Set- only) ---
        [pscustomobject]@{ Type = 'HostedConnectionFilterPolicy';   Category = 'Singleton'; Identity = 'Default'; Order = 10 }
        [pscustomobject]@{ Type = 'AtpPolicyForO365';               Category = 'Singleton'; Identity = 'Default'; Order = 30 }
        [pscustomobject]@{ Type = 'ATPBuiltInProtectionRule';       Category = 'Singleton'; Identity = $null;     Order = 40 }

        # --- Preset security-policy rules ---
        [pscustomobject]@{ Type = 'EOPProtectionPolicyRule';        Category = 'PresetRule'; Order = 40 }
        [pscustomobject]@{ Type = 'ATPProtectionPolicyRule';        Category = 'PresetRule'; Order = 40 }

        # --- Tenant Allow/Block List ---
        [pscustomobject]@{ Type = 'TenantAllowBlockListItems';      Category = 'TABL';      Order = 50 }
        [pscustomobject]@{ Type = 'TenantAllowBlockListSpoofItems'; Category = 'TABLSpoof'; Order = 50 }
    )
}

function Connect-MDOTenant {
    <#
        Connects to Exchange Online and Security & Compliance PowerShell as a direct tenant admin.
        Re-uses an existing session if one is already open.
    #>
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [switch]$SkipSecurityCompliance
    )

    if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
        Write-Host 'Installing ExchangeOnlineManagement module...' -ForegroundColor Cyan
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module ExchangeOnlineManagement -DisableNameChecking -ErrorAction Stop

    $exoConnected = $false
    try { $null = Get-AcceptedDomain -ErrorAction Stop; $exoConnected = $true } catch { $exoConnected = $false }
    if (-not $exoConnected) {
        Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan
        $exoParams = @{ ShowBanner = $false }
        if ($UserPrincipalName) { $exoParams['UserPrincipalName'] = $UserPrincipalName }
        Connect-ExchangeOnline @exoParams
    }

    if (-not $SkipSecurityCompliance) {
        $ippsConnected = $false
        try { $null = Get-ProtectionAlert -ErrorAction Stop | Select-Object -First 1; $ippsConnected = $true } catch { $ippsConnected = $false }
        if (-not $ippsConnected) {
            Write-Host 'Connecting to Security & Compliance PowerShell...' -ForegroundColor Cyan
            $ippsParams = @{}
            if ($UserPrincipalName) { $ippsParams['UserPrincipalName'] = $UserPrincipalName }
            Connect-IPPSSession @ippsParams
        }
    }
}

function ConvertTo-MDOSplat {
    <#
        Builds a parameter hashtable for $TargetCmdlet from $InputObject, including only properties
        that are real parameters of that cmdlet. Identity/Name are excluded (the caller sets them),
        as are common parameters, null/blank values and empty collections.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $InputObject,
        [Parameter(Mandatory)][string] $TargetCmdlet,
        [string[]] $Exclude = @()
    )

    $command = Get-Command $TargetCmdlet -ErrorAction Stop
    $validParams = $command.Parameters.Keys
    $commonParams = [System.Management.Automation.Cmdlet]::CommonParameters +
                    [System.Management.Automation.Cmdlet]::OptionalCommonParameters
    # Name set by caller; MakeDefault skipped so we never flip a tenant's default policy; the read-only
    # list (Identity, Guid, WhenChanged, ...) is dropped so cross-tenant identity/UUID values never replay.
    $alwaysSkip = @('Name', 'MakeDefault') + $Script:MDOReadOnlyProperty + $Exclude

    $splat = @{}
    foreach ($property in $InputObject.PSObject.Properties) {
        $name = $property.Name
        if ($validParams -notcontains $name)  { continue }
        if ($commonParams -contains $name)    { continue }
        if ($alwaysSkip -contains $name)      { continue }

        $value = $property.Value
        if ($null -eq $value) { continue }
        if (($value -is [string]) -and [string]::IsNullOrWhiteSpace($value)) { continue }

        if (($value -is [System.Collections.IEnumerable]) -and ($value -isnot [string])) {
            $items = @($value)
            if ($items.Count -eq 0) { continue }
            $value = $items
        }
        $splat[$name] = $value
    }
    return $splat
}

function Invoke-MDOAction {
    <#
        Runs one create/update action. With -Execute it calls the cmdlet (errors are caught, never fatal);
        without -Execute it only reports what would happen. Always returns a result record for the summary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Cmdlet,
        [hashtable]$Parameters = @{},
        [string]$Description,
        [switch]$Execute
    )

    $paramSummary = (($Parameters.Keys | Sort-Object) -join ', ')
    if (-not $Execute) {
        Write-Host "  [DRYRUN] $Cmdlet  $Description" -ForegroundColor Yellow
        Write-Verbose "           params: $paramSummary"
        return [pscustomobject]@{ Success = $true; DryRun = $true; Cmdlet = $Cmdlet; Description = $Description; Error = $null }
    }

    try {
        & $Cmdlet @Parameters -ErrorAction Stop | Out-Null
        Write-Host "  [OK]     $Cmdlet  $Description" -ForegroundColor Green
        return [pscustomobject]@{ Success = $true; DryRun = $false; Cmdlet = $Cmdlet; Description = $Description; Error = $null }
    }
    catch {
        Write-Host "  [FAIL]   $Cmdlet  $Description" -ForegroundColor Red
        Write-Host "           $($_.Exception.Message)" -ForegroundColor DarkRed
        return [pscustomobject]@{ Success = $false; DryRun = $false; Cmdlet = $Cmdlet; Description = $Description; Error = $_.Exception.Message }
    }
}

Export-ModuleMember -Function Get-MDOReadOnlyProperty, Get-MDOProperty, Get-MDOTypeRegistry, Connect-MDOTenant, ConvertTo-MDOSplat, Invoke-MDOAction
