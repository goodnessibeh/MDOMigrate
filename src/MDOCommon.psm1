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

function Get-MDODefaultExportRoot {
    <#
        Returns the default location for exports: <Desktop>\MDOMigrate-Exports.
        Uses the OS Desktop path (handles OneDrive-redirected desktops on Windows) and falls back to
        ~/Desktop when the OS does not report one (e.g. Linux/macOS).
    #>
    [CmdletBinding()]
    param()
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = Join-Path $HOME 'Desktop' }
    return (Join-Path $desktop 'MDOMigrate-Exports')
}

function Resolve-MDOImportPath {
    <#
        Resolves which export folder to import/compare from. If $Path is given and contains a
        manifest.json it is used as-is; otherwise the most recent timestamped sub-folder (under $Path,
        or under the default export root when $Path is empty) that contains a manifest is selected.
    #>
    [CmdletBinding()]
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { $Path = Get-MDODefaultExportRoot }
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Export location not found: $Path. Run Export-MDOConfig.ps1 first."
    }
    if (Test-Path -LiteralPath (Join-Path $Path 'manifest.json')) { return (Resolve-Path -LiteralPath $Path).Path }

    $latest = Get-ChildItem -LiteralPath $Path -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'manifest.json') } |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if (-not $latest) { throw "No export (manifest.json) found under $Path. Run Export-MDOConfig.ps1 first." }
    return $latest.FullName
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

function Get-MDOConfig {
    <#
        Loads the tenant config file (tenants.json) that names the Source and Destination tenants.
        Default location is config/tenants.json in the repository root. Returns the parsed object, or
        $null when no config file exists. Only the admin UPN is needed per tenant (the domain is derived
        from it); a Domain may still be supplied to override. Shape:

            { "Source":      { "UserPrincipalName": "admin@source.onmicrosoft.com" },
              "Destination": { "UserPrincipalName": "admin@destination.onmicrosoft.com" } }
    #>
    [CmdletBinding()]
    param([string]$ConfigPath)

    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        $ConfigPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'config/tenants.json'
    }
    if (-not (Test-Path -LiteralPath $ConfigPath)) { return $null }
    try { return (Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json) }
    catch { throw "Failed to read tenant config '$ConfigPath': $($_.Exception.Message)" }
}

function Get-MDODomainFromUpn {
    <#
        Derives a tenant domain from an admin UPN: the part after '@'. A UPN like
        admin@contoso.onmicrosoft.com can only sign in if that domain is verified in the tenant, so the
        derived domain is a valid value for the wrong-tenant guard. Returns $null for an empty/invalid UPN.
    #>
    [CmdletBinding()]
    param([string]$UserPrincipalName)
    if ([string]::IsNullOrWhiteSpace($UserPrincipalName) -or $UserPrincipalName -notmatch '@') { return $null }
    return ($UserPrincipalName -split '@', 2)[1].Trim()
}

function Resolve-MDOTenant {
    <#
        Resolves the UserPrincipalName (and the domain to guard on) for one tenant role
        ('Source' or 'Destination'). The UPN is the only thing you need to provide; the domain is
        auto-derived from it (the part after '@'). Precedence for both: explicit parameter, then the
        config file. A Domain in the config (legacy/optional) still overrides the derived one.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Source', 'Destination')][string]$Role,
        [string]$ConfigPath,
        [string]$Domain,
        [string]$UserPrincipalName
    )

    $entry = $null
    $config = Get-MDOConfig -ConfigPath $ConfigPath
    if ($config) { $entry = Get-MDOProperty $config $Role }

    if ([string]::IsNullOrWhiteSpace($UserPrincipalName) -and $entry) { $UserPrincipalName = Get-MDOProperty $entry 'UserPrincipalName' }
    if ([string]::IsNullOrWhiteSpace($Domain)            -and $entry) { $Domain            = Get-MDOProperty $entry 'Domain' }
    if ([string]::IsNullOrWhiteSpace($Domain)) { $Domain = Get-MDODomainFromUpn $UserPrincipalName }

    return [pscustomobject]@{
        Role              = $Role
        Domain            = $Domain
        UserPrincipalName = $UserPrincipalName
    }
}

function Get-MDOConnectedDomain {
    <# Returns the accepted domains of the currently connected Exchange Online tenant, or $null if not connected. #>
    [CmdletBinding()]
    param()
    try { return @((Get-AcceptedDomain -ErrorAction Stop).DomainName) }
    catch { return $null }
}

function Assert-MDOTenantDomain {
    <#
        Hard guard: throws unless the connected Exchange Online tenant serves $Domain. Call this right
        before any write so a misdirected session (e.g. still signed into the source tenant) can never
        be written to. A no-op when $Domain is empty.
    #>
    [CmdletBinding()]
    param([string]$Domain)

    if ([string]::IsNullOrWhiteSpace($Domain)) { return }
    $domains = Get-MDOConnectedDomain
    if (-not $domains) {
        throw "Not connected to Exchange Online; cannot verify the target tenant '$Domain'."
    }
    if ($domains -notcontains $Domain) {
        throw "Connected tenant does NOT serve '$Domain' (accepted domains: $($domains -join ', ')). " +
              "Refusing to write. Sign in with an admin of the '$Domain' tenant."
    }
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

        Tenant awareness: pass -TenantDomain to bind the connection to a specific tenant. An existing
        session is re-used only when it serves that domain; otherwise it is disconnected and a fresh
        sign-in to the requested tenant is prompted. This is what lets export (source) and import
        (destination) authenticate to two different tenants in succession from one shell. After
        connecting, the tenant is verified to serve -TenantDomain (it throws if not), so a misdirected
        session can never be used. Use -ForceReconnect to always drop any open session first.
    #>
    [CmdletBinding()]
    param(
        [string]$UserPrincipalName,
        [string]$TenantDomain,
        [switch]$SkipSecurityCompliance,
        [switch]$ForceReconnect
    )

    if (-not (Get-Module ExchangeOnlineManagement -ListAvailable)) {
        Write-Host 'Installing ExchangeOnlineManagement module...' -ForegroundColor Cyan
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module ExchangeOnlineManagement -DisableNameChecking -ErrorAction Stop

    $currentDomains = Get-MDOConnectedDomain
    $exoConnected   = $null -ne $currentDomains

    # Decide whether the open session (if any) can be re-used.
    $servesTarget = -not $TenantDomain -or ($exoConnected -and ($currentDomains -contains $TenantDomain))
    if ($exoConnected -and ($ForceReconnect -or -not $servesTarget)) {
        if ($TenantDomain -and -not $servesTarget) {
            Write-Host "Open session is a different tenant (serves: $($currentDomains -join ', ')); it does not serve '$TenantDomain'." -ForegroundColor Yellow
        }
        Write-Host 'Disconnecting current Exchange Online / Security & Compliance session...' -ForegroundColor Yellow
        # Disconnect-ExchangeOnline closes both the EXO and the IPPS connections in this session.
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        $exoConnected = $false
    }

    if (-not $exoConnected) {
        $for = if ($TenantDomain) { " ($TenantDomain)" } else { '' }
        Write-Host "Connecting to Exchange Online$for..." -ForegroundColor Cyan
        $exoParams = @{ ShowBanner = $false }
        if ($UserPrincipalName) { $exoParams['UserPrincipalName'] = $UserPrincipalName }
        Connect-ExchangeOnline @exoParams
    }

    # Hard verify: confirm we landed on the requested tenant before anyone writes to it.
    if ($TenantDomain) {
        Assert-MDOTenantDomain -Domain $TenantDomain
        Write-Host "Connected to tenant serving '$TenantDomain'." -ForegroundColor Green
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

Export-ModuleMember -Function Get-MDOReadOnlyProperty, Get-MDODefaultExportRoot, Resolve-MDOImportPath, Get-MDOProperty, Get-MDOConfig, Get-MDODomainFromUpn, Resolve-MDOTenant, Get-MDOConnectedDomain, Assert-MDOTenantDomain, Get-MDOTypeRegistry, Connect-MDOTenant, ConvertTo-MDOSplat, Invoke-MDOAction
