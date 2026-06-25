#Requires -Version 7.0
<#
.SYNOPSIS
    One-command, end-to-end MDO/EOP migration: export from the SOURCE tenant and import into the
    DESTINATION tenant, all from a single shell with full logging.

.DESCRIPTION
    This is the entry point for the whole pipeline. It reads the tenant config (tenants.json) for the
    Source and Destination domains/UPNs, then runs every step so you never have to call the individual
    scripts by hand:

        1. Connect to the SOURCE tenant      -> export its MDO/EOP configuration to a timestamped folder.
        2. Connect to the DESTINATION tenant -> import that configuration.
           (The source session is dropped and you sign in to the destination in succession.)
        3. (optional) Re-snapshot the destination and report configuration drift.

    SAFETY: the import runs as a DRY RUN by default (it only prints what it would do). Pass -Live to
    actually write changes. Before any write, the connected tenant is verified to serve the configured
    Destination.Domain, so a session still signed into the source tenant can never be written to.

    Any tenant UPN left empty in the config is prompted for in the terminal at run time.

    Everything printed is also captured to a transcript log under <export base>\logs.

.PARAMETER ConfigPath
    Path to the tenant config file. Default: tenants.json in this folder. Copy tenants.example.json to
    tenants.json and fill it in. Only the admin UPN is needed per tenant; the domain used by the
    wrong-tenant guard is derived from the UPN. Shape:
        { "Source":      { "UserPrincipalName": "admin@source.onmicrosoft.com" },
          "Destination": { "UserPrincipalName": "admin@destination.onmicrosoft.com" } }

.PARAMETER Live
    Actually write changes to the destination tenant. Omit (or pass -DryRun) for a safe simulation.

.PARAMETER DryRun
    Explicitly request a dry run (this is already the default). Cannot be combined with -Live.

.PARAMETER SourceDomain / SourceUserPrincipalName
    Override the Source entry from the config.

.PARAMETER DestinationDomain / DestinationUserPrincipalName
    Override the Destination entry from the config.

.PARAMETER OutputPath
    Base folder for the export. A timestamped sub-folder is created beneath it.
    Default: <Desktop>\MDOMigrate-Exports

.PARAMETER SkipExport
    Skip the export step and import from an existing export instead (latest under OutputPath, or
    -ExportPath if given). Useful to re-run an import without re-exporting the source.

.PARAMETER ExportPath
    Import from this specific export folder instead of exporting fresh (implies -SkipExport).

.PARAMETER SkipCompare
    Skip the parity comparison. By default, after the import the destination tenant is re-snapshotted and
    a source-vs-destination drift report is printed on completion.

.PARAMETER IncludeCategory / IncludeType / IgnoreRecipientScope
    Passed through to the import step (see Import-MDOConfig.ps1).

.PARAMETER CreateMissingGroups
    When a rule targets a distribution group absent in the destination: Ask (default, prompt per group),
    Always (create empty groups without asking), or Never (drop the missing group from the rule).

.PARAMETER ConfigureTenantAllowBlockList
    When the destination tenant is not provisioned for the Tenant Allow/Block List: Ask (default, prompt
    to configure or skip), Always (run Enable-OrganizationCustomization), or Never (skip the entries).

.PARAMETER Force
    Skip the "about to write to <destination>" confirmation prompt in -Live mode.

.PARAMETER LogPath
    Transcript log file. Default: <OutputPath>\logs\migration-<timestamp>.log

.EXAMPLE
    ./Invoke-MDOMigration.ps1                       # full pipeline, dry run (simulate)
    ./Invoke-MDOMigration.ps1 -Live                 # full pipeline, apply to destination
    ./Invoke-MDOMigration.ps1 -SkipExport -Live     # re-import latest export, apply
    ./Invoke-MDOMigration.ps1 -Live                 # apply, then report remaining drift (compare runs by default)
    ./Invoke-MDOMigration.ps1 -Live -SkipCompare    # apply without the parity comparison
#>
[CmdletBinding()]
param(
    [string]$ConfigPath,
    [switch]$Live,
    [switch]$DryRun,
    [string]$SourceDomain,
    [string]$SourceUserPrincipalName,
    [string]$DestinationDomain,
    [string]$DestinationUserPrincipalName,
    [string]$OutputPath,
    [switch]$SkipExport,
    [string]$ExportPath,
    [switch]$SkipCompare,
    [string[]]$IncludeCategory,
    [string[]]$IncludeType,
    [switch]$IgnoreRecipientScope,
    [ValidateSet('Ask', 'Always', 'Never')][string]$CreateMissingGroups = 'Ask',
    [ValidateSet('Ask', 'Always', 'Never')][string]$ConfigureTenantAllowBlockList = 'Ask',
    [switch]$Force,
    [string]$LogPath
)

$ErrorActionPreference = 'Stop'

if ($Live -and $DryRun) { throw 'Specify either -Live or -DryRun, not both. (Dry run is the default.)' }
$execute = [bool]$Live

Import-Module (Join-Path $PSScriptRoot 'src/MDOCommon.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'src/MDOExport.psm1')  -Force
Import-Module (Join-Path $PSScriptRoot 'src/MDOImport.psm1')  -Force
Import-Module (Join-Path $PSScriptRoot 'src/MDOCompare.psm1') -Force

if (-not $OutputPath) { $OutputPath = Get-MDODefaultExportRoot }
if ($ExportPath)      { $SkipExport = $true }

function Read-MDOTenantField {
    <# Returns $Current if set; otherwise prompts the user in the terminal. $AllowBlank lets the user skip. #>
    param([string]$Current, [string]$Prompt, [switch]$AllowBlank)
    if (-not [string]::IsNullOrWhiteSpace($Current)) { return $Current }
    while ($true) {
        $value = (Read-Host $Prompt).Trim()
        if ($value)     { return $value }
        if ($AllowBlank) { return '' }
        Write-Host '  (required) please enter a value.' -ForegroundColor Yellow
    }
}

# ---- Resolve both tenants from config, prompting for any missing UPN --------------------------------
# Only the admin UPN is needed; the tenant domain (used by the wrong-tenant guard) is derived from it.
$source = Resolve-MDOTenant -Role Source      -ConfigPath $ConfigPath -Domain $SourceDomain      -UserPrincipalName $SourceUserPrincipalName
$dest   = Resolve-MDOTenant -Role Destination -ConfigPath $ConfigPath -Domain $DestinationDomain -UserPrincipalName $DestinationUserPrincipalName

if (-not $SkipExport) {
    $source.UserPrincipalName = Read-MDOTenantField $source.UserPrincipalName 'SOURCE tenant admin UPN (email)'
    if (-not $SourceDomain)      { $source.Domain = Get-MDODomainFromUpn $source.UserPrincipalName }
}
$dest.UserPrincipalName = Read-MDOTenantField $dest.UserPrincipalName 'DESTINATION tenant admin UPN (email)'
if (-not $DestinationDomain) { $dest.Domain = Get-MDODomainFromUpn $dest.UserPrincipalName }

# ---- Start logging ---------------------------------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $LogPath) {
    $logDir = Join-Path $OutputPath 'logs'
    if (-not (Test-Path -LiteralPath $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    $LogPath = Join-Path $logDir "migration-$stamp.log"
}
Start-Transcript -Path $LogPath -Append | Out-Null

$importResults = $null
try {
    $mode = if ($execute) { 'LIVE (changes WILL be written)' } else { 'DRY RUN (simulate only)' }
    Write-Host '================ MDO MIGRATION ================' -ForegroundColor Cyan
    Write-Host " Mode        : $mode"
    Write-Host " Source      : $($source.Domain)      ($($source.UserPrincipalName))"
    Write-Host " Destination : $($dest.Domain)      ($($dest.UserPrincipalName))"
    Write-Host " Log         : $LogPath"
    Write-Host '==============================================' -ForegroundColor Cyan

    # ---- Step 1: export from the SOURCE tenant -----------------------------------------------------
    if ($SkipExport) {
        $existing = if ($ExportPath) { $ExportPath } else { $OutputPath }
        $exportFolder = Resolve-MDOImportPath -Path $existing
        Write-Host "`n[1/3] Skipping export; using existing export: $exportFolder" -ForegroundColor Cyan
    }
    else {
        Write-Host "`n[1/3] Exporting configuration from SOURCE tenant..." -ForegroundColor Cyan
        Connect-MDOTenant -UserPrincipalName $source.UserPrincipalName -TenantDomain $source.Domain
        $exportFolder = Join-Path $OutputPath $stamp
        Export-MDOConfiguration -Path $exportFolder | Out-Null
        Write-Host "      Source configuration saved to: $exportFolder" -ForegroundColor Green
    }

    # ---- Step 2: connect to the DESTINATION and import ---------------------------------------------
    Write-Host "`n[2/3] Connecting to DESTINATION tenant..." -ForegroundColor Cyan
    # -ForceReconnect drops the source session so we authenticate to the destination in succession.
    Connect-MDOTenant -UserPrincipalName $dest.UserPrincipalName -TenantDomain $dest.Domain -ForceReconnect

    if ($execute) {
        Assert-MDOTenantDomain -Domain $dest.Domain   # hard guard right before writing
        if (-not $Force) {
            $where = if ($dest.Domain) { $dest.Domain } else { 'the connected tenant' }
            $answer = Read-Host "About to WRITE the imported configuration to $where. Type 'yes' to continue"
            if ($answer.Trim().ToLower() -ne 'yes') { throw 'Aborted by user before writing.' }
        }
    }

    Write-Host "`n      Importing into DESTINATION ($mode)..." -ForegroundColor Cyan
    $importParams = @{ Path = $exportFolder; Execute = $execute; IgnoreRecipientScope = $IgnoreRecipientScope; CreateMissingGroups = $CreateMissingGroups; ConfigureTenantAllowBlockList = $ConfigureTenantAllowBlockList }
    if ($IncludeCategory) { $importParams['IncludeCategory'] = $IncludeCategory }
    if ($IncludeType)     { $importParams['IncludeType']     = $IncludeType }
    $importResults = Import-MDOConfiguration @importParams

    # ---- Step 3: parity comparison (runs on completion, right after the import summary) -------------
    # Wrapped so a snapshot/compare hiccup can never swallow the run or hide the import results.
    $parityReport = $null
    if (-not $SkipCompare) {
        Write-Host "`n[3/3] Parity check - snapshotting the destination and comparing it to the source export..." -ForegroundColor Cyan
        try {
            $snapshot = Join-Path ([System.IO.Path]::GetTempPath()) "mdo-dest-$stamp"
            Write-Host "      Snapshotting destination tenant..." -ForegroundColor DarkGray
            Export-MDOConfiguration -Path $snapshot | Out-Null
            # Compare-MDOConfiguration prints the full per-type parity report; capture findings to save too.
            $findings = @(Compare-MDOConfiguration -ReferencePath $exportFolder -DifferencePath $snapshot)
            if ($findings.Count) {
                $parityReport = Join-Path (Split-Path -Parent $LogPath) "parity-$stamp.csv"
                $findings | Export-Csv -Path $parityReport -NoTypeInformation -Encoding utf8
                Write-Host ("`n Full parity report ({0} drift item(s)) saved to: {1}" -f $findings.Count, $parityReport) -ForegroundColor Cyan
            }
            else {
                Write-Host "`n Full parity: the destination matches the source export." -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Parity comparison could not be completed: $($_.Exception.Message)"
            Write-Host "      Run it manually later: ./scripts/Compare-MDOConfig.ps1 -ExportTarget -CsvPath parity.csv" -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host "`n[3/3] Skipping comparison (-SkipCompare)." -ForegroundColor DarkGray
    }

    # ---- Final summary -----------------------------------------------------------------------------
    $applied = @($importResults | Where-Object { $_.Success -and -not $_.DryRun }).Count
    $planned = @($importResults | Where-Object { $_.DryRun }).Count
    $failed  = @($importResults | Where-Object { -not $_.Success }).Count
    Write-Host "`n================ DONE ================" -ForegroundColor Cyan
    Write-Host " Mode    : $mode"
    Write-Host " Applied : $applied"
    Write-Host " Planned : $planned (dry-run)"
    Write-Host " Failed  : $failed"
    Write-Host " Log     : $LogPath"
    if ($parityReport) { Write-Host " Parity  : $parityReport" }
    if (-not $execute) {
        Write-Host "`nThis was a simulation. Re-run with -Live to apply." -ForegroundColor Yellow
    }
}
catch {
    # Surface why a run ended early instead of dying silently with no parity report.
    Write-Host "`n================ MIGRATION ABORTED ================" -ForegroundColor Red
    Write-Host " $($_.Exception.Message)" -ForegroundColor Red
    Write-Host " Log: $LogPath" -ForegroundColor DarkGray
    throw
}
finally {
    Stop-Transcript | Out-Null
}
