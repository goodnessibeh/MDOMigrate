#Requires -Version 7.0
<#
.SYNOPSIS
    Documents Exchange Online Protection / Defender for Office 365 policies to JSON + Excel.

.DESCRIPTION
    Produces a human-readable report (one row per policy property, with cmdlet help descriptions).
    For configuration parity between tenants use Export-MDOConfig.ps1 / Import-MDOConfig.ps1 instead -
    this script is for documentation, not re-import.

.PARAMETER CustomerName
    Customer/tenant label written into each row. Prompted for if omitted.

.PARAMETER DelegatedOrganization
    Optional partner/GDAP delegated organisation (e.g. customer.onmicrosoft.com). Omit for a direct admin.

.PARAMETER OutputPrefix
    Base name for the output files. Default: defender-office365-policies
#>
[CmdletBinding()]
param(
    [string]$CustomerName,
    [string]$DelegatedOrganization,
    [string]$OutputPrefix = 'defender-office365-policies'
)

# --- Modules ---
foreach ($module in 'ExchangeOnlineManagement', 'ImportExcel') {
    if (-not (Get-Module $module -ListAvailable)) {
        Install-Module $module -Scope CurrentUser -Force
    }
    Import-Module $module -DisableNameChecking
}

if (-not $CustomerName) { $CustomerName = Read-Host -Prompt 'Enter customer name (for the report)' }

# --- Connect (Exchange Online + Security & Compliance) ---
$exoConnected = $false
try { $null = Get-AcceptedDomain -ErrorAction Stop; $exoConnected = $true } catch { $exoConnected = $false }
if (-not $exoConnected) {
    Write-Host 'Connecting to Exchange Online...' -ForegroundColor Cyan
    if ($DelegatedOrganization) { Connect-ExchangeOnline -DelegatedOrganization $DelegatedOrganization -ShowBanner:$false }
    else { Connect-ExchangeOnline -ShowBanner:$false }
}
Write-Host 'Connecting to Security & Compliance PowerShell...' -ForegroundColor Cyan
try { $null = Get-ProtectionAlert -ErrorAction Stop } catch { Connect-IPPSSession }

# Each spec is the Get-<Type> cmdlet plus how to handle it:
#   Args    - hashtable of parameters the Get- cmdlet requires
#   Help    - $false to skip looking up parameter descriptions (no matching New- cmdlet)
#   Alerts  - $true for Get-ProtectionAlert, which is summarised differently
$policySpecs = @(
    @{ Type = 'AntiPhishPolicy' }
    @{ Type = 'HostedContentFilterPolicy' }
    @{ Type = 'HostedConnectionFilterPolicy' }
    @{ Type = 'HostedOutboundSpamFilterPolicy' }
    @{ Type = 'MalwareFilterPolicy' }
    @{ Type = 'SafeAttachmentPolicy' }
    @{ Type = 'SafeLinksPolicy' }
    @{ Type = 'QuarantinePolicy' }
    @{ Type = 'EOPProtectionPolicyRule' }
    @{ Type = 'TeamsProtectionPolicy' }
    @{ Type = 'TeamsProtectionPolicyRule' }
    @{ Type = 'ATPProtectionPolicyRule' }
    @{ Type = 'ATPBuiltInProtectionRule' }
    @{ Type = 'AtpPolicyForO365';        Help = $false }
    @{ Type = 'TenantAllowBlockListItems'; Args = @{ ListType = 'Sender' };   Help = $false }
    @{ Type = 'TenantAllowBlockListItems'; Args = @{ ListType = 'Url' };      Help = $false }
    @{ Type = 'TenantAllowBlockListItems'; Args = @{ ListType = 'FileHash' }; Help = $false }
    @{ Type = 'ProtectionAlert';         Help = $false; Alerts = $true }
)

$helpDescriptions = @()
$data = @()

foreach ($spec in $policySpecs) {
    $policyType = $spec.Type
    $getHelp = -not ($spec.ContainsKey('Help') -and -not $spec.Help)
    $alertPolicies = [bool]($spec.ContainsKey('Alerts') -and $spec.Alerts)
    $arguments = if ($spec.ContainsKey('Args')) { $spec.Args } else { @{} }
    $label = if ($arguments.Count) { "$policyType ($($arguments.Values -join ','))" } else { $policyType }

    Write-Host "Get information for Policy Type: $label" -ForegroundColor Cyan
    try {
        $output = @(& "Get-$policyType" @arguments -ErrorAction Stop)
    }
    catch {
        Write-Warning "Get-$policyType did not yield any results: $($_.Exception.Message)"
        continue
    }
    if ($output.Count -eq 0) { Write-Warning "Get-$policyType returned nothing"; continue }

    if ($getHelp) {
        # Pull parameter descriptions from the matching New-<Type> cmdlet (run Update-Help once for full text).
        $descriptionsForPolicy = @()
        foreach ($member in ($output[0] | Get-Member -MemberType Property)) {
            $description = (Get-Help "New-$policyType" -Parameter $member.Name -ErrorAction SilentlyContinue).Description.Text -join ''
            $descriptionsForPolicy += @{
                Name        = $member.Name
                PolicyType  = $policyType
                Description = if ($description) { $description } else { "Property $($member.Name) has no corresponding attribute in New-$policyType" }
            }
        }
        $helpDescriptions += $descriptionsForPolicy
    }

    if ($alertPolicies) {
        foreach ($record in $output) {
            $data += [pscustomobject]@{
                CustomerName = $CustomerName
                PolicyType   = $policyType
                Policy       = $record.Name
                Property     = ''
                Value        = @{ $true = 'Disabled'; $false = 'Enabled' }[[bool]$record.Disabled]
                Description  = $record.Comment
                Category     = $record.Category
                Severity     = $record.Severity
            }
        }
        continue
    }

    foreach ($record in $output) {
        foreach ($member in ($record | Get-Member -MemberType Property)) {
            $value = $record.($member.Name)
            if (($null -ne $value) -and ($value -isnot [string]) -and ($value -is [System.Collections.IEnumerable])) {
                $value = (@($value) -join ',')
            }
            $description = ($helpDescriptions | Where-Object { $_.PolicyType -eq $policyType -and $_.Name -eq $member.Name }).Description
            $data += [pscustomobject]@{
                CustomerName = $CustomerName
                PolicyType   = $policyType
                Policy       = $record.Name
                Property     = $member.Name
                Value        = $value
                Description  = $description
                Category     = ''
                Severity     = ''
            }
        }
    }
}

# --- Export: JSON, then Excel (round-trip through JSON works around an Export-Excel quirk) ---
$jsonFile  = "$OutputPrefix.json"
$excelFile = "$OutputPrefix.xlsx"

$sortedData = $data | Select-Object CustomerName, PolicyType, Policy, Property, Value, Description, Category, Severity
$sortedData | ConvertTo-Json -Depth 3 | Out-File $jsonFile -Encoding utf8

$excel = Get-Content $jsonFile | ConvertFrom-Json | Export-Excel -Path $excelFile -AutoSize -TableName 'definitions' -FreezeTopRow -PassThru
$sheet = $excel.Workbook.Worksheets['Sheet1']
$sheet.Column(6) | Set-ExcelRange -Width 100 -WrapText
$sheet.Column(5) | Set-ExcelRange -Width 100 -WrapText -HorizontalAlignment Left
Export-Excel -ExcelPackage $excel

$helpDescriptions | ConvertTo-Json -Depth 3 | Out-File 'helpdescriptions.json' -Encoding utf8
$helpExcel = Get-Content 'helpdescriptions.json' | ConvertFrom-Json | Export-Excel -Path 'helpdescriptions.xlsx' -AutoSize -TableName 'descriptions' -FreezeTopRow -PassThru
$helpSheet = $helpExcel.Workbook.Worksheets['Sheet1']
$helpSheet.Column(3) | Set-ExcelRange -Width 100 -WrapText
Export-Excel -ExcelPackage $helpExcel

Write-Host "`nReport written: $jsonFile, $excelFile" -ForegroundColor Green
