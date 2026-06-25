#Requires -Version 7.0
<#
    MDOCompare.psm1
    Compares two export folders (reference = source, difference = target) and reports configuration
    drift: objects missing/extra in the target and per-property value differences. Identity/UUID/
    timestamp fields are ignored so only meaningful drift is shown. Requires MDOCommon.psm1 to be loaded.
#>

function Read-MDOExportFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Folder, [Parameter(Mandatory)][string]$Type)
    $file = Join-Path $Folder "$Type.json"
    if (-not (Test-Path -LiteralPath $file)) { return @() }
    return @(Get-Content -LiteralPath $file -Raw | ConvertFrom-Json)
}

function Get-MDOObjectKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Category)
    switch ($Category) {
        'TABL'      { return ('{0}|{1}' -f (Get-MDOProperty $Object '_ListType'), (Get-MDOProperty $Object 'Value')) }
        'TABLSpoof' { return ('{0}|{1}' -f (Get-MDOProperty $Object 'SpoofedUser'), (Get-MDOProperty $Object 'SendingInfrastructure')) }
        default {
            $name = Get-MDOProperty $Object 'Name'
            if ($name) { return $name }
            return (Get-MDOProperty $Object 'Identity' '(unnamed)')
        }
    }
}

function ConvertTo-MDOComparable {
    <# Normalise a value to a stable string so collections and types compare cleanly. #>
    [CmdletBinding()]
    param($Value)
    if ($null -eq $Value) { return '' }
    if (($Value -is [System.Collections.IEnumerable]) -and ($Value -isnot [string])) {
        return ((@($Value) | ForEach-Object { "$_" } | Sort-Object) -join '|')
    }
    return "$Value"
}

function Compare-MDOObjectPair {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Object,
        [Parameter(Mandatory)]$Reference,
        [Parameter(Mandatory)]$Difference,
        [string[]]$Ignore = @()
    )
    $props = @($Reference.PSObject.Properties.Name + $Difference.PSObject.Properties.Name | Select-Object -Unique)
    $out = @()
    foreach ($prop in $props) {
        if ($Ignore -contains $prop) { continue }
        $refVal = ConvertTo-MDOComparable (Get-MDOProperty $Reference $prop)
        $difVal = ConvertTo-MDOComparable (Get-MDOProperty $Difference $prop)
        if ($refVal -ne $difVal) {
            $out += [pscustomobject]@{ Type = $Type; Object = $Object; Status = 'Changed'; Property = $prop; Reference = $refVal; Difference = $difVal }
        }
    }
    return $out
}

function Write-MDOCompareSummary {
    [CmdletBinding()]
    param([array]$Findings)
    $missing = @($Findings | Where-Object { $_.Status -eq 'MissingInTarget' })
    $extra   = @($Findings | Where-Object { $_.Status -eq 'ExtraInTarget' })
    $changed = @($Findings | Where-Object { $_.Status -eq 'Changed' })

    Write-Host "`n================ PARITY REPORT ================" -ForegroundColor Cyan
    Write-Host (" Missing in target  : {0}" -f $missing.Count) -ForegroundColor $(if ($missing.Count) { 'Red' } else { 'Green' })
    Write-Host (" Extra in target    : {0}" -f $extra.Count)   -ForegroundColor $(if ($extra.Count) { 'Yellow' } else { 'Green' })
    Write-Host (" Changed properties : {0}" -f $changed.Count) -ForegroundColor $(if ($changed.Count) { 'Yellow' } else { 'Green' })

    if ($Findings.Count -eq 0) {
        Write-Host "`n FULL PARITY: reference and target match (identity/UUID fields ignored)." -ForegroundColor Green
        return
    }

    # Per-type breakdown table so the report is comprehensive at a glance before the line-by-line detail.
    Write-Host "`n By type:" -ForegroundColor Cyan
    $Findings | Group-Object Type | Sort-Object Name | ForEach-Object {
        [pscustomobject]@{
            Type    = $_.Name
            Missing = @($_.Group | Where-Object { $_.Status -eq 'MissingInTarget' }).Count
            Extra   = @($_.Group | Where-Object { $_.Status -eq 'ExtraInTarget' }).Count
            Changed = @($_.Group | Where-Object { $_.Status -eq 'Changed' }).Count
            Total   = $_.Count
        }
    } | Format-Table -AutoSize | Out-Host

    Write-Host " Details:" -ForegroundColor Cyan
    $Findings | Sort-Object Type, Object, Property |
        Format-Table Type, Object, Status, Property, Reference, Difference -AutoSize -Wrap | Out-Host
}

function Compare-MDOConfiguration {
    <#
        Compares a reference export (source tenant) against a difference export (target tenant) and
        returns one record per drift item. Identity/UUID/timestamp properties are ignored.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ReferencePath,
        [Parameter(Mandatory)][string]$DifferencePath,
        [string[]]$IncludeType
    )

    if (-not (Test-Path -LiteralPath $ReferencePath)) { throw "Reference folder not found: $ReferencePath" }
    if (-not (Test-Path -LiteralPath $DifferencePath)) { throw "Difference folder not found: $DifferencePath" }

    $ignore = Get-MDOReadOnlyProperty
    $registry = Get-MDOTypeRegistry | Sort-Object Order
    $findings = @()

    foreach ($entry in $registry) {
        $type = $entry.Type
        if ($IncludeType -and ($IncludeType -notcontains $type)) { continue }

        $refObjects = Read-MDOExportFile -Folder $ReferencePath -Type $type
        $difObjects = Read-MDOExportFile -Folder $DifferencePath -Type $type
        if (($refObjects.Count + $difObjects.Count) -eq 0) { continue }

        $refMap = @{}; foreach ($o in $refObjects) { $refMap[(Get-MDOObjectKey $o $entry.Category)] = $o }
        $difMap = @{}; foreach ($o in $difObjects) { $difMap[(Get-MDOObjectKey $o $entry.Category)] = $o }

        $keys = @($refMap.Keys + $difMap.Keys | Select-Object -Unique)
        foreach ($key in $keys) {
            if (-not $difMap.ContainsKey($key)) {
                $findings += [pscustomobject]@{ Type = $type; Object = $key; Status = 'MissingInTarget'; Property = ''; Reference = '(present)'; Difference = '(absent)' }
                continue
            }
            if (-not $refMap.ContainsKey($key)) {
                $findings += [pscustomobject]@{ Type = $type; Object = $key; Status = 'ExtraInTarget'; Property = ''; Reference = '(absent)'; Difference = '(present)' }
                continue
            }
            $findings += Compare-MDOObjectPair -Type $type -Object $key -Reference $refMap[$key] -Difference $difMap[$key] -Ignore $ignore
        }
    }

    Write-MDOCompareSummary -Findings $findings
    return $findings
}

Export-ModuleMember -Function Compare-MDOConfiguration
