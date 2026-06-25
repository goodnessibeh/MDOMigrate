#Requires -Version 7.0
<#
    MDOExport.psm1
    Exports every supported MDO/EOP object as full JSON (one file per type) so it can be
    recreated in another tenant by Import-MDOConfiguration. Requires MDOCommon.psm1 to be loaded.
#>

function Export-MDOConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$JsonDepth = 8
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    $registry = Get-MDOTypeRegistry
    $manifest = @()

    foreach ($entry in $registry) {
        $type = $entry.Type
        Write-Host "Exporting $type ..." -ForegroundColor Cyan
        $records = @()

        try {
            switch ($entry.Category) {
                'TABL' {
                    # Tenant Allow/Block List is split by ListType; tag each record so import knows which list.
                    foreach ($listType in 'Sender', 'Url', 'FileHash') {
                        $items = @(Get-TenantAllowBlockListItems -ListType $listType -ErrorAction Stop)
                        foreach ($item in $items) {
                            $item | Add-Member -NotePropertyName '_ListType' -NotePropertyValue $listType -Force
                            $records += $item
                        }
                    }
                }
                'TABLSpoof' {
                    $records = @(Get-TenantAllowBlockListSpoofItems -ErrorAction Stop)
                }
                default {
                    $records = @(& "Get-$type" -ErrorAction Stop)
                }
            }
        }
        catch {
            Write-Warning "  Could not export ${type}: $($_.Exception.Message)"
            continue
        }

        $clean = $records | Select-Object -Property * -ExcludeProperty RunspaceId, PSComputerName, PSShowComputerName, PSSourceJobInstanceId
        $file = Join-Path $Path "$type.json"
        ($clean | ConvertTo-Json -Depth $JsonDepth) | Out-File -FilePath $file -Encoding utf8

        Write-Host "  -> $($records.Count) object(s) saved to $file" -ForegroundColor Green
        $manifest += [pscustomobject]@{ Type = $type; Category = $entry.Category; Count = $records.Count; File = "$type.json" }
    }

    $manifest | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $Path 'manifest.json') -Encoding utf8
    Write-Host "`nExport complete: $($manifest.Count) type(s) written to $Path" -ForegroundColor Cyan
    return $manifest
}

Export-ModuleMember -Function Export-MDOConfiguration
