# MDOMigrate

**Export, migrate, and verify Microsoft Defender for Office 365 (MDO) / Exchange Online Protection (EOP)
policy configuration between tenants.**

MDOMigrate snapshots every threat policy in a source tenant to JSON, recreates them in a target tenant
for full configuration parity, and compares the two to prove they match. It is built for tenant-to-tenant
migrations, building a known-good baseline, disaster-recovery rebuilds, and config drift auditing.

> **Why PowerShell, not Microsoft Graph?**
> As of 2026 the Microsoft Graph API does **not** expose MDO/EOP threat policies (anti-phishing,
> anti-spam, anti-malware, Safe Links, Safe Attachments, quarantine, preset security policies, or the
> Tenant Allow/Block List). They are only available through **Exchange Online PowerShell** and
> **Security & Compliance PowerShell**, which is what MDOMigrate uses.

---

## Features

- **Export** all supported policy and rule types to one JSON file per type (plus a manifest).
- **Import** them into another tenant, choosing `New-` (create) vs `Set-` (update) automatically.
- **Compare** source vs target and report exactly what is missing, extra, or changed.
- **Safe by default** — import runs as a dry run; you must pass `-Execute` to make changes.
- **Cross-tenant safe** — identity, GUID, and timestamp fields are never replayed, so imports don't
  fail with "identity/UUID" errors. Recipient scope (tenant-specific domains/groups) can be dropped
  with one switch.
- **Custom policies included** — `Get-*` with no name filter returns every policy, so your custom
  policies and rules are captured alongside the built-in defaults.

## What it covers

| Area | Objects |
|------|---------|
| Anti-phishing | `AntiPhishPolicy` + `AntiPhishRule` |
| Anti-spam (inbound) | `HostedContentFilterPolicy` + `HostedContentFilterRule` |
| Anti-spam (outbound) | `HostedOutboundSpamFilterPolicy` + `HostedOutboundSpamFilterRule` |
| Connection filter | `HostedConnectionFilterPolicy` (Default) |
| Anti-malware | `MalwareFilterPolicy` + `MalwareFilterRule` |
| Safe Attachments | `SafeAttachmentPolicy` + `SafeAttachmentRule` + global `AtpPolicyForO365` |
| Safe Links | `SafeLinksPolicy` + `SafeLinksRule` |
| Quarantine | `QuarantinePolicy` (+ global settings) |
| Preset security policies | `EOPProtectionPolicyRule`, `ATPProtectionPolicyRule`, `ATPBuiltInProtectionRule` |
| Tenant Allow/Block List | senders, URLs, file hashes, spoofed senders |

## Requirements

- **PowerShell 7.0+**
- Modules (auto-installed on first run): [`ExchangeOnlineManagement`](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)
  and, for the optional report, [`ImportExcel`](https://github.com/dfinke/ImportExcel)
- A **Global Administrator** or **Security Administrator** account in each tenant.

## Install

```bash
git clone https://github.com/goodnessibeh/MDOMigrate.git
cd MDOMigrate
```

## Usage

### 1. Export from the source tenant

```powershell
./Export-MDOConfig.ps1 -UserPrincipalName admin@source.onmicrosoft.com
```

By default this writes to a timestamped folder under your Desktop, e.g.
`<Desktop>\MDOMigrate-Exports\20260625-120000\`, containing one JSON file per type and a `manifest.json`.
(Override with `-OutputPath` if you want a different location.)

### 2. Import into the target tenant

Always dry-run first — it prints every create/update it *would* make and changes nothing. With no
`-Path`, it automatically uses the **most recent export** under `<Desktop>\MDOMigrate-Exports`:

```powershell
./Import-MDOConfig.ps1 -UserPrincipalName admin@target.onmicrosoft.com
```

When the plan looks right, apply it:

```powershell
./Import-MDOConfig.ps1 -Execute
```

To import a specific older export, pass `-Path '<Desktop>\MDOMigrate-Exports\20260101-090000'`.

Useful options:

```powershell
# Limit scope by category or type
./Import-MDOConfig.ps1 -IncludeCategory Policy,Rule -Execute
./Import-MDOConfig.ps1 -IncludeType SafeLinksPolicy,SafeLinksRule -Execute

# Drop recipient conditions (domains/groups) that don't exist in the target tenant, then re-scope later
./Import-MDOConfig.ps1 -IgnoreRecipientScope -Execute
```

### 3. Verify parity

```powershell
# Snapshot the connected target tenant and diff it against the latest Desktop export
./Compare-MDOConfig.ps1 -ExportTarget -CsvPath parity.csv

# Or compare two export folders directly
./Compare-MDOConfig.ps1 -ReferencePath ./export-source -DifferencePath ./export-target
```

The parity report lists objects **missing in target**, **extra in target**, and any **changed
properties** — ignoring identity/UUID/timestamp fields so only meaningful drift is shown.

### Optional: human-readable report

`Get-MDOPolicyReport.ps1` produces a documentation report (JSON + Excel, one row per property with
cmdlet help text). This is for review/audit, not for re-import.

```powershell
./Get-MDOPolicyReport.ps1 -CustomerName "Contoso"
```

## How import decides create vs update

- A custom policy that doesn't exist in the target is created with `New-<Type>`.
- A policy that already exists, or a built-in `Default`, is updated in place with `Set-<Type>`.
- Rules are imported **after** policies and re-link to their policy automatically by name. Rule
  enabled/disabled state is reapplied with `Enable-`/`Disable-`.
- Only parameters the target `New-`/`Set-` cmdlet actually accepts are sent. Read-only and
  tenant-specific fields (`Identity`, `Guid`, `WhenChanged`, `OriginatingServer`, …) are dropped.
- Every action is wrapped in try/catch, so one failure never aborts the run. A summary reports what
  was applied, planned, and failed.

## Notes & limitations

- **Recipient scope** (`RecipientDomainIs`, `SentToMemberOf`, …) references domains and groups that are
  tenant-specific. By default it is replayed (and may fail on a missing target domain/group); use
  `-IgnoreRecipientScope` to import rules cleanly and re-scope them afterwards.
- **Built-in quarantine policies** (`DefaultFullAccessPolicy`, etc.) are intentionally skipped — they
  already exist identically in every tenant.
- **Tenant Allow/Block "allow" entries** may require a service-enforced expiration window; such items
  surface as reported failures rather than being silently dropped.
- **Preset security policy rules** can require the preset to be enabled in the portal first; those
  failures are reported clearly.
- Always review the dry-run output before running `-Execute` against a production tenant.

## Project layout

```
Export-MDOConfig.ps1        # entry: export source tenant
Import-MDOConfig.ps1        # entry: import into target tenant (dry run by default)
Compare-MDOConfig.ps1       # entry: parity comparison
Get-MDOPolicyReport.ps1     # entry: optional JSON/Excel documentation report
Set-MDORuleScope.ps1        # entry: scope a rule set to all accepted domains (dry run by default)
src/MDOCommon.psm1          # connect, type registry, parameter mapping, read-only denylist
src/MDOExport.psm1          # export engine
src/MDOImport.psm1          # import engine
src/MDOCompare.psm1         # comparison engine
PSScriptAnalyzerSettings.psd1
```

## Validation

All scripts target PowerShell 7+, pass the PowerShell language parser, and are clean under
**PSScriptAnalyzer** (0 errors, 0 warnings):

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
