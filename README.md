# MDOMigrate

**Export, migrate, and verify Microsoft Defender for Office 365 (MDO) / Exchange Online Protection (EOP)
policy configuration between tenants.**

MDOMigrate snapshots every threat policy in a source tenant to JSON, recreates them in a target tenant
for full configuration parity, and compares the two to prove they match. One command
(`Invoke-MDOMigration.ps1`) runs the whole pipeline - connect to source, export, connect to
destination, import, verify - driven by a small config file and logged end to end.

> **Why PowerShell, not Microsoft Graph?**
> As of 2026 the Microsoft Graph API does **not** expose MDO/EOP threat policies (anti-phishing,
> anti-spam, anti-malware, Safe Links, Safe Attachments, quarantine, preset security policies, or the
> Tenant Allow/Block List). They are only available through **Exchange Online PowerShell** and
> **Security & Compliance PowerShell**, which is what MDOMigrate uses.

---

## Use cases

### 1. Migrate a security setup to a new tenant - MSSPs & consultants
You are standing up a brand-new Microsoft 365 tenant for a customer (or moving them off an old one) and
need their hard-won MDO/EOP posture - anti-phishing, anti-spam, Safe Links/Attachments, quarantine,
Tenant Allow/Block List - recreated faithfully in the destination. MDOMigrate exports the source,
authenticates to **both tenants in succession**, and rebuilds the configuration in the destination,
then proves parity. The `tenants.json` config makes the source/destination pair explicit so the import
can never land on the wrong tenant.

### 2. Keep dev / test / staging / production in parity
Teams that maintain separate MDO environments (or separate tenants per ring) can promote a known-good
security baseline outward - author and validate in **test**, then push the same policy set to **dev**,
**staging**, and **production**, comparing after each step so drift is caught immediately. Run it on a
schedule to continuously detect and report configuration drift between environments.

### 3. Back up configuration before major changes
Before a risky change - a preset security policy rollout, a large anti-spam retune, a tenant
reorganization, or an admin handover - snapshot the current configuration to versionable JSON. If the
change goes wrong, re-import the backup to restore the previous posture. The export is plain JSON, so
it fits naturally in source control, ticketing attachments, or your backup store as point-in-time
evidence of what the tenant looked like.

### 4. Migrate to another email security provider - *roadmap*
MDOMigrate already captures your MDO/EOP posture as a structured, provider-neutral JSON model. Upcoming
releases will add translators that map that model onto other email security platforms, so you can move
**off** (or run **alongside**) Microsoft Defender without rebuilding every policy by hand:

- **Proofpoint** - planned
- **Mimecast** - planned
- **Google Workspace** (Gmail security / Workspace email protections) - planned

Until those ship, the export is still the useful first step: it gives you a complete, documented
inventory of every policy and rule to translate.

---

## Features

- **One-command pipeline** - `Invoke-MDOMigration.ps1` runs export → import → (optional) compare in a
  single shell, prompting for anything not in the config and logging the whole run.
- **Config-driven** - a `config/tenants.json` file names the **Source** and **Destination** tenants by
  admin UPN; the tenant domain is derived from the UPN. Missing UPNs are prompted for at run time.
- **Export** all supported policy and rule types to one JSON file per type (plus a manifest).
- **Import** them into another tenant, choosing `New-` (create) vs `Set-` (update) automatically.
- **Compare** source vs target and report exactly what is missing, extra, or changed.
- **Safe by default** - import runs as a dry run; you must pass `-Live` (orchestrator) / `-Execute`
  (script) to make changes.
- **Wrong-tenant guard** - the destination domain (derived from the admin UPN) is verified on the live
  connection *before any write*, so a session still signed into the source tenant can never be written to.
- **Cross-tenant safe** - identity, GUID, and timestamp fields are never replayed, so imports don't
  fail with "identity/UUID" errors. Recipient scope (tenant-specific domains/groups) can be dropped
  with one switch.
- **Custom policies included** - `Get-*` with no name filter returns every policy, so your custom
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
- A **Global Administrator** or **Security Administrator** account in **each** tenant.

## Install

```bash
git clone https://github.com/goodnessibeh/MDOMigrate.git
cd MDOMigrate
```

On Windows, allow local scripts to run (one-time, current user only). Run this in PowerShell 7:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

`RemoteSigned` lets your local scripts run while still requiring downloaded scripts to be signed. To
allow scripts for the current session only (no persistent change), use instead:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

## Configure

All config lives in `config/`. Copy the example and fill in the admin UPN for each tenant.
`config/tenants.json` is git-ignored (it holds your admin UPNs); the example is committed.

```bash
cp config/tenants.example.json config/tenants.json
```

```json
{
  "Source":      { "UserPrincipalName": "admin@source.onmicrosoft.com" },
  "Destination": { "UserPrincipalName": "admin@destination.onmicrosoft.com" }
}
```

- **UserPrincipalName** - the admin UPN for each tenant. That's all you need: the tenant **domain** used
  by the wrong-tenant guard is derived automatically from the UPN (the part after `@`). **Leave a UPN
  empty and you'll be prompted for it in the terminal** at run time.
- (Optional) You can still add a `"Domain"` to a tenant entry to override the derived value.

## Before you run: enable organization customization on the destination

The **Tenant Allow/Block List** requires the destination tenant to have *organization customization*
enabled. Without it, every allow/block entry fails with
`Value cannot be null. Parameter name: exchangeConfigUnit`. Enable it once, **before** running the
orchestrator (this is an Exchange Online cmdlet - connect to Exchange Online, not Security & Compliance):

```powershell
Connect-ExchangeOnline -UserPrincipalName admin@destination.onmicrosoft.com
Enable-OrganizationCustomization
```

- `This operation is not required. Organization is already enabled` - already done, nothing to do.
- `not recognized as a cmdlet` - update the module and reconnect: `Update-Module ExchangeOnlineManagement`,
  then `Connect-ExchangeOnline` again.
- **Portal alternative** (most reliable): in the Microsoft Defender portal open *Email & collaboration >
  Policies & rules > Threat policies > Tenant Allow/Block Lists* and add any one entry. That first
  interaction provisions the list.

Provisioning can take from a few minutes up to a couple of hours to propagate. If you skip this step,
the orchestrator can still offer to run `Enable-OrganizationCustomization` for you
(`-ConfigureTenantAllowBlockList Ask|Always`), but doing it ahead of time avoids a wasted run, since the
rest of the migration completes while the Tenant Allow/Block List is still propagating. Re-run later with
`-IncludeType TenantAllowBlockListItems,TenantAllowBlockListSpoofItems` to apply just those entries.

## Usage

### Quick start - the whole pipeline in one command

`Invoke-MDOMigration.ps1` (in the repo root) reads `tenants.json`, then exports from the source,
connects to the destination, and imports - prompting for any missing UPN and writing a transcript log
under `<export base>\logs`.

```powershell
# Simulate the full migration (dry run - nothing is written). This is the default.
./Invoke-MDOMigration.ps1

# Apply it to the destination tenant (asks for a 'yes' confirmation before writing).
# On completion it re-snapshots the destination and prints a source-vs-destination drift report.
./Invoke-MDOMigration.ps1 -Live

# Apply without the parity comparison.
./Invoke-MDOMigration.ps1 -Live -SkipCompare

# Re-import the most recent export without re-exporting the source.
./Invoke-MDOMigration.ps1 -SkipExport -Live
```

You authenticate to the **source** tenant for the export, then to the **destination** tenant for the
import, one after another in the same window. The parity comparison runs on completion by default
(`-SkipCompare` to skip). Useful switches: `-CreateMissingGroups` and `-ConfigureTenantAllowBlockList`
(`Ask`/`Always`/`Never`), `-IncludeCategory` / `-IncludeType` / `-IgnoreRecipientScope` (passed through
to the import), `-OutputPath` (export location), `-ExportPath` (import a specific older export),
`-Force` (skip the write confirmation), `-LogPath`.

### Or run each step yourself

The individual scripts live in `scripts/` and honor the same `tenants.json` (override with `-Domain` /
`-UserPrincipalName` / `-ConfigPath`).

**1. Export from the source tenant**

```powershell
./scripts/Export-MDOConfig.ps1
```

Writes to a timestamped folder under your Desktop, e.g.
`<Desktop>\MDOMigrate-Exports\20260625-120000\`, containing one JSON file per type and a `manifest.json`.
(Override with `-OutputPath`.)

**2. Import into the target tenant**

Always dry-run first - it prints every create/update it *would* make and changes nothing. With no
`-Path`, it uses the **most recent export** under `<Desktop>\MDOMigrate-Exports`:

```powershell
./scripts/Import-MDOConfig.ps1
```

When the plan looks right, apply it:

```powershell
./scripts/Import-MDOConfig.ps1 -Execute
```

To import a specific older export, pass `-Path '<Desktop>\MDOMigrate-Exports\20260101-090000'`.

```powershell
# Limit scope by category or type
./scripts/Import-MDOConfig.ps1 -IncludeCategory Policy,Rule -Execute
./scripts/Import-MDOConfig.ps1 -IncludeType SafeLinksPolicy,SafeLinksRule -Execute

# Drop recipient conditions (domains/groups) that don't exist in the target tenant, then re-scope later
./scripts/Import-MDOConfig.ps1 -IgnoreRecipientScope -Execute
```

**3. Verify parity**

```powershell
# Snapshot the connected target tenant and diff it against the latest Desktop export
./scripts/Compare-MDOConfig.ps1 -ExportTarget -CsvPath parity.csv

# Or compare two export folders directly
./scripts/Compare-MDOConfig.ps1 -ReferencePath ./export-source -DifferencePath ./export-target
```

The parity report lists objects **missing in target**, **extra in target**, and any **changed
properties** - ignoring identity/UUID/timestamp fields so only meaningful drift is shown.

### Optional: human-readable report

`scripts/Get-MDOPolicyReport.ps1` produces a documentation report (JSON + Excel, one row per property
with cmdlet help text). This is for review/audit, not for re-import.

```powershell
./scripts/Get-MDOPolicyReport.ps1 -CustomerName "Contoso"
```

## How import decides create vs update

- A custom policy that doesn't exist in the target is created with `New-<Type>`.
- A policy that already exists, or a built-in `Default`, is updated in place with `Set-<Type>`.
- **Preset / Evaluation policies** (Standard, Strict, Evaluation) exist in the target under a different
  auto-generated name, so they are matched by `RecommendedPolicyType` and **overwritten** in place rather
  than duplicated (which the service rejects with "Already there is a 'Standard' recommended policy").
- Rules are imported **after** policies and re-link to their policy automatically by name. Rule
  enabled/disabled state is reapplied with `Enable-`/`Disable-`.
- Only parameters the target `New-`/`Set-` cmdlet actually accepts are sent. Read-only and
  tenant-specific fields (`Identity`, `Guid`, `WhenChanged`, `OriginatingServer`, …) are dropped.
- **Self-healing**: if a create/update is rejected because of a single tenant-specific parameter
  (e.g. `IntraOrgFilterState`, an out-of-range rule `Priority`, or impersonation settings on a new
  Evaluation policy), that parameter is dropped and the call retried, so one quirk never loses the whole
  object. Dropped parameters are listed in the summary's **Adjusted** section.
- Every action is wrapped in try/catch, so one failure never aborts the run. A summary reports what
  was applied, planned, adjusted, and failed.

## Notes & limitations

- **Run the import against the destination, not the source.** Because both connections happen in one
  shell, the wrong-tenant guard (`Destination.Domain`) exists to stop an import from accidentally
  re-targeting the tenant you just exported. Set the domains in `tenants.json` to keep it active.
- **Recipient scope** (`RecipientDomainIs`, `SentToMemberOf`, …) references domains and groups that are
  tenant-specific. By default it is replayed (and may fail on a missing target domain/group); use
  `-IgnoreRecipientScope` to import rules cleanly and re-scope them afterwards.
- **Missing distribution groups** that a rule targets (`SentToMemberOf`, …) are handled by
  `-CreateMissingGroups`: `Ask` (default) prompts to create an empty group per missing group, `Always`
  creates them without asking, and `Never` drops the missing group from the rule. Created groups have
  **no members** - add members afterwards.
- **Built-in quarantine policies** (`DefaultFullAccessPolicy`, etc.) are intentionally skipped - they
  already exist identically in every tenant.
- **Tenant Allow/Block List not provisioned** in the destination makes every entry fail with
  `exchangeConfigUnit`. `-ConfigureTenantAllowBlockList` controls this: `Ask` (default) prompts to
  configure it (runs `Enable-OrganizationCustomization`) or skip; `Always` configures without asking;
  `Never` skips. Provisioning can take time to propagate, so a re-run may be needed for the entries to
  apply. The tool stops after the first such failure rather than repeating it for every entry.
- **Tenant Allow/Block "allow" entries** may require a service-enforced expiration window; such items
  surface as reported failures rather than being silently dropped.
- **Preset security policy rules** can require the preset to be enabled in the portal first; those
  failures are reported clearly.
- Always review the dry-run output before running `-Live` / `-Execute` against a production tenant.

## Project layout

```
Invoke-MDOMigration.ps1         # entry: one-command end-to-end migration (export -> import -> verify)
config/
  tenants.example.json          # copy to config/tenants.json and fill in Source/Destination UPNs (git-ignored)
  PSScriptAnalyzerSettings.psd1 # lint rules
scripts/
  Export-MDOConfig.ps1          # export source tenant
  Import-MDOConfig.ps1          # import into target tenant (dry run by default)
  Compare-MDOConfig.ps1         # parity comparison
  Get-MDOPolicyReport.ps1       # optional JSON/Excel documentation report
  Set-MDORuleScope.ps1          # scope a rule set to all accepted domains (dry run by default)
src/
  MDOCommon.psm1                # config, connect, type registry, parameter mapping, read-only denylist
  MDOExport.psm1                # export engine
  MDOImport.psm1                # import engine
  MDOCompare.psm1               # comparison engine
```

## Validation

All scripts target PowerShell 7+, pass the PowerShell language parser, and are clean under
**PSScriptAnalyzer** (0 errors, 0 warnings):

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./config/PSScriptAnalyzerSettings.psd1
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
