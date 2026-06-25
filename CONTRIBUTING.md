# Contributing to MDOMigrate

Thanks for your interest in improving MDOMigrate! This project helps administrators migrate and verify
Microsoft Defender for Office 365 / Exchange Online Protection policy configuration between tenants.

## Ways to contribute

- Report bugs or unexpected behavior.
- Add support for additional policy/rule types.
- Improve cross-tenant safety (parameter mapping, identity handling).
- Improve documentation and examples.

## Getting set up

You need **PowerShell 7.0+**. The runtime modules are only required when actually talking to a tenant;
you can develop and validate the code without them.

```powershell
# Validation tooling
Install-Module PSScriptAnalyzer -Scope CurrentUser

# Runtime modules (only needed to run against a real tenant)
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module ImportExcel -Scope CurrentUser
```

## Project structure

| File | Responsibility |
|------|----------------|
| `Invoke-MDOMigration.ps1` | Root entry point: end-to-end orchestrator (export → import → verify) |
| `tenants.example.json` | Template for `tenants.json` (Source/Destination domain + UPN) |
| `scripts/Export-MDOConfig.ps1` / `Import-MDOConfig.ps1` / `Compare-MDOConfig.ps1` | Thin per-step entry points (arg parsing + connect) |
| `scripts/Get-MDOPolicyReport.ps1` | Optional JSON/Excel documentation report |
| `src/MDOCommon.psm1` | Config, connect, type registry, parameter mapping, read-only/identity denylist |
| `src/MDOExport.psm1` | Export engine |
| `src/MDOImport.psm1` | Import engine |
| `src/MDOCompare.psm1` | Comparison engine |

Keep entry scripts thin; put logic in the `src/*.psm1` modules.

## Adding a new policy/rule type

1. Add an entry to `Get-MDOTypeRegistry` in `src/MDOCommon.psm1` with the correct `Category` and
   `Order` (policies before the rules that reference them; quarantine policies first).
2. If the type needs special handling (singleton, dedicated cmdlet shape), add a handler in
   `src/MDOImport.psm1` and route it in `Import-MDOConfiguration`.
3. Confirm read-only/identity properties are covered by `$Script:MDOReadOnlyProperty` so they are never
   replayed across tenants.

## Coding standards

- **PowerShell 7+**, approved verbs, `[CmdletBinding()]` on functions, singular nouns.
- Keep each file focused and reasonably small; split modules rather than growing one large file.
- Use the call operator (`& "Get-$type"`) and splatting — **never** `Invoke-Expression`.
- Destructive actions must honor the dry-run model: do nothing unless `-Execute` is passed.
- Never replay tenant-specific identity/UUID/timestamp values into another tenant.

## Before opening a pull request

1. **Lint must be clean** (0 errors, 0 warnings):
   ```powershell
   Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1
   ```
2. **Syntax must parse** for every script:
   ```powershell
   Get-ChildItem -Recurse -Include *.ps1,*.psm1 | ForEach-Object {
       $errors = $null
       [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errors) | Out-Null
       if ($errors.Count) { Write-Error "$($_.Name): $($errors.Count) parse error(s)" }
   }
   ```
3. If you changed import/compare logic, validate it against mocked cmdlets (no tenant required) so the
   create-vs-update decision, parameter mapping, and identity stripping still behave.
4. Update `README.md` if you changed behavior or added options.

## Pull request guidelines

- Keep PRs focused on a single change.
- Describe what you changed and why, and how you tested it.
- Note any new caveats for cross-tenant migrations.

## Reporting issues

Please include:

- What you ran (command + relevant switches; redact tenant names/secrets).
- What you expected vs what happened.
- The summary/error output (redacted).
- PowerShell version (`$PSVersionTable.PSVersion`) and `ExchangeOnlineManagement` module version.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
