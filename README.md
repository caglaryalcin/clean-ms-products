# Clean MS Products

Clean MS Products removes selected optional Windows apps and features, then applies privacy-focused Microsoft policies. It targets Windows 10 22H2 and current Windows 11 releases and requires 64-bit Windows PowerShell 5.1 running as administrator on 64-bit Windows. Windows 10 22H2 reached end of support on October 14, 2025; use it only with applicable Extended Security Updates or with full awareness of the unsupported state.

## What it does by default

- Removes an explicit list of optional AppX/MSIX apps from existing users and the provisioning layer for future users.
- Handles the current `Microsoft.OutlookForWindows` and `Microsoft.Copilot` package names as well as legacy inbox apps.
- Removes Windows Media Player (legacy), Work Folders Client, Fax/Scan, the XPS writer feature, and their printer queues when present.
- Minimizes documented Microsoft Edge and Office diagnostic/personalization settings.
- Disables Windows settings sync, Windows 11 Widgets, or Windows 10 News and interests through the appropriate documented policy keys.
- Uninstalls OneDrive and disables sync without explicitly deleting the contents of OneDrive folders.
- Force-removes the machine-wide Edge browser with its Microsoft-signed installer and, when needed, retries with temporary `EdgeUpdateDev\AllowUninstall`, `WINDIR`, EU-region, and protected region-policy overrides.

Teams is not removed by default. The default target list does not include framework packages, media codecs, or the Windows Web Experience Pack. WebView2 runtime files are not directly deleted. The Edge fallback temporarily edits and then restores `EdgeUpdateDev\AllowUninstall`, `WINDIR`, the `.DEFAULT` region, and the System32/SysWOW64 copies of `IntegratedServicesRegionPolicySet.json` plus their ACLs; after confirmed Edge removal it unregisters allowlisted Edge Update tasks. Those shared update tasks can also affect WebView2 updates.

## Run

Open **64-bit Windows PowerShell 5.1 as administrator**. The project remains a single-file remote command; HTTPS redirects to the current `main/set.psm1`:

```powershell
iwr "https://del-ms.caglaryalcin.com" -UseB | iex
```

Direct `iwr | iex` uses the default removal profile immediately. To preview changes or pass options, download and import the same file first; importing defines the command but does not start cleanup:

```powershell
iwr "https://del-ms.caglaryalcin.com" -UseB -OutFile .\set.psm1
Import-Module .\set.psm1 -Force
Invoke-CleanMsProducts -WhatIf
```

## Common options

```powershell
# Keep apps that are removed by the default profile
Invoke-CleanMsProducts -KeepApp 'Microsoft.OutlookForWindows', 'Microsoft.WindowsAlarms'

# Also remove new/consumer Teams and machine-wide MSI Teams Meeting Add-ins
Invoke-CleanMsProducts -RemoveTeams

# Keep Edge; forced browser removal is otherwise part of the default run
Invoke-CleanMsProducts -SkipEdge

# Run only the policy sections; do not remove apps, features, OneDrive, or Edge
Invoke-CleanMsProducts -SkipApps -SkipOptionalFeatures -SkipOneDrive -SkipEdge

# Inspect itemized results
Invoke-CleanMsProducts -WhatIf -PassThru | Format-Table -AutoSize
```

Available skip switches are `-SkipApps`, `-SkipOptionalFeatures`, `-SkipPrivacy`, `-SkipWindowsSync`, `-SkipWidgets`, `-SkipCopilot`, `-SkipOneDrive`, and `-SkipEdge`. Use `-AdditionalApp` to supply exact extra AppX package names; wildcards are rejected before any changes. `KeepApp` does accept wildcard patterns. `UnusedApps` remains an alias for `Invoke-CleanMsProducts` when the module is imported.

## Important behavior and limits

- App removal is potentially irreversible for local app data. Create a backup or restore point and use `-WhatIf` first.
- `-AdditionalApp` applies to both installed and provisioned packages. Use exact application names only; do not add framework, runtime, codec, or dependency package names.
- `Microsoft.OutlookForWindows` is now preinstalled on newer Windows builds. Preserve it with `-KeepApp Microsoft.OutlookForWindows` if you use new Outlook.
- `-RemoveTeams` is opt-in because `MSTeams` can be a work/school client, not merely a consumer app.
- The old `TurnOffWindowsCopilot` policy is deprecated. The script removes the current `Microsoft.Copilot` package and keeps the old policy only as a compatibility fallback. Managed organizations should use AppLocker to prevent reinstallation.
- Edge removal deliberately goes beyond Microsoft's supported uninstall matrix. Unless `-SkipEdge` is used, the script verifies the machine-wide setup signature and first invokes `--uninstall --msedge --force-uninstall` directly. If Edge remains, it repeats the signed setup with temporary 32-bit `EdgeUpdateDev\AllowUninstall`, machine/process `WINDIR`, `.DEFAULT` Geo values `FR/84`, and finally the Edge-uninstall policy GUID enabled in both System32 and SysWOW64 `IntegratedServicesRegionPolicySet.json` files. Registry values are restored with their original types; each JSON's original bytes are restored after verified byte backups and its ACL is restored from the captured original SDDL in `finally`. A machine-wide mutex prevents two deep-removal runs from snapshotting each other's temporary state. After confirmed removal, allowlisted Edge Update tasks are unregistered and best-effort values are written to block reinstallation. Exit code 3010 stops the fallback chain and is reported as `RestartRequired`. Removing shared update tasks can affect WebView2 updates, and removing Edge can break Edge-dependent apps, PWAs, News, Search, Weather, or Widgets.
- `finally` rollback covers normal completion and catchable failures. Terminating `powershell.exe`, a forced reboot, or power loss during a deep fallback can bypass `finally`; do not interrupt that phase. JSON recovery `.bak` files are retained when an in-process restore fails and their paths are reported.
- `DiagnosticData=0` minimizes Edge diagnostic data but Microsoft marks the setting as not recommended because it reduces diagnostic capability. Use `-SkipPrivacy` if that tradeoff is not wanted.
- Office's `SendTelemetry=3` means neither required nor optional client diagnostic data, but Microsoft 365 can still send required service data for licensing and connected services.
- The Widgets, News and interests, and settings-sync policies are supported on Pro/Enterprise/Education and listed IoT editions, not Home; writing the values on Home is not guaranteed to have policy effect.
- On managed Windows 11 24H2 Enterprise/Education devices, Microsoft's policy-based inbox app removal is preferable because it also blocks selected apps from being reinstalled.
- The command reports `Failed` operations in its summary and warnings. Use `-PassThru` to include itemized results.
- The script never explicitly removes OneDrive folder contents. Microsoft states that uninstalling OneDrive does not lose the files or data and that they remain accessible on OneDrive.com; cloud-only placeholders should not be treated as local backups.
- OneDrive removal covers the machine-wide installation and the account running the script. A separate per-user installation belonging to another Windows profile is not executed with elevated privileges; the machine policy still disables syncing.

## Why this update was needed

Microsoft changed several relevant interfaces after the original release:

- Windows Mail and Calendar support ended on December 31, 2024, and new Outlook uses `Microsoft.OutlookForWindows`.
- The standalone Copilot app uses `Microsoft.Copilot`; the old Windows Copilot policy is being retired.
- New Teams uses `MSTeams`; a fixed Teams Meeting Add-in MSI product code is not stable.
- AppX removal for current users and image provisioning are separate operations. Both layers now get handled explicitly.
- Several old Edge policies are obsolete, including `AddressBarMicrosoftSearchInBingProviderEnabled`; current diagnostic and Copilot-toolbar policies are used instead. Forced browser removal and the restored deep-removal fallback chain are deliberate defaults that can be disabled with `-SkipEdge`.
- Removing `MicrosoftWindows.Client.WebExperience` is no longer used to disable Widgets; the documented Widgets policy is used.

## Microsoft references

- [Remove AppX packages](https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage)
- [Remove provisioned AppX packages](https://learn.microsoft.com/en-us/powershell/module/dism/remove-appxprovisionedpackage)
- [Manage Windows and Microsoft 365 Copilot](https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot)
- [Control installing and using new Outlook](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/get-started/control-install)
- [Uninstall the Teams client](https://learn.microsoft.com/en-us/microsoftteams/teams-client-uninstall)
- [Microsoft Edge Update policies](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-update-policies)
- [Microsoft Edge browser policies](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies)
- [Widgets policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-newsandinterests)
- [Windows 10 News and interests policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-feeds)
- [Office privacy controls](https://learn.microsoft.com/en-us/microsoft-365-apps/privacy/manage-privacy-controls)
- [Turn off, disable, or uninstall OneDrive](https://support.microsoft.com/en-us/onedrive/turn-off-disable-or-uninstall-onedrive)
- [Policy-based inbox app removal](https://learn.microsoft.com/en-us/windows/configuration/policy-based-inbox-app-removal/policy-based-inbox-app-removal)
- [Windows 10 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro)
