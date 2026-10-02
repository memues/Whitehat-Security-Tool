# Whitehat Security Tool: MSIX lifecycle review

**A development MSIX can now be built. It is not cleared for Store submission or
certified.** The package retains supported monitoring and explicit response
functions. Microsoft Store signing remains the free distribution route, subject
to Microsoft's restricted-capability decision and successful certification.

## Confirmed Store draft identity

| Field | Value |
| --- | --- |
| Exact Store/application display name | Whitehat Security Tool |
| Store ID | `9MTVDV7FSJDS` |
| Package identity name | `omni.apps.WhitehatSecurityTool` |
| Package publisher | `CN=79C00735-EF73-493D-AE6B-36BE09C31052` |
| Publisher display name | `omni.apps` |
| Expected package family name | `omni.apps.WhitehatSecurityTool_mhkhb0gkqyqq8` |
| Current source architecture | x64 |

A Store draft and assigned identity do not establish approval of `allowElevation`,
the developer account's eligibility, package validity, or certification. Store
submission status and external correspondence are tracked in
[the submission guide](store-submission.md).

## Implemented package behavior

[`AppxManifest.xml.template`](../packaging/msix/AppxManifest.xml.template) is the
source manifest for [`Build-MsixPackage.ps1`](../scripts/Build-MsixPackage.ps1).
The script reads the real version from the project, resolves OS-version tokens,
draws the existing product shield/checkmark at package-asset resolutions, and
publishes an x64 self-contained, multi-file application with `StoreBuild=true`.
Restore rejects known NuGet vulnerabilities or unavailable audit data, and checks
that embedded third-party notices match the actual restored runtime dependencies.
MakeAppx semantic validation must succeed; `/nv` is never used. The real identity,
English UI resources, exact display name, `runFullTrust` and `allowElevation`
declarations, and disabled startup task are included in the resulting MSIX.

The desktop process runs at medium integrity; the existing executable's
ordinary launch remains `asInvoker`. Any elevated operation still requires user
initiation and Windows administrator consent. Native Windows package identity
detection suppresses the legacy first-run install prompt and rejects packaged
`--install`/`--uninstall` commands before elevation or installer writes. Packaged
instance mutex/events are separated from the EXE edition and scoped to the user
and logon session.

The startup extension passes `--silent` for tray startup. A packaged-only tray
menu opens **Windows Settings > Apps > Startup**; Windows owns the enable/disable
choice. The app does not create a Run key or override a disabled-by-user task.
An unconfigured silent startup exits without opening a folder picker. Startup
parameter delivery and logon behavior still require actual packaged tests.

On the first interactive packaged launch, the user explicitly selects a local
data/recovery folder outside AppData, system, temporary and known OneDrive
locations. Only the selection pointer belongs to the package. The selected
folder and its recovery records are retained; resetting/reinstalling the app
requires choosing that same folder again. Missing/replaced storage is rejected,
not silently recreated. Response actions check its availability before applying
changes. This does not solve ownership of machine-wide changes shared with the
EXE edition or another Windows user; those remain release-review requirements.

## Build and review gates

With .NET 8 SDK, PowerShell 7 and Windows SDK MakeAppx available:

```powershell
pwsh -File scripts/Build-MsixPackage.ps1
```

Use `-DotNetPath` and `-MakeAppxPath` if the required tools are outside PATH and
the standard SDK directory. Each run creates a fresh directory under
`artifacts/msix`, containing an **unsigned development package**, the actual
manifest/assets, publish and MakeAppx logs, SHA-256 payload inventory, a
`candidate-record.json`, and `review-evidence.pending.json`. No certificate is
created, trusted or imported, and nothing is submitted. Test-sign a copy only in
a disposable Windows environment; keep the original unsigned candidate intact.

The default OS target is `10.0.19041.0`. This is a build target, not evidence that
Windows 10 build 19041 was tested. Set the final minimum and maximum target values
only after testing the supported OS range. A successful package build does not
prove elevation, correct host-state monitoring, startup, recovery or removal.

After the actual package has passed review, use:

```powershell
pwsh -File scripts/Build-MsixPackage.ps1 -Mode StoreSubmission `
  -CandidateRecordPath <candidate-record.json> -ReviewEvidencePath <review-evidence.json>
```

This mode does not rebuild or upload. It checks the exact unsigned package hash,
identity, clean committed source provenance, named reviewer/time, and affirmative review records with existing,
nonempty evidence files for restricted capabilities, publisher account, minimum
OS, administrator/standard users, startup/update, external changes/recovery,
install/reset/uninstall, security/package validation, and listing/privacy. It
records evidence hashes. These are review attestations, not independently
authenticated Microsoft approvals. Leave every uncompleted item **Pending**;
the default evidence file deliberately fails the submission gate. Actual Store
certification is a subsequent, separate decision by Microsoft.

Uploading an unsigned package to the existing Partner Center **draft** for
server-side package validation is a separate preparation step. A draft upload is
not a certification submission, restricted-capability approval or publication.
It must retain accurate pending status; do not select **Submit for certification**
while the approval or technical release gates are unresolved. This build script
performs neither a draft upload nor a certification submission.

## Lifecycle and validation matrix

The implementation notes above establish which code exists. Every outcome below
still needs packaged evidence. Existing EXE smoke tests are evidence about shared
logic only; they do not satisfy the corresponding MSIX lifecycle checks.

| Area | Current desktop behavior / package concern | Required outcome and review evidence |
| --- | --- | --- |
| Identity and branding | The project produces `WhitehatSecurity.exe`; historical storage/registration identifiers use Whitehat Security. | Package identity exactly matches the Store draft; all public display names use Whitehat Security Tool. Keep internal compatibility identifiers separate. Verify shortcuts, task list, notifications and listing. |
| First launch | Package identity suppresses the EXE self-install prompt and asks for an explicitly selected durable data folder. | Verify first launch, cancelled selection, activation and a read-only package directory. No duplicate installation or package-file replacement. |
| Install/uninstall command modes | Packaged `--install`/`--uninstall` return error 87 before invoking the EXE installer. | Verify quiet/interactive variants under actual package identity, no installer writes, no UAC, no interference with an existing EXE edition. |
| Startup | Disabled package startup task; tray opens Windows Startup Settings. | Verify logon launches in tray mode, Windows-disabled state is respected, unconfigured silent startup exits, and update never re-enables a disabled task. |
| Activation and coexistence | Packaged mutex/event uses PFN, user SID and Local session namespace; EXE keeps its prior names. | Verify each edition activates correctly and cannot divert the other's activation. Shared machine-state ownership remains unresolved; no installation is deleted automatically. |
| Files and recovery data | Packaged config/logs/quarantine/service journals use an explicitly selected external folder with a persistent identity marker; privileged DNS backup still uses protected ProgramData storage. | Verify reset/removal/reinstall reopen retained records, missing storage blocks response, different-account UAC is correct, and other-user/EXE ownership cannot conflict. |
| Administrator boundary | Helpers use `runas` for selected actions; standard-user UAC can use a different administrator account. | Validate helper activation, correct user context, argument integrity, cancellation and failure reporting with both administrator and standard accounts. Recovery paths must not accidentally switch to the administrator's profile. |
| Monitoring | Engines inspect local processes, network state, registry, services and security events. | Verify observations reach intended machine state under package identity and required access failures remain visible. A package must not silently turn monitoring into a view of only redirected app state. |
| Firewall and hosts response | The app applies identified firewall rules and marked hosts blocks outside ordinary package state. | Confirm Microsoft accepts the supported, consented actions and how changes are retained or reversed. Test create/remove/partial failure without altering unrelated settings or disabling platform protection. |
| DNS response | The app applies provider choices and keeps restoration data. | Use accepted public Windows interfaces; do not restore unsupported private DoH registry writes. Verify original DNS recovery, adapter changes, multi-user ownership and interruption recovery under the chosen package design. |
| Service and registry response | Eligible services and startup entries have saved state and conflict checks; protected settings are restricted. | Preserve the supported response intent and safeguards. Verify accepted APIs, changed-target rejection, recovery availability, and that protected Windows/security settings cannot be disabled through alternate commands. |
| Quarantine and process response | Quarantine relocates files; termination requires target access. | Verify target restrictions, recovery integrity and permissions inside the package. Test removal/reset while quarantined originals exist, and distinguish access denial from successful remediation. |
| Package updates | The packaged app bypasses the legacy self-install/update path; Store owns package files. | Verify update while running, version changes, preserved user decisions, compatible recovery records and rollback/relaunch without self-replacement. |
| Package removal | Only the EXE uninstaller calls `CleanupManagedChanges`; a normal MSIX uninstall does not invoke that method automatically. | Obtain an acceptable lifecycle design for external system changes. Test removal from Windows Settings and Store with active rules/hosts/DNS changes; do not claim those changes are automatically reverted. |
| Multiple users | Installation and some system changes are machine-wide; MSIX registration is commonly per user. | Define ownership/ref-count/conflict behavior before implementation. One user's removal must not erase another user's active configuration or leave recovery inaccessible. Test two accounts and elevation using separate credentials. |
| Package and Store checks | The build script produces a semantically validated unsigned development MSIX and blocks submission review while evidence is pending. | Run applicable Windows package validation and this matrix in disposable VMs, then complete approval evidence, reviewer notes and actual Store certification. |

## Questions that must precede final release

1. Can this publisher and the retained response scope receive `allowElevation`
   approval, and which evidence or account verification does Microsoft require?
2. Is the proposed explicit-UAC helper model acceptable for the listed supported
   actions, or is another documented architecture required?
3. What lifecycle behavior is acceptable for app-authored changes outside package
   state, and how must recovery data survive package removal/reset?
4. Which minimum Windows version and package requirements apply to the accepted
   design, including the startup parameter and activation behavior?

Do not assume a custom uninstall extension solves the third question. Microsoft's
published capability guidance restricts `customInstallActions` to specific game
scenarios. Adding a service, sparse package or unvirtualized storage is also not
an approved shortcut; each introduces additional deployment and permission issues.
The development manifest proposes none of those capabilities.

An advance capability reply is distinct from app certification. Only submit the
actual package for certification once the approved design works, the listing is
accurate, and installation/removal evidence supports the claims made to reviewers.

## Official implementation references

- [Restricted capabilities, elevation and custom install actions](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations)
- [desktop:StartupTask](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-desktop-startuptask)
- [desktop:Extension and startup parameters](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-desktop-extension)
- [GetCurrentPackageFullName](https://learn.microsoft.com/en-us/windows/win32/api/appmodel/nf-appmodel-getcurrentpackagefullname)
- [StartupTask and Windows-managed startup choices](https://learn.microsoft.com/en-us/uwp/api/windows.applicationmodel.startuptask)
- [Supported Windows Settings URI for startup apps](https://learn.microsoft.com/en-us/windows/apps/develop/launch/launch-settings#apps)
- [MakeAppx packaging and semantic validation](https://learn.microsoft.com/en-us/windows/msix/package/create-app-package-with-makeappx-tool)
- [Preparing a desktop application for MSIX](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-prepare)
- [Microsoft Store signing and publication](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/publish-first-app)
