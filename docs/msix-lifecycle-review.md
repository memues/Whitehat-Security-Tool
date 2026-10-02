# Whitehat Security Tool: MSIX lifecycle review

**Review preparation only. No functional MSIX conversion or certified package is
represented by this document or the manifest template.** The goal is to retain
supported monitoring and explicit response functions with free Microsoft Store
MSIX signing, subject to Microsoft's capability and lifecycle decisions.

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

## Review manifest

[`AppxManifest.xml.template`](../packaging/msix/AppxManifest.xml.template) records
the real identity, the exact display name, the proposed `runFullTrust` and
`allowElevation` declarations, and a proposed disabled-by-default startup task.
It is deliberately **not buildable**: required version, tested OS range, language
and asset values remain explicit `__REQUIRED_*__` tokens. It is not imported by a
project or release workflow. No logo assets have been supplied by this template.

The proposed desktop process runs at medium integrity; the existing executable's
ordinary launch remains `asInvoker`. Any elevated operation still requires user
initiation and Windows administrator consent. The startup extension proposes
`uap10:Parameters="--silent"` to reuse tray-only startup. Both the parameter delivery
and a new `StartupTask` opt-in/out integration need validation on the selected OS
range. The template does not implement either behavior.

Do not substitute plausible version/asset values and label this package ready.
First obtain Microsoft's eligibility and lifecycle guidance, implement the agreed
design, create the assets, validate the actual package, then set its real metadata.

## Lifecycle and validation matrix

Every row below is pending packaged implementation or verification. Existing EXE
smoke tests are evidence about shared logic only; they do not satisfy these rows.

| Area | Current desktop behavior / package concern | Required outcome and review evidence |
| --- | --- | --- |
| Identity and branding | The project produces `WhitehatSecurity.exe`; historical storage/registration identifiers use Whitehat Security. | Package identity exactly matches the Store draft; all public display names use Whitehat Security Tool. Keep internal compatibility identifiers separate. Verify shortcuts, task list, notifications and listing. |
| First launch | `Program.cs` offers self-installation outside its legacy Program Files location. | Packaged launch must never offer to copy itself, create a second installation or replace package files. Test first launch, activation and a read-only package directory. |
| Install/uninstall command modes | `--install` and `--uninstall` invoke the custom elevated EXE installer. | A packaged instance must not execute the legacy installer against itself or another edition. Verify every setup command and cancellation path under package identity. |
| Startup | The EXE uses an opt-in HKLM Run value. | Use the package startup declaration and supported user-controlled enable/disable flow. Verify logon launches in tray mode, Windows-disabled state is respected, and update never re-enables a disabled task. |
| Activation and coexistence | The global mutex/show event can overlap with an unpackaged instance. | Define supported migration/coexistence behavior. Test that either edition cannot silently divert the other's activation or block its launch. Do not delete an existing installation without consent. |
| Files and recovery data | Config/logs/quarantine/service journals use `Paths.DataDir`; privileged DNS backups use protected ProgramData storage. | Define package-safe locations and ownership for each data class. Recoverable originals and journals must not be lost when package-local data is removed. Verify update, repair, reset and removal with real records. |
| Administrator boundary | Helpers use `runas` for selected actions; standard-user UAC can use a different administrator account. | Validate helper activation, correct user context, argument integrity, cancellation and failure reporting with both administrator and standard accounts. Recovery paths must not accidentally switch to the administrator's profile. |
| Monitoring | Engines inspect local processes, network state, registry, services and security events. | Verify observations reach intended machine state under package identity and required access failures remain visible. A package must not silently turn monitoring into a view of only redirected app state. |
| Firewall and hosts response | The app applies identified firewall rules and marked hosts blocks outside ordinary package state. | Confirm Microsoft accepts the supported, consented actions and how changes are retained or reversed. Test create/remove/partial failure without altering unrelated settings or disabling platform protection. |
| DNS response | The app applies provider choices and keeps restoration data. | Use accepted public Windows interfaces; do not restore unsupported private DoH registry writes. Verify original DNS recovery, adapter changes, multi-user ownership and interruption recovery under the chosen package design. |
| Service and registry response | Eligible services and startup entries have saved state and conflict checks; protected settings are restricted. | Preserve the supported response intent and safeguards. Verify accepted APIs, changed-target rejection, recovery availability, and that protected Windows/security settings cannot be disabled through alternate commands. |
| Quarantine and process response | Quarantine relocates files; termination requires target access. | Verify target restrictions, recovery integrity and permissions inside the package. Test removal/reset while quarantined originals exist, and distinguish access denial from successful remediation. |
| Package updates | The EXE updater replaces the legacy installed binary. | Store updates own package files. Verify update while running, version changes, preserved user decisions, compatible recovery records and rollback/relaunch without self-replacement. |
| Package removal | Only the EXE uninstaller calls `CleanupManagedChanges`; a normal MSIX uninstall does not invoke that method automatically. | Obtain an acceptable lifecycle design for external system changes. Test removal from Windows Settings and Store with active rules/hosts/DNS changes; do not claim those changes are automatically reverted. |
| Multiple users | Installation and some system changes are machine-wide; MSIX registration is commonly per user. | Define ownership/ref-count/conflict behavior before implementation. One user's removal must not erase another user's active configuration or leave recovery inaccessible. Test two accounts and elevation using separate credentials. |
| Package and Store checks | There is no validated `.msix` output or completed certification. | Resolve all tokens, produce the package, inspect manifest/identity/assets, run applicable Windows package validation and the matrix above in disposable VMs, then complete reviewer notes and actual Store certification. |

## Questions that must precede final package design

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
This review template proposes none of those capabilities.

An advance capability reply is distinct from app certification. Only submit the
actual package for certification once the approved design works, the listing is
accurate, and installation/removal evidence supports the claims made to reviewers.

## Official implementation references

- [Restricted capabilities, elevation and custom install actions](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations)
- [desktop:StartupTask](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-desktop-startuptask)
- [desktop:Extension and startup parameters](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-desktop-extension)
- [Preparing a desktop application for MSIX](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-prepare)
- [Microsoft Store signing and publication](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/publish-first-app)
