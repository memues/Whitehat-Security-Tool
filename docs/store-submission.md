# Microsoft Store preparation

Whitehat Security Tool is a WinForms desktop security monitor with explicit
administrator actions. The repository now contains **MSIX development packaging
and package-aware runtime behavior**, alongside the existing standalone EXE
installer route. Supported response functions remain part of the product.
The normal build remains available for direct distribution. Both Store packaging
scripts compile with `StoreBuild=true` and retain the documented restrictions.

The repository alone is **not a certified or submission-ready product**. An
approved capability/account route, a verified release candidate and packaged
installation tests are still needed. Neither packaging script submits a product.

## Approval status — 2 October 2026

The exact product name **Whitehat Security Tool** is reserved in Partner Center
as an MSIX app, Store ID `9MTVDV7FSJDS`. Submission 1 is a draft, not a
certification submission. Publisher display name: `omni.apps`; the current
developer account type is **Individual**. The draft's category, privacy-policy
URL, support links and x64 requirement have been saved. Properties and free
worldwide pricing/availability are complete. English (United States) and Turkish
(Türkiye) listings are complete with two actual application screenshots and
captions each; both correctly identify the interface as English. Submission
options include explicit restricted-capability justifications and reviewer notes.
The unsigned 7.4.20 candidate is saved in the Store draft; package acceptance
completed with a restricted-capability approval warning. The IARC preview
returned ESRB Everyone and PEGI 3+; its final legal acceptance is pending.

An advance `allowElevation` eligibility request was sent to Microsoft's
documented contact, `reportapp@microsoft.com`, with the real product identity,
account type, preserved response functions and unresolved package lifecycle.
An eligibility inquiry was also sent to `support@signpath.io` for the Foundation
free-signing route. Neither request constitutes approval, signing acceptance,
or app certification. Both responses are pending.

The [MSIX lifecycle review](msix-lifecycle-review.md) records the reserved identity
and validation questions. The manifest is now consumed by
[`Build-MsixPackage.ps1`](../scripts/Build-MsixPackage.ps1), which supplies actual
version/OS metadata and generated assets. A successful development build proves
packaging checks passed; it does not establish runtime compatibility or Store
approval. The EXE remains an alternative if an accepted free-signing workflow
becomes available.

## Recorded validation

The [dated validation record](store-validation-2026-10-02.json) identifies the
exact unsigned package, product commit, test-only follow-up commit and CI runs.
The test sequence passed 83 isolated lifecycle checks: 19 on a 7.4.19 pilot and
64 on the final 7.4.20 update/reset/removal/reinstallation sequence. Original data
could be reopened through actual first-launch UI after reset and reinstall.
There were 56 normal and 55 Store smoke tests at the test-harness follow-up;
both GitHub build jobs and the CodeQL gate passed after individual false-positive
review. No security rule or source path was excluded.

This is partial platform evidence: the guest was Windows 11 24H2 with an
administrator account, UAC disabled and no network adapter. Minimum-OS,
standard-user UAC, real DNS, startup/logon and multi-user external-change behavior
remain unverified. The local sideload signature was created only inside the
disposable guest; Microsoft Store certification and restricted-capability
approval have not been granted.

## Implemented MSIX behavior and remaining validation

Windows package identity selects the runtime behavior; a build flag or directory
name does not impersonate package identity. A packaged launch bypasses the EXE
self-install prompt, refuses legacy install/uninstall commands, and uses separate
package/user instance objects. The package declares an initially disabled startup
task. A tray command opens Windows Startup Settings, where the user controls it;
the packaged flow does not register the legacy HKLM startup entry.

The first interactive packaged launch asks the user to confirm or choose a local
data/recovery directory outside AppData and the package. Logs, configuration,
quarantined originals and service recovery journals remain in this folder after
package reset/removal. Only a folder pointer lives in package-owned LocalState.
After reset/reinstallation, selecting the existing folder reopens its records.
Configured folders are not silently recreated if missing or replaced; a durable
folder identity and path checks must pass. Network/removable drives, known
OneDrive locations, system/app/temp directories, aliases and reparse paths are
rejected. The first unattended launch exits until the user selects a folder.
Response actions check that recovery storage is available before proceeding.
The existing administrator-protected DNS backup remains in ProgramData; it is
not moved into the user's writable recovery folder.

MSIX removal does not call the EXE uninstaller's `CleanupManagedChanges` routine.
Do not promise that removing the package automatically reverses intentional
firewall, hosts, DNS, service or registry responses. The design preserves recovery
records and exposes supported in-app reversal; the exact behavior, conflicts,
multi-user ownership and reinstallation recovery need packaged VM evidence.
The Store's clean-uninstall rule does not explicitly require unconditional
rollback of every user-directed system change, but that is not an app-specific
acceptance decision. The proposed design must still satisfy Microsoft's review.

Minimum-OS behavior, standard-user package elevation, Windows logon/startup,
observation of actual machine state, and recovery of real external changes are
outstanding verification gates. The recorded install/update/reset/removal evidence
is limited to the isolated guest described above. A monitoring-only edition has
not been selected. Platform
protection and supported-API restrictions apply to every response function.

## Free signing options

**Microsoft Store MSIX signing:** Microsoft signs certified MSIX packages, so this
route does not require buying a CA certificate. Whitehat's implemented MSIX
adaptation retains user-directed elevated functions and therefore requires
Microsoft's strictly reviewed `allowElevation` approval, plus validation of the
package lifecycle described above. Its standalone EXE cannot receive this free
MSIX signing. See Microsoft's
[signing guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/publish-first-app)
and [elevation rules](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations).

**SignPath Foundation:** acceptance is discretionary. Its
[terms](https://signpath.org/terms.html) require OSI licensing without commercial
dual-licensing, permitted dependencies, an actively maintained and released project,
documented functionality, MFA, assigned signing roles, a public signing/privacy
policy, verifiable builds and manual release approval. Vulnerability-discovery tools
are excluded; actual breach/malware detection has an exception.

Whitehat's vulnerable-driver warnings and non-loopback listener monitoring therefore
need a specific eligibility decision. Repository history explicitly declared MIT,
and current source files carry MIT SPDX headers. The owner confirmed that the
historical author aliases belong to them. Full project and dependency license
notices are included in the repository and executable; see
[license provenance](license-provenance.md). Foundation eligibility still
requires its own review.
Required signing roles, MFA, and a public signing policy have not been verified.
Do not describe SignPath acceptance or free signing as already available.

Foundation signing also cannot sign unrelated upstream binaries with the project's
certificate. The current local-certificate script is **not a hosted SignPath
integration** and must not be reused unchanged: it signs unsigned bundled PEs.
An accepted hosted workflow would need upstream-signature coverage compatible with
Microsoft's all-PE signing requirement. No formal application or signing account
has been created. A preliminary inquiry has been sent; the
[application page](https://signpath.org/apply.html) is a reference for formal onboarding.

## Build an MSIX development candidate

Prerequisites: Windows, PowerShell 7, the exact SDK selected by `global.json`, and
Windows SDK MakeAppx. Development mode creates an unsigned package for isolated
testing; it neither installs a trust certificate nor uploads the package.

```powershell
pwsh -NoProfile -File .\scripts\Build-MsixPackage.ps1 -Mode Development
```

Use `-DotNetPath`, `-MakeAppxPath` and `-OutputDirectory` to select local tools and
output. The script checks the reserved identity, uses a distinct output directory
for each run, generates logo assets, and invokes MakeAppx with semantic validation
enabled. The output includes the unsigned `.msix`, tool logs, payload hashes,
`candidate-record.json` and a pending review-evidence file. The default OS metadata
targets Windows 10 build 19041; the minimum supported and maximum tested versions
must be justified by actual testing, not inferred from successful packaging.

The script's `StoreSubmission` mode verifies that the original candidate hash
matches a completed review-evidence file and its referenced evidence documents:

```powershell
pwsh -NoProfile -File .\scripts\Build-MsixPackage.ps1 -Mode StoreSubmission `
  -CandidateRecordPath 'PATH_TO_CANDIDATE_RECORD' `
  -ReviewEvidencePath 'PATH_TO_COMPLETED_REVIEW_EVIDENCE'
```

This records human review attestations; it cannot authenticate Microsoft's
approval or certify the app. Leave uncompleted reviews pending. Do not edit a
pending field to `Verified` solely because a source build or MakeAppx succeeded.

Test the exact candidate in disposable Windows VMs: first manual and silent
launch, standard-user UAC with separate administrator credentials, explicit
response/undo, offline operation, startup opt-in/out, update, reset and removal.
Include retained quarantine/journals, a missing or replaced recovery folder,
unrelated system changes, and reopening the folder after reinstall. Preserve the
original unsigned candidate and its hash when preparing a separately test-signed
copy for sideload testing. Store certification must evaluate the actual candidate.

## Alternative: build the signed standalone installer

Prerequisites:

- Windows, PowerShell 7 (`pwsh`), the repository's .NET SDK, and Windows SDK SignTool.
- A currently valid code-signing certificate with its private key accessible in
  `CurrentUser\My` or `LocalMachine\My`. The issuing CA must belong to the
  **Microsoft Trusted Root Program**. A self-signed certificate does not qualify.
- Access to the certificate's revocation endpoints and an RFC 3161 timestamp
  service. Hardware/cloud private-key providers must be configured by the publisher.

From the repository root:

```powershell
pwsh -NoProfile -File .\scripts\Build-StorePackage.ps1 -CertificateThumbprint 'YOUR_40_HEX_CHARACTER_THUMBPRINT'
```

Use `-CertificateStore LocalMachine`, `-SignToolPath`, `-TimestampUrl`, or
`-OutputDirectory` when required by your signing setup. Execution must comply with
the publisher machine's PowerShell policy. No certificate or trust-root installation
is performed by this script.

The script stops when signing prerequisites or validation fail. It copies all
single-file bundle inputs into an isolated staging directory, signs unsigned PE
files before bundling, preserves valid vendor signatures, rejects invalid existing
signatures, and signs/timestamps the final EXE. It does not alter the .NET runtime
or NuGet caches. Every staged PE and the final EXE are checked with Authenticode
and SignTool. Checking local certificate trust does **not** prove that the issuing
CA belongs to Microsoft's program; the publisher must verify that requirement.

The versioned `artifacts/store/<version>-<unique-id>/release/` directory contains
the standalone installer and `store-package.json` with its SHA-256 hash, signing
inventory, and silent switches. The intermediate payload directory is retained
for independent signature inspection. Do not upload an ordinary unsigned publish
output or claim that signing the outer EXE alone verifies its embedded assemblies.

## Validate the EXE alternative before submission

Run the smoke tests for the Store build:

```powershell
dotnet run --project tests\WhitehatSecurity.SmokeTests -c Release -p:StoreBuild=true
```

Use a disposable Windows VM for actual installation testing. Do not use a work
machine containing an existing Whitehat installation or security settings to keep.

1. Download the exact signed candidate from its intended immutable HTTPS URL.
   Verify the SHA-256 hash against `store-package.json` and its publisher signature.
2. Install with `--install --quiet`. No installer UI should appear apart from UAC.
   Confirm its process exit code, Apps & Features entry, shortcuts, and installed
   binary signature. Test under a standard account and an administrator account.
3. Launch normally and confirm all Store-visible functions work without internet
   downloads of required application files or a separately installed .NET runtime.
   Confirm the first-run installer prompt is absent for the installed copy.
4. Verify explicit consent for the supported administrator actions and verify
   that the Store build cannot disable Windows Firewall or write unsupported
   Windows DoH registry settings. Verify unavailable monitoring is reported clearly.
5. Exercise install-over-existing-version and repeat installation. Validate startup
   opt-in/out and cancellation of UAC. Run these tests with non-ASCII user paths too.
6. Uninstall with `--uninstall --quiet` and through Windows Settings. Check process
   exit codes and cleanup of installation, shortcuts, startup registration, and
   app-managed settings. Separately verify that pre-existing unrelated settings,
   quarantine contents, and recovery records receive the documented treatment.
7. Repeat on every supported Windows version. Record the OS build, candidate hash,
   exact commands, exit codes, and observed results in the release evidence.

A source build or smoke-test pass does not substitute for those installation and
certification checks. The EXE uninstaller has its own lifecycle; its results do
not validate the MSIX package's Windows-managed removal path.

## Partner Center handoff

For the reserved **MSIX** product, use its exact assigned identity. A development
candidate may be uploaded to the draft for server-side validation; submit the
reviewed package for certification only after the capability/account and runtime
gates are resolved.
Complete the listing, age rating, screenshots, privacy/support links and reviewer
instructions. Explain the retained recovery folder, intentional system changes,
explicit UAC, startup control and how to test reversal. A draft/package upload and
restricted-capability approval are each distinct from final app certification.

For an accepted **EXE alternative**, use the appropriate Win32 submission route:

- Create or select the correct developer-owned Win32 product and publisher.
- Host the signed EXE at a versioned direct HTTPS URL. Never replace the binary
  at a submitted URL; publish a new URL for every changed binary.
- Enter `--install --quiet` as the silent installation arguments, x64 architecture,
  accurate Windows requirements, and the package's version and language metadata.
- Provide an accurate app description, support contact, screenshots, age rating,
  and the public privacy-policy URL. Explain that this is a monitoring and response
  tool; do not describe heuristic scanning as a guaranteed malware diagnosis.
- Include reviewer notes for features needing administrator consent, unavailable
  Windows-version-dependent features, and Store-build restrictions.
- Submit only after the publisher credentials, CA eligibility, URL, VM test results,
  and Store listing have been verified. Microsoft makes the certification decision.

The Store does not deliver updates for the MSI/EXE path in the same way it does for
MSIX. Publish a newly signed version and update the versioned installer URL for a
new Store submission; keep the in-app/direct-download update instructions accurate.

## Official references

- [MSI/EXE package requirements](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/app-package-requirements)
- [Manual MSI/EXE package validation](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msi/manual-package-validation)
- [Restricted capabilities and elevation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations)
- [Packaged desktop runtime and virtualization](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes)
- [Durable user data versus package-owned app data](https://learn.microsoft.com/en-us/windows/apps/develop/data/store-and-retrieve-app-data)
- [Flexible virtualization and writable locations](https://learn.microsoft.com/en-us/windows/msix/desktop/flexible-virtualization)
- [Microsoft Store policies 7.19](https://learn.microsoft.com/en-us/windows/apps/publish/store-policy-archive/store-policy-7-19)
- [.NET single-file signing extension points](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview#post-processing-binaries-before-bundling)
- [Distribution paths](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/choose-distribution-path)
