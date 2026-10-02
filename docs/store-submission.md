# Microsoft Store EXE submission

This project uses the Microsoft Store **EXE installer** route. It is a WinForms
desktop security monitor with explicit administrator actions, a standalone
self-installer, and custom cleanup of its own firewall/hosts/DNS changes.
The normal build remains available for direct distribution. The Store build is
compiled with `StoreBuild=true` and keeps the restrictions documented in the app.

The repository alone is **not a certified or submission-ready product**. A real
publisher certificate, a verified signed release, a public privacy-policy URL,
Partner Center information, and installation tests are still needed. No submission
is performed by the build script.

## Why this is not an MSIX conversion

MSIX would require replacing the first-run self-install prompt, custom uninstall,
HKLM startup registration, and system-change cleanup with package-aware behavior.
Runtime elevation would also require Microsoft's restricted-capability approval.
Simply wrapping this EXE in an MSIX would leave important functionality or cleanup
unverified. The EXE route preserves the desktop installer and does not require
claiming an elevation exception has been approved.

## Free signing options

**Microsoft Store MSIX signing:** Microsoft signs certified MSIX packages, so this
route does not require buying a CA certificate. For Whitehat, it would require
package-aware installation, startup, storage and cleanup, plus either removing
the elevated system-changing features from that edition or obtaining Microsoft's
strictly reviewed elevation approval. This is a separate adaptation; the current
EXE package cannot receive that free MSIX signing. See Microsoft's
[signing guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/publish-first-app)
and [elevation rules](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/app-capability-declarations).

**SignPath Foundation:** acceptance is discretionary. Its
[terms](https://signpath.org/terms.html) require OSI licensing without commercial
dual-licensing, permitted dependencies, an actively maintained and released project,
documented functionality, MFA, assigned signing roles, a public signing/privacy
policy, verifiable builds and manual release approval. Vulnerability-discovery tools
are excluded; actual breach/malware detection has an exception.

Whitehat's vulnerable-driver warnings and non-loopback listener monitoring therefore
need a specific eligibility decision. There is also no root `LICENSE` file:
`README.md` refers only to a parent repository, although source files carry MIT
SPDX headers. Owner clarification is needed; this work does not change licensing.
Required signing roles, MFA, and a public signing policy have not been verified.
Do not describe SignPath acceptance or free signing as already available.

Foundation signing also cannot sign unrelated upstream binaries with the project's
certificate. The current local-certificate script is **not a hosted SignPath
integration** and must not be reused unchanged: it signs unsigned bundled PEs.
An accepted hosted workflow would need upstream-signature coverage compatible with
Microsoft's all-PE signing requirement. No application, account creation or message
has been sent; the [application page](https://signpath.org/apply.html) is a reference.

## Build the signed standalone installer

Prerequisites:

- Windows, the repository's .NET SDK, and Windows SDK SignTool.
- A currently valid code-signing certificate with its private key accessible in
  `CurrentUser\My` or `LocalMachine\My`. The issuing CA must belong to the
  **Microsoft Trusted Root Program**. A self-signed certificate does not qualify.
- Access to the certificate's revocation endpoints and an RFC 3161 timestamp
  service. Hardware/cloud private-key providers must be configured by the publisher.

From the repository root:

```powershell
.\scripts\Build-StorePackage.ps1 -CertificateThumbprint 'YOUR_40_HEX_CHARACTER_THUMBPRINT'
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

## Validate before submission

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
certification checks. MSIX's automatic uninstall guarantees do not apply here.

## Partner Center handoff

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
- [.NET single-file signing extension points](https://learn.microsoft.com/en-us/dotnet/core/deploying/single-file/overview#post-processing-binaries-before-bundling)
- [Distribution paths](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/choose-distribution-path)
