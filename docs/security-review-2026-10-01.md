# Whitehat CodeQL baseline triage and remediation record

Reviewed 2026-10-01. This is a triage of the existing default-branch scan, not a claim that the final release scan is clean. No alert was dismissed or hidden.

- Repository: memues/Whitehat-Security-Tool
- Baseline commit: 175678ac9fc49c2835da39e13ded152704a1b453
- C# CodeQL analysis: 1874740972; CodeQL 2.27.1, build-mode none; 91 results, 63 rules.
- GitHub labels: 7 critical command-line alerts (#85-91), 84 high path alerts (#1-84).
- Raw evidence is available from the GitHub CodeQL analysis ID above.
- Review traced the SARIF source and sink locations, then inspected the corresponding code and calling privilege context. Source locations reported by the scan refer to the baseline, not the changed checkout.

## Substantiated security defects requiring fixes

1. **Mutable scripts across elevation**: #85/#86 identify command lines containing temp script paths. The base64 bootstrap and quoted path themselves do not admit command-line syntax injection, but the baseline rereads and executes a user-writable script after UAC approval. This is a genuine boundary defect. The owning agent is pinning a hash of the intended script into the immutable launcher and executing the exact byte snapshot verified, and using trusted absolute PowerShell paths.
2. **Mutable self-delete batch**: #28/#87 cover an elevated uninstaller writing and executing a per-user temp batch, then waiting before deleting. Replacing this with an in-memory encoded command avoids both script replacement and cmd metacharacter expansion. The owner is fixing it.
3. **Privileged log append**: #5/#12 contain real product flows from Program.RunInstall/RunUninstall to Logger(Path.GetTempPath()). Logger appends to predictable monitor_yyyy-MM-dd.log. A same-user attacker can preplant a link at that path to redirect the privileged append. These alerts also contain test sources; the product sources must not be dismissed with the test cases. The owner was notified to avoid privileged logging to user-writable temp.
4. **Privileged error output**: although the visible C# #20/#21 are only unprivileged reads, the generated baseline PowerShell writes error detail with Set-Content to a writable-temp pathname, permitting a planted existing link to redirect the elevated write. The owner changed this to exclusive creation; final review must confirm ancestor protection/appropriate scope.

## Other independently observed boundaries

- ProgramData DNS backup: DnsConfiguration and cleanup consume an existing ProgramData/Whitehat Security/dns-backup.json without a protected-directory check in the baseline. ProgramData on this host grants Users Write with ContainerInherit; a user can precreate the directory and own its files. Forged backup DNS addresses can therefore be applied after an approved reset/uninstall. The owner is adding an ACL/reparse guard. Generated PowerShell is not analyzed as C#; this issue is not fully represented by the 91 alerts.
- User-data registry/service remediation records are not authenticated history. Registry rollback validates shape/current value, but baseline targets are not restricted to the watched registry list. User confirmation and UAC are required; a falsified historical alert can nevertheless misdescribe the operation. This must remain a documented trust limitation if not changed; do not treat local JSON as trusted security evidence.
- The legacy Allow-WhitehatSecurity.ps1 weakened Defender and removed MOTW. It was rewritten to require a supplied 64-hex SHA-256 and only compare the selected file, with no launch, security-setting changes, or elevation. Matching, lowercase, mismatch, and invalid-format cases passed against a harmless fixture. Host script execution policy was not changed; tests invoked the reviewed script as an in-memory ScriptBlock. A matching checksum does not establish trust in its source.
- Whitehat's startup-hook and BinaryFormatter runtime flags were missing relative to IPTray; root was notified to disable them. Native runtime profiler/environment instrumentation remains a broader self-elevating .NET limitation; disabling startup hooks alone is not a blanket solution.
- Neither repository contains an automatic binary update/download-and-execute implementation in the inspected source. The release workflow used mutable action version tags and a broad write token; root owns pinning/minimizing that workflow.
- Pattern scanning found no known access-token/private-key signatures in source. Root also reported GitHub secret scanning and Dependabot open-alert lists empty for both repositories. These are bounded observations, not proof of no secrets or vulnerabilities.

## Grouped triage covering every baseline alert

| Alerts | Count | Assessment and rationale |
| --- | ---: | --- |
| #44-84 | 41 | Test-only sinks in SmokeTests. The sources are the runner's GetTempPath (or a system known folder in #78); fixtures use generated paths and explicit test content. Tests are excluded from the product compile. These are not remote or product privilege-boundary injections. Test harnesses should run unelevated in isolated CI. |
| #1-4, #7, #31-37 | 12 | Product utility sinks reached **only from test GetTempPath sources in this SARIF**: AlertHistoryStore (#1-4,#7) and NotifyConfig (#31-37). Normal runtime uses local user data. Do not infer an arbitrary remote file primitive from these specific flows. They do not authenticate the contents of local history/config. |
| #40-43 | 4 | Intentional read-only monitoring of System32/drivers and System32/drivers/etc/hosts, derived from Environment.SpecialFolder.System. No request-supplied path and no write/execute sink. |
| #8-9, #39 | 3 | Intentional File.Exists/read/hash inspection of an alert's file path after normalization, including environment expansion. Runs under the desktop user's token; it is not a network file service and does not elevate to read. UNC/network-path behavior is an operational trust consideration, not established arbitrary privileged-file access in these flows. |
| #38 | 1 | Creation of app-specific fallback data directory under the current user's temp root when normal storage is unavailable. This is an intended local user-data destination in the normal unelevated application. |
| #6, #14-19, #24, #26-27, #89 | 11 | Fixed ProgramFiles/Whitehat Security product destination, version checks, install copy/move/remove, and postinstall launch. Source is Windows' ProgramFiles known folder, with a fixed leaf; no free-form URL/request path enters the command. The protected ProgramFiles installation boundary is required. #89 is not command argument injection. Installer reparse checks are useful defense against a preexisting abnormal install directory. |
| #25, #29-30 | 3 | Known-folder shortcut creation/deletion. Product-generated fixed shortcut basename, not command-line injection. Start menu/Public Desktop are administrator-protected; the current user's Desktop can be redirected and is user-writable. Explicit installer behavior rather than a remote sink; paths must still be treated cautiously while elevated. |
| #5, #12 | 2 | **Real privilege-crossing temp-log issue**, not a blanket false positive. See defect 3 above. |
| #10-11, #13, #20-23 | 7 | Temp script/error filesystem handling. #13/#20-23 are unelevated staging/read/cleanup; #10/#11 run during elevated direct cleanup. The important exploit is subsequent script execution or error-file redirection, covered above. Guid leaf names limit precreation but do not authenticate mutable input. Review fixes to #85/#86 together with these sites. |
| #28, #87 | 2 | **Real mutable elevated self-delete-script issue**; see defect 2. |
| #85-86 | 2 | **Real mutable elevated-script issue**; CodeQL names command injection, but the validated mechanism is script-file substitution rather than breaking base64/quoted command syntax. |
| #88 | 1 | Explorer /select argument comes from normalized existing file path, inside double quotes. Windows file names cannot contain double quotes, and the code checks existence before launch. No cmd/PowerShell interpreter is used. Syntactic injection was not established. Bare explorer.exe lookup is avoidable and should be pinned to the Windows copy. |
| #90 | 1 | Service restore journal data reaches a self-elevated command line. Caller first successfully Base64-decodes and validates payload; fixed verb plus valid Base64 has no shell syntax. No shell interpreter is used. This is not arbitrary command execution; the saved service-state semantics remain user-controlled and must be independently validated (name, protected services, and unchanged ImagePath are checked). |
| #91 | 1 | Regedit executable is either a fixed literal or Windows/SysWOW64/regedit.exe from a system known folder, with fixed -m argument. No free-form command payload. Bare regedit.exe lookup is avoidable and should be pinned to the Windows copy. |

Counts sum to 91. None of these grouped assessments warrants silently dismissing the findings; preserve the scanner history and compare the final commit scan with this evidence.

## Verification recommended before publishing

Run the existing smoke suite, targeted benign tests for script tamper/hash validation, preexisting error-path refusal and trusted backup directory acceptance/rejection, plus normal unelevated startup/UI and build metadata checks. For privileged DNS/firewall/install operations, use an isolated Windows test VM or explicitly authorized system test; source/static tests alone do not prove end-to-end UAC and networking behavior. Review the final diff and rerun CodeQL on the actual release commit. Record any unresolved local-environment or unsigned-binary limitation rather than saying the software is universally secure.

## Independent final-diff review addendum

- IPTray commit f3d5e85db77cdb14e6a1e98b534152ed70e583bd: no concrete P1/P2 regression found in the clipboard/CSV guards or PNG/cache bounds. Valid provider dimensions remain accepted; normal displayed values round-trip; the cache reads through one bounded opened stream.
- Whitehat working diff removes privileged predictable temp logging, pins script bytes by SHA-256 before execution of the same snapshot, uses absolute system executable paths, uses exclusive error-file creation, and keeps self-delete code in immutable command arguments.
- An initial DNS guard rejected every legacy directory inheriting ProgramData Users:Write. The owner revised this after review: legacy directory child creation is permitted only during validation; existing backup file ownership and permissions are independently required to be trusted, then the directory is sealed and rechecked. Untrusted contents are not made trusted merely by changing a directory ACL. Dangling entries are detected by parent enumeration before use, and cleanup validates its DNS state before starting hosts/firewall changes.
- Read-only verification on the actual existing installation: the directory is Administrators-owned and inherits Users:Write with ContainerInherit; its existing backup is Administrators-owned with Users:ReadAndExecute only. The revised directory guard with AllowDirectoryCreate and the strict backup-file guard both passed. No backup content was printed/read and no ACL or DNS changes were performed.
- Read-only module-discovery verification with the hardened Windows PowerShell PSModulePath set exclusively to PSHOME/Modules resolved Get-NetAdapter, Get-NetRoute, Set-DnsClientServerAddress, Get-DnsClientDohServerAddress, Set-NetFirewallProfile, New-NetFirewallRule, Remove-NetFirewallRule, Get-Acl and Set-Acl. This checks availability on the host, not privileged end-to-end network changes.
- No additional concrete P1/P2 regression was found in the reviewed current fixes. This statement does not replace the owner smoke results, final release-commit CI scan, or privileged VM validation.

## Remediation outcome for 7.4.17

The baseline review notes above record the findings before remediation. The final patch addresses all four substantiated defect groups: hash-bound, read-once privileged scripts, inline self-delete commands, removal of elevated per-user temporary logging, and exclusive error report creation. It also secures DNS backup storage, validates protected legacy backups before migration, pins Windows executable/module paths, guards quarantine records and disables managed startup hooks/unsafe serialization. The legacy bypass helper now only verifies an explicit SHA-256.

All 37 Windows smoke tests passed, including harmless tamper, protected-output, ACL, quarantine and junction regressions. Release compilation with warnings as errors passed with zero warnings/errors. An independent final diff review found no remaining blocking regression. The reviewer checked the existing legitimate DNS backup ACLs read-only and confirmed required cmdlets resolve with the restricted module path. No actual DNS, firewall, service or installation changes were performed by these tests.

The final PR records scan results and any individually justified false-positive classifications. Baseline findings are retained for traceability; this document does not claim that 91 exploitable vulnerabilities were found or that all local-environment threats are eliminated. See SECURITY.md for precise behavior changes and remaining limits.
