# Security

Whitehat Security Tool is a local Windows monitoring and remediation tool. Its
security review reduces identified risks; it does not certify the application
or its dependencies as free of vulnerabilities.

## Unicode path correction in 7.4.18

The follow-up review corrected the earlier false-positive assessment of
CodeQL alerts #125 and #127. PowerShell treats several Unicode apostrophes as
string delimiters. Escaping only the ASCII apostrophe did not safely encode
temporary script/error paths: a crafted path could introduce expressions into
the launcher before its intended script digest was checked. A harmless,
unelevated regression reproduced command interpretation with U+2018, U+2019,
U+201A and U+201B.

Version 7.4.18 transports each path as Base64-encoded Unicode data decoded by
a fixed expression. Path characters no longer become PowerShell syntax. The
same handling is used for inline uninstall cleanup. Script integrity checks,
error-file exclusive creation, command exit codes and normal filesystem paths
retain their behavior. This change does not add/remove product features.

The earlier scan's green status reflected alert triage, not proof that every
injection path was absent. The affected alerts were reopened for this fix;
unrelated OS-known-folder and isolated test-fixture findings remain separate.
PowerShell's [documented quoting rules](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules)
include the Unicode delimiter behavior.

## October 2026 hardening

Version 7.4.17 keeps the monitoring engines, dashboard, firewall controls,
DNS providers, quarantine, installer and remediation actions. Changes focus
on boundaries where local files or process lookup could affect privileged
operations:

- Privileged PowerShell verifies a SHA-256 digest bound into its command line
  and executes the same in-memory byte snapshot. Changing the temporary script
  while UAC is pending now fails instead of executing replacement code.
- PowerShell and Windows utility paths are explicit. Privileged scripts load
  modules from the Windows PowerShell system module directory.
- Error reports use exclusive creation and cannot overwrite pre-existing
  files or links. Install/uninstall no longer append elevated diagnostics to
  predictable per-user temporary log files; failures retain dialogs/exit codes.
- Delayed uninstall runs an inline encoded command instead of a mutable
  temporary batch file.
- The application runtime disables managed startup hooks and unsafe
  BinaryFormatter serialization.
- DNS backups require trusted ownership and permissions and reject reparse
  points, including dangling links. New backup storage has an explicit
  Administrators/SYSTEM ACL. Cleanup validates the backup before modifying
  firewall or hosts settings.
- Quarantine rejects junction paths and malformed records and refuses to
  restore a file whose bytes no longer match its recorded digest.

## Existing DNS backups

The older administrator-owned ProgramData directory may allow ordinary users
to create new children while its existing backup file allows only reading.
That layout is migrated only after checking the backup's own ownership and
permissions. Directory rights that permit deleting/replacing children or
changing permissions are rejected. The directory is then secured and the
backup is checked again before its contents are consumed.

A user-owned, user-writable or redirected backup is refused with an error.
The application preserves that data and does not apply its resolver addresses.
An administrator must inspect the backup and verify the intended original DNS
settings before repairing or replacing it; simply changing permissions cannot
establish that previously writable contents are trustworthy.

## Validation and limits

The 7.4.18 changes pass 38 Windows smoke tests, including Unicode paths,
error-report preservation, harmless script
replacement, protected error output, literal uninstall paths, ACL validation,
quarantine tampering, real junction/dangling-junction rejection, existing
monitoring behavior and dashboard layout. Release compilation with warnings
as errors succeeds. The NuGet direct/transitive advisory audit reported no
known vulnerable packages at review time. GitHub CodeQL results require
individual triage; see the repository's security review report and Actions.

Tests do not alter the machine's actual DNS, firewall, installed services or
installation. Privileged apply/uninstall behavior still needs validation in
a disposable administrator test environment. Binaries are not Authenticode
signed; release checksums detect mismatched downloads but do not independently
authenticate a publisher.

Local alert history and remediation journals are not authenticated evidence.
Review a finding before approving a privileged action. Quarantine digest and
path checks are not a native-handle-based, race-proof defense against a process
already controlling the same user's files. Managed startup hooks being disabled
does not disable every native CLR profiler or other inherited-environment
injection mechanism. A compromised administrator or same-user process remains
outside the guarantees of these safeguards.

Report security issues privately through GitHub's repository security reporting
interface when available; do not publish sensitive exploit details in an issue.
