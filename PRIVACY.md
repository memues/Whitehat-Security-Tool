# Whitehat Security Tool privacy policy

Last updated: 2 October 2026

Whitehat Security Tool is a local Windows security monitoring utility maintained in the
memues/Whitehat-Security-Tool GitHub project. It does not require an account and
does not automatically send telemetry, crash reports, scan results, files, or
logs to the project maintainer. It has no advertising or analytics service.

## Information processed on your device

To provide monitoring, alerts, and actions you request, the application reads
information about running processes and their executable paths, digital
signatures, memory regions, network addresses and ports, listening ports, drivers,
services, startup registry entries, the hosts file, and Windows security settings
and events. File integrity checks calculate hashes. This information can contain
your computer name, account names in file paths or events, remote IP addresses,
and other identifying information.

Configuration, integrity baselines, alert history, logs, remediation records, and
quarantined files are stored locally. Logs include timestamps and the computer
name. Alert history may include process names and IDs, file paths, network
addresses, registry values, and information needed to undo a change. Quarantine
moves a file into local storage and records its original path, hash, and time so
it can be restored; the file's contents remain on your device.

For a Microsoft Store/MSIX copy, the first interactive launch asks you to
confirm or choose a local data folder outside package storage. The suggested
location is %USERPROFILE%\Whitehat Security Tool Data. Configuration, logs,
quarantine and recovery records remain there after package reset or removal.
Only the folder pointer is kept in the package's LocalState directory. After
reset or reinstallation, select the same data folder to reopen existing records.
The app refuses to use an unavailable folder or silently fall back to temporary
storage. Choose a private folder that is not shared or synced to a cloud service.

For a standalone EXE installed copy, the usual data folder is
%LOCALAPPDATA%\Whitehat Security. Portable EXE copies use their executable directory
when writable, otherwise the local application data folder, with
%TEMP%\WhitehatSecurity as a final fallback. A DNS configuration backup is stored
under %PROGRAMDATA%\Whitehat Security with administrator access restrictions.
The privacy dialog displays the data directory used by the running copy.

These local files are not encrypted by the application. Access depends on your
Windows account, file permissions, disk encryption, and device security. Other
people or programs with sufficient access to your device can read them.

## Network use and external services

Monitoring and behavioural scans run locally. The application's Authenticode
checks request cache-only certificate verification. Windows and Microsoft Store
services can use the network independently under their own settings and privacy
policies.

IP Lookup is optional. Each lookup asks for confirmation before opening an
HTTPS page on ipinfo.io in your default browser. Continuing shares the displayed
IP address in the page URL with IPinfo. IPinfo also receives the public IP address
of your browser's connection and normal browser request information; your
browser or IPinfo may use cookies or keep history. Declining does not make the
request. Whitehat Security Tool does not send the rest of the alert or a log file.
IPinfo's handling of the request is governed by https://ipinfo.io/privacy-policy.
Consent applies to that lookup only; decline future prompts to stop future
lookups. A completed request cannot be withdrawn by this application.

If you apply a DNS provider in Settings, Windows sends subsequent DNS queries
for the affected network adapters to that provider until you change the setting.
That provider can receive queried domain names and the connection's public IP
address. Provider options include Cloudflare, Quad9, Google, OpenDNS, and AdGuard;
each provider controls its own service and privacy practices. Review the selected
provider's policy before applying it. DNS encryption availability depends on
Windows, the provider, and your configuration. Choosing None requests restoration
of the application's saved DNS configuration, or automatic DNS when no backup
is available. You can also change DNS through Windows network settings.

The application does not automatically upload exports. If you export alerts,
settings, or console output, you choose the destination. If you then share those
files, the recipient receives their contents under the service you choose.

## Controls, retention, and removal

You can change notification preferences, review local logs and alerts, clear
the displayed alert list, and exit the tray application to stop monitoring.
Clearing the displayed list does not erase saved history or daily logs; saved
history can be removed by deleting alert-history.jsonl after exiting the app. Ordinary
log files older than 30 days are removed on startup where permitted. Alert
history is trimmed to the most recent 2,000 records when loaded; it can grow
between launches. Other local data remains until you remove it or an application
operation replaces it.

Uninstall retains user data, including logs, history, baselines, remediation
records, and quarantine, so a removal does not destroy the only recoverable copy
of a quarantined file. Review or restore quarantined files before deleting the
data folder. After exiting the application, you can remove unwanted local data
manually. Deleting quarantine permanently removes its recoverable contents;
deleting remediation records can remove information needed to undo changes.
An administrator may need to review any remaining DNS backup before removing it.
Uninstall does not erase exports you saved elsewhere.

Removing the MSIX package does not automatically reverse security or network
changes you explicitly applied, such as firewall rules, hosts entries, DNS or
service settings. Review and undo supported changes in the app before removal,
or reinstall it and reopen the retained data folder to use its recovery records.
System changes may also be managed through the corresponding Windows settings.

## Questions and policy updates

The current policy is available with the project at
https://github.com/memues/Whitehat-Security-Tool/blob/master/PRIVACY.md and offline
from the application's Privacy Policy menu. Questions can be raised at
https://github.com/memues/Whitehat-Security-Tool/issues. GitHub issues are public:
do not include private logs, IP addresses, or files without first removing
sensitive information. Updates to application data practices will be reflected
in this policy and its date.
