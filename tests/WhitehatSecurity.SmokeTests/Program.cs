// SPDX-License-Identifier: MIT

using WhitehatSecurity.Core;
using WhitehatSecurity.Engines;
using WhitehatSecurity.Native;
using WhitehatSecurity.Ui;
using Microsoft.Win32;
using System.Diagnostics;
using System.Reflection;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var failures = new List<string>();

Run("ConsoleSink remains bounded and clears state", () =>
{
    var sink = new ConsoleSink();
    for (var i = 0; i < 2100; i++)
        sink.WriteLine($"line {i}");
    Equal(2000, sink.Snapshot().Count);
    Equal(100, sink.LinesDropped);
    sink.Clear();
    Equal(0, sink.Snapshot().Count);
    Equal(0, sink.LinesDropped);
});

Run("AlertThrottle validates limits", () =>
{
    Throws(() => new AlertThrottle(TimeSpan.Zero, 1));
    Throws(() => new AlertThrottle(TimeSpan.FromSeconds(1), 0));
});

Run("NotifyConfig strict loader rejects malformed JSON", () =>
{
    var path = Path.Combine(Path.GetTempPath(), $"whs-{Guid.NewGuid():N}.json");
    try
    {
        File.WriteAllText(path, "{not-json");
        Throws(() => NotifyConfig.LoadStrict(path));
        Equal("{not-json", File.ReadAllText(path));
    }
    finally
    {
        File.Delete(path);
    }
});

Run("NotifyConfig strict loader validates DNS provider", () =>
{
    var path = Path.Combine(Path.GetTempPath(), $"whs-{Guid.NewGuid():N}.json");
    try
    {
        File.WriteAllText(path, """{"SchemaVersion":1,"DNS_Provider":"invalid"}""");
        Throws(() => NotifyConfig.LoadStrict(path));
    }
    finally
    {
        File.Delete(path);
    }
});

Run("DNS provider catalog preserves both resolver addresses", () =>
{
    Equal(
        true,
        DnsConfiguration.TryGetProvider(
            "Google", out var google));
    Equal("8.8.8.8", google?.PrimaryIpv4);
    Equal("8.8.4.4", google?.SecondaryIpv4);
    Equal("2001:4860:4860::8888", google?.PrimaryIpv6);
    Equal("2001:4860:4860::8844", google?.SecondaryIpv6);
    Equal(
        "https://dns.google/dns-query",
        google?.DohTemplate);
    Equal(
        false,
        DnsConfiguration.TryGetProvider(
            "NotAProvider", out _));

    // Every provider must carry a complete, parseable set of four
    // resolvers; a missing IPv6 pair would silently configure one family.
    foreach (var name in DnsConfiguration.ProviderNames)
    {
        if (name == "None") continue;
        DnsConfiguration.TryGetProvider(name, out var p);
        foreach (var v4 in p!.Ipv4Addresses)
            Equal(
                System.Net.Sockets.AddressFamily.InterNetwork,
                System.Net.IPAddress.Parse(v4).AddressFamily);
        foreach (var v6 in p.Ipv6Addresses)
            Equal(
                System.Net.Sockets.AddressFamily.InterNetworkV6,
                System.Net.IPAddress.Parse(v6).AddressFamily);
    }
});

Run("DNS scripts target routed adapters and roll back failures", () =>
{
    var apply = DnsConfiguration.BuildProviderScript("Google");
    Contains(
        "Get-NetRoute -AddressFamily IPv4", apply);
    Contains(
        "Restore-WhsDnsSnapshot -Snapshot $beforeApply", apply);
    // Both resolvers of a family always go in together, and whatever was
    // applied is what gets verified — a provider must never end up with
    // only its primary configured.
    Contains("$addresses = @('8.8.8.8','8.8.4.4')", apply);
    Contains("-ServerAddresses $addresses", apply);
    Contains("Assert-WhsDnsAddresses -InterfaceIndex $index", apply);
    DoesNotContain(
        "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object",
        apply);

    var reset = DnsConfiguration.BuildProviderScript("None");
    Contains("-ResetServerAddresses", reset);
    Contains("Assert-WhsDnsAutomatic", reset);

    AssertPowerShellParses(apply);
    AssertPowerShellParses(reset);
});

Run("Secure DNS configures both resolvers without destructive disable", () =>
{
    var enable = DnsConfiguration.BuildDohScript(
        true, "Cloudflare");
    Contains(
        "$addresses = @('1.1.1.1','1.0.0.1')", enable);
    Contains("-AutoUpgrade $true", enable);
    Contains("DoH verification failed", enable);

    var disable = DnsConfiguration.BuildDohScript(
        false, "Cloudflare");
    Contains("-AutoUpgrade $false", disable);
    DoesNotContain(
        "Remove-DnsClientDohServerAddress", disable);

    AssertPowerShellParses(enable);
    AssertPowerShellParses(disable);
});

Run("Secure DNS switches the adapter, not just the server catalogue", () =>
{
    // Add-DnsClientDohServerAddress only records that an IP speaks DoH.
    // Windows decides whether an adapter is encrypted from
    // Dnscache\InterfaceSpecificParameters\<guid>\DohInterfaceSettings, and
    // that is what the Settings app shows. Verifying only the catalogue is
    // why the dashboard said "applied and verified" over plaintext DNS.
    var enable = DnsConfiguration.BuildDohScript(true, "Cloudflare");
    Contains(@"DohInterfaceSettings\Doh", enable);
    Contains("Set-WhsDohInterface -InterfaceIndices $targets", enable);
    Contains("Assert-WhsDohInterface -InterfaceIndex $index", enable);
    Contains("-Name DohFlags -Value 1", enable);
    Contains("-PropertyType QWord", enable);
    Contains("-Name DohTemplate", enable);

    // Turning it off has to clear those keys, or Windows keeps resolving
    // over DoH while the dashboard shows the toggle as off.
    var disable = DnsConfiguration.BuildDohScript(false, "Cloudflare");
    Contains("Remove-WhsDohInterface -InterfaceIndices $targets", disable);
    Contains("Assert-WhsDohInterfaceCleared", disable);

    // Switching provider or going back to automatic must not leave the
    // previous provider's resolvers registered for encryption.
    var provider = DnsConfiguration.BuildProviderScript("Quad9");
    Contains("Remove-WhsDohInterface -InterfaceIndices $targets", provider);
    var reset = DnsConfiguration.BuildProviderScript("None");
    Contains("Remove-WhsDohInterface -InterfaceIndices $targets", reset);
    Contains("Assert-WhsDohInterfaceCleared", reset);

    AssertPowerShellParses(enable);
    AssertPowerShellParses(disable);
    AssertPowerShellParses(provider);
    AssertPowerShellParses(reset);
});

Run("DNS and Secure DNS cover IPv6 where IPv6 actually routes", () =>
{
    var apply = DnsConfiguration.BuildProviderScript("Cloudflare");
    Contains("2606:4700:4700::1111", apply);
    Contains("2606:4700:4700::1001", apply);
    // Applied only on interfaces holding an IPv6 default route. A machine
    // can carry router-advertised global addresses with no IPv6 path out;
    // pointing DNS at unreachable resolvers there stalls every lookup.
    Contains("Get-WhsDnsIpv6Targets", apply);
    Contains("-DestinationPrefix '::/0'", apply);
    Contains("-AddressFamily IPv6", apply);

    var enable = DnsConfiguration.BuildDohScript(true, "Cloudflare");
    Contains("$addresses6 = @('2606:4700:4700::1111','2606:4700:4700::1001')",
        enable);
    // IPv6 DoH lives under Doh6, not Doh.
    Contains(@"'Doh6'", enable);
    Contains("-AddressFamily IPv6", enable);

    // Both families roll back together, and the snapshot has to record the
    // IPv6 family or a failed apply would restore only half the state.
    Contains("AutomaticV6", apply);
    Contains("ServerAddressesV6", apply);

    var reset = DnsConfiguration.BuildProviderScript("None");
    Contains("AutomaticV6", reset);

    // The uninstall sweep needs every managed resolver, both families.
    var managed = DnsConfiguration.ManagedDohAddresses;
    Equal(true, managed.Contains("2606:4700:4700::1111"));
    Equal(true, managed.Contains("2620:fe::9"));
    Equal(true, managed.Contains("2001:4860:4860::8844"));
    Equal(true, managed.Contains("2a10:50c0::ad2:ff"));
    // OpenDNS has no managed DoH template, so neither family is listed.
    Equal(false, managed.Contains("2620:119:35::35"));

    AssertPowerShellParses(apply);
    AssertPowerShellParses(enable);
});

Run("Every engine category has a settings toggle", () =>
{
    // The three behavioural engines raised categories IsCategoryEnabled had
    // never heard of. They fell through to the unknown-category default, so
    // they always fired and no checkbox could silence them.
    var config = NotifyConfig.Defaults();
    foreach (var category in new[]
             {
                 "Firmware", "Driver", "Service", "Connection", "Process",
                 "Listener", "Registry", "Security", "RDP", "Hosts",
                 "HiddenProcess", "Memory", "BYOVD",
             })
    {
        Equal(true, NotifyConfig.AllCategories.Contains(category));
        // A category with a real toggle must follow it in both directions;
        // one that falls through to the default cannot be switched off.
        var probe = NotifyConfig.Defaults();
        SetCategory(probe, category, false);
        Equal(false, probe.IsCategoryEnabled(category));
        SetCategory(probe, category, true);
        Equal(true, probe.IsCategoryEnabled(category));
    }
    Equal(13, NotifyConfig.AllCategories.Count);

    // An engine added later must still raise rather than be muted silently.
    Equal(true, config.IsCategoryEnabled("SomethingAddedLater"));
});

Run("Upgrading a config cannot silently disable a detection", () =>
{
    // A bool absent from JSON deserializes to false. When v7.4.8 gave the
    // behavioural engines real categories, every existing config came back
    // with HiddenProcess, Memory and BYOVD switched off — they had always
    // fired before, and nothing told the user they had stopped.
    var legacy = NotifyConfig.LoadStrictJson(
        """{"SchemaVersion":1,"Firmware":true,"DNS_Provider":"None"}""");
    Equal(true, legacy.IsCategoryEnabled("HiddenProcess"));
    Equal(true, legacy.IsCategoryEnabled("Memory"));
    Equal(true, legacy.IsCategoryEnabled("BYOVD"));
    Equal(NotifyConfig.CurrentSchemaVersion, legacy.SchemaVersion);

    // 7.4.8 and 7.4.9 wrote the wrong value into the file itself, so a
    // schema-1 file that already says false has to be corrected too.
    var damaged = NotifyConfig.LoadStrictJson(
        """{"SchemaVersion":1,"HiddenProcess":false,"Memory":false,"BYOVD":false}""");
    Equal(true, damaged.IsCategoryEnabled("Memory"));

    // Once migrated, an explicit choice is honoured.
    var chosen = NotifyConfig.LoadStrictJson(
        """{"SchemaVersion":2,"HiddenProcess":false}""");
    Equal(false, chosen.IsCategoryEnabled("HiddenProcess"));
    Equal(true, chosen.IsCategoryEnabled("Memory"));

    Throws(() => NotifyConfig.LoadStrictJson(
        """{"SchemaVersion":99}"""));

    // The migrated values must reach disk, or the file keeps claiming the
    // detections are off and the next hand-edit brings the bug back.
    var path = Path.Combine(
        Path.GetTempPath(), $"whs-cfg-{Guid.NewGuid():N}.json");
    try
    {
        File.WriteAllText(
            path,
            """{"SchemaVersion":1,"HiddenProcess":false,"Memory":false,"BYOVD":false}""");
        var loaded = NotifyConfig.LoadOrCreate(path);
        Equal(true, loaded.IsCategoryEnabled("BYOVD"));

        var onDisk = NotifyConfig.LoadStrict(path);
        Equal(NotifyConfig.CurrentSchemaVersion, onDisk.SchemaVersion);
        Equal(true, onDisk.IsCategoryEnabled("HiddenProcess"));
        Equal(true, onDisk.IsCategoryEnabled("Memory"));
        Equal(true, onDisk.IsCategoryEnabled("BYOVD"));
        // Already-current files must not be rewritten on every start.
        Equal(false, onDisk.WasMigrated);
    }
    finally
    {
        try { File.Delete(path); } catch { }
    }
});

Run("Alert history survives a restart", () =>
{
    var path = Path.Combine(
        Path.GetTempPath(), $"whs-history-{Guid.NewGuid():N}.jsonl");
    try
    {
        var store = new AlertHistoryStore(path);
        Equal(0, store.Load().Count);

        var payload = new Dictionary<string, string>
        {
            ["RegistryPath"] = @"HKEY_CURRENT_USER\Software\Example",
            [RegistryRollbackService.PayloadMetadataKey] = "encoded-payload",
        };
        store.Append(new Alert(
            new DateTime(2026, 7, 27, 19, 40, 0),
            "Registry",
            "REGISTRY ADDED",
            "Run key gained a value",
            AlertSeverity.High,
            ProcessName: "explorer",
            ProcessId: 1234,
            RemoteIp: "203.0.113.5",
            RemotePort: 443,
            Path: @"C:\example\thing.exe",
            Extra: payload));

        // A truncated final record after a hard power-off must not cost the
        // user the rest of their history.
        File.AppendAllText(path, "{not-json" + Environment.NewLine);
        store.Append(new Alert(
            new DateTime(2026, 7, 27, 19, 41, 0),
            "Memory", "EXECUTABLE PRIVATE MEMORY", "rwx",
            AlertSeverity.Crit));

        var loaded = new AlertHistoryStore(path).Load();
        Equal(2, loaded.Count);
        Equal("REGISTRY ADDED", loaded[0].Title);
        Equal(AlertSeverity.High, loaded[0].Severity);
        Equal(1234, loaded[0].ProcessId ?? 0);
        Equal("203.0.113.5", loaded[0].RemoteIp);
        Equal(@"C:\example\thing.exe", loaded[0].Path);
        // The remediation payload has to survive, or "Undo registry change"
        // stops working after a restart.
        Equal(
            "encoded-payload",
            loaded[0].Extra?[RegistryRollbackService.PayloadMetadataKey]);
        Equal(AlertSeverity.Crit, loaded[1].Severity);

        // Seeding the sink must not re-fire notifications for old alerts.
        var sink = new DashboardSink();
        var raised = 0;
        sink.AlertReceived += _ => raised++;
        sink.Seed(loaded);
        Equal(2, sink.Count);
        Equal(0, raised);
    }
    finally
    {
        try { File.Delete(path); } catch { }
    }
});

Run("DNS provider names come from a single catalog", () =>
{
    Equal(
        "None,Cloudflare,Quad9,Google,OpenDNS,AdGuard",
        string.Join(",", DnsConfiguration.ProviderNames));

    // A hand-edited config used to validate as "cloudflare" and then fail
    // every apply with -5, because validation was case-insensitive and the
    // provider lookup was ordinal.
    Equal(
        true,
        DnsConfiguration.TryNormalizeProviderName(
            "cloudflare", out var canonical));
    Equal("Cloudflare", canonical);
    Equal(
        true,
        DnsConfiguration.TryNormalizeProviderName(
            "none", out var automatic));
    Equal("None", automatic);
    Equal(
        false,
        DnsConfiguration.TryNormalizeProviderName(
            "NotAProvider", out _));

    var config = NotifyConfig.LoadStrictJson(
        """{"SchemaVersion":1,"DNS_Provider":"cloudflare","DNS_DoH":true}""");
    Equal("Cloudflare", config.DNS_Provider);
    Equal(true, config.DNS_DoH);

    var openDns = NotifyConfig.LoadStrictJson(
        """{"SchemaVersion":1,"DNS_Provider":"OpenDNS","DNS_DoH":true}""");
    Equal(false, openDns.DNS_DoH);

    foreach (var name in DnsConfiguration.ProviderNames)
    {
        if (name == "None") continue;
        // Every listed provider must be applicable, or the settings combo
        // offers an option that cannot be selected.
        _ = DnsConfiguration.BuildProviderScript(name);
    }
    Equal(false, DnsConfiguration.SupportsDoh("None"));
    Equal(false, DnsConfiguration.SupportsDoh("OpenDNS"));
    Equal(true, DnsConfiguration.SupportsDoh("AdGuard"));
});

Run("Uninstall cleanup restores automatic DNS and both DoH resolvers", () =>
{
    var script = ElevationHelper.BuildCleanupScript();
    Equal(true, script.IndexOf("$backup = Get-WhsDnsBackupPath", StringComparison.Ordinal)
        < script.IndexOf("Get-NetFirewallRule", StringComparison.Ordinal));

    // Deciding from ServerAddresses alone pinned the DHCP-supplied
    // resolvers as a static configuration on uninstall.
    Contains("if ([bool]$adapter.Automatic)", script);

    // v7.4.3 started configuring the secondary resolver for DoH but the
    // cleanup list still only named the primaries.
    foreach (var address in new[]
             {
                 "1.1.1.1", "1.0.0.1",
                 "9.9.9.9", "149.112.112.112",
                 "8.8.8.8", "8.8.4.4",
                 "94.140.14.14", "94.140.15.15",
             })
        Contains($"'{address}'", script);

    // OpenDNS has no managed DoH template, so it must not be listed.
    DoesNotContain("208.67.222.222", script);

    // Per-interface encrypted-DNS keys outlive a plain DNS reset, so the
    // uninstaller has to delete them too.
    Contains("DohInterfaceSettings", script);

    AssertPowerShellParses(script);
});

Run("Privileged scripts run under a Restricted execution policy", () =>
{
    // Regression test for the failure that broke every privileged action on
    // a Group-Policy-managed machine: PowerShell will not load a .ps1 when
    // MachinePolicy is Restricted, and that policy outranks the
    // -ExecutionPolicy switch, so the launcher must not use -File.
    var arguments = ElevationHelper.BuildLauncherArguments(
        @"C:\example\script.ps1", @"C:\example\error.txt", new string('0', 64));
    Contains("-EncodedCommand", arguments);
    DoesNotContain("-File", arguments);

    var directory = Path.Combine(
        Path.GetTempPath(), $"whs-elev-test-{Guid.NewGuid():N}");
    Directory.CreateDirectory(directory);
    var scriptPath = Path.Combine(directory, "payload.ps1");
    var markerPath = Path.Combine(directory, "marker.txt");
    var errorPath = Path.Combine(directory, "error.txt");
    try
    {
        // Run the launcher for real, unelevated, against whatever policy
        // this machine has. Under the old -File launcher this exits 1
        // without ever creating the marker on a Restricted machine.
        File.WriteAllText(
            scriptPath,
            "Set-Content -LiteralPath '"
            + markerPath.Replace("'", "''")
            + "' -Value 'ran' -Encoding UTF8\r\n");
        Equal(0, RunLauncher(scriptPath, errorPath));
        Equal("ran", File.ReadAllText(markerPath).Trim());
        Equal(false, File.Exists(errorPath));

        // A failing script must surface its reason through the error file,
        // which is what makes a real failure diagnosable in the log.
        File.WriteAllText(
            scriptPath, "throw 'deliberate smoke-test failure'\r\n");
        Equal(1, RunLauncher(scriptPath, errorPath));
        Equal(true, File.Exists(errorPath));
        Contains(
            "deliberate smoke-test failure",
            File.ReadAllText(errorPath));

        // Exit codes chosen by the script itself must survive; the DoH path
        // reports "cmdlet unavailable" as exit 6.
        File.WriteAllText(scriptPath, "exit 6\r\n");
        Equal(6, RunLauncher(scriptPath, errorPath));
    }
    finally
    {
        try { Directory.Delete(directory, recursive: true); } catch { }
    }
});

Run("Privileged launcher rejects replaced scripts and preserves existing error files", () =>
{
    var directory = Path.Combine(Path.GetTempPath(), $"whs-integrity-{Guid.NewGuid():N}");
    Directory.CreateDirectory(directory);
    var scriptPath = Path.Combine(directory, "payload.ps1");
    var markerPath = Path.Combine(directory, "marker.txt");
    var errorPath = Path.Combine(directory, "error.txt");
    try
    {
        File.WriteAllText(scriptPath, "exit 0");
        var arguments = ElevationHelper.BuildLauncherArguments(
            scriptPath, errorPath, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(scriptPath))));
        // Simulate replacement while UAC is pending, without elevating.
        File.WriteAllText(scriptPath,
            "[System.IO.File]::WriteAllText('" + markerPath.Replace("'", "''") + "', 'unexpected')");
        Equal(1, RunPowerShellArguments(arguments));
        Equal(false, File.Exists(markerPath));
        Contains("changed before execution", File.ReadAllText(errorPath));

        // Elevated error reporting must not overwrite a planted file/link.
        File.WriteAllText(errorPath, "must survive");
        Equal(1, RunPowerShellArguments(arguments));
        Equal("must survive", File.ReadAllText(errorPath));

        // Legitimate non-ASCII scripts retain UTF-8 content.
        File.WriteAllText(scriptPath,
            "[System.IO.File]::WriteAllText('" + markerPath.Replace("'", "''") + "', 'İstanbul güvenlik')");
        Equal(0, RunLauncher(scriptPath, errorPath));
        Equal("İstanbul güvenlik", File.ReadAllText(markerPath));
        Throws(() => ElevationHelper.BuildLauncherArguments(scriptPath, errorPath, "'; exit 0; '"));
        Equal(true, Path.IsPathFullyQualified(ElevationHelper.PowerShellPath));
        Equal(true, File.Exists(ElevationHelper.PowerShellPath));
    }
    finally { Directory.Delete(directory, recursive: true); }
});

Run("Privileged launcher preserves Unicode path characters and error reports", () =>
{
    foreach (var quote in new[] { '\u2018', '\u2019', '\u201a', '\u201b' })
    {
        var directory = Path.Combine(Path.GetTempPath(), $"whs-unicode-{quote}-'$& İstanbul-\U0001f512-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var scriptPath = Path.Combine(directory, "script.ps1");
        var errorPath = Path.Combine(directory, "error.txt");
        try
        {
            File.WriteAllText(scriptPath, "exit 6\r\n");
            Equal(6, RunLauncher(scriptPath, errorPath));
            Equal(false, File.Exists(errorPath));

            File.WriteAllText(scriptPath, "throw 'expected Unicode path failure'\r\n");
            Equal(1, RunLauncher(scriptPath, errorPath));
            Contains("expected Unicode path failure", File.ReadAllText(errorPath));

            File.WriteAllText(errorPath, "existing Unicode path report");
            var arguments = ElevationHelper.BuildLauncherArguments(
                scriptPath, errorPath, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(scriptPath))));
            Equal(1, RunPowerShellArguments(arguments));
            Equal("existing Unicode path report", File.ReadAllText(errorPath));
        }
        finally { Directory.Delete(directory, recursive: true); }
    }
});

Run("Uninstall self-delete stays inline and treats metacharacters as a literal path", () =>
{
    var directory = Path.Combine(Path.GetTempPath(), $"whs-delete-'$&-\u2018\u2019\u201a\u201b İstanbul-\U0001f512-{Guid.NewGuid():N}");
    Directory.CreateDirectory(directory);
    try
    {
        File.WriteAllText(Path.Combine(directory, "inert.txt"), "smoke-test");
        var arguments = Installer.BuildSelfDeleteArguments(directory);
        Equal(0, RunPowerShellArguments(arguments));
        Equal(false, Directory.Exists(directory));
        Throws(() => Installer.BuildSelfDeleteArguments(Path.GetPathRoot(directory)!));
    }
    finally { if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true); }
});

Run("DNS backup guards reject untrusted owners and write permissions", () =>
{
    // Exercise ACL validation in memory; no actual DNS state or system ACL
    // is changed. Reader access remains valid for legacy trusted backups.
    var script = PrivilegedStorage.DnsBackupPowerShell + """
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$admin = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$user = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$acl.SetOwner($admin)
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admin, 'FullControl', 'Allow')))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user, 'ReadAndExecute', 'Allow')))
Assert-WhsBackupAcl -Acl $acl
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user, 'Write', 'Allow')))
$rejected = $false
try { Assert-WhsBackupAcl -Acl $acl } catch { $rejected = $true }
if (-not $rejected) { exit 2 }
# The old administrator-owned ProgramData directory permits child creation
# but cannot replace its separately validated read-only backup file.
Assert-WhsBackupAcl -Acl $acl -AllowDirectoryCreate
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($user, 'DeleteSubdirectoriesAndFiles', 'Allow')))
$rejected = $false
try { Assert-WhsBackupAcl -Acl $acl -AllowDirectoryCreate } catch { $rejected = $true }
if (-not $rejected) { exit 4 }
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($user)
$rejected = $false
try { Assert-WhsBackupAcl -Acl $acl } catch { $rejected = $true }
if (-not $rejected) { exit 3 }
exit 0
""";
    AssertPowerShellParses(script);
    Equal(0, RunPowerShellArguments(ElevationHelper.BuildInlineArguments(script)));
});

Run("Published runtime disables startup hook and BinaryFormatter injection", () =>
{
    var runtimePath = Path.Combine(AppContext.BaseDirectory, "WhitehatSecurity.runtimeconfig.json");
    using var runtime = JsonDocument.Parse(File.ReadAllText(runtimePath));
    var properties = runtime.RootElement.GetProperty("runtimeOptions").GetProperty("configProperties");
    Equal(false, properties.GetProperty("System.StartupHookProvider.IsSupported").GetBoolean());
    Equal(false, properties.GetProperty("System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization").GetBoolean());
});

Run("Per-IP firewall rules are named after the address", () =>
{
    var address = System.Net.IPAddress.Parse("203.0.113.5");
    var block = ElevationHelper.BuildIpRuleScript(address, block: true);

    // "WHS_Block_$ip_In" made PowerShell expand the undefined $ip_In, so
    // both names collapsed to "WHS_Block_": one misnamed inbound rule, no
    // outbound rule, and every later address silently skipped.
    Contains("'WHS_Block_203.0.113.5_In'", block);
    Contains("'WHS_Block_203.0.113.5_Out'", block);
    DoesNotContain("$ip", block);
    Contains("-Direction Inbound", block);
    Contains("-Direction Outbound", block);

    var unblock = ElevationHelper.BuildIpRuleScript(address, block: false);
    Contains("'WHS_Block_203.0.113.5_In'", unblock);
    Contains("'WHS_Block_203.0.113.5_Out'", unblock);
    DoesNotContain("New-NetFirewallRule", unblock);

    AssertPowerShellParses(block);
    AssertPowerShellParses(unblock);

    var v6 = ElevationHelper.BuildIpRuleScript(
        System.Net.IPAddress.Parse("2001:db8::1"), block: true);
    Contains("'WHS_Block_2001:db8::1_In'", v6);
    AssertPowerShellParses(v6);

    // The retired-rule sweep has to clear the stray rule older builds left.
    Equal(
        true,
        ElevationHelper.RetiredFirewallRuleNames.Contains("WHS_Block_"));
    Equal(
        true,
        ElevationHelper.RetiredFirewallRuleNames.Contains(
            "WHS_BlockAllOutbound"));
});

Run("Version metadata agrees across the project", () =>
{
    var root = FindRepositoryRoot();
    if (root is null)
    {
        // Running from a packaged output without the sources next to it.
        return;
    }

    var csproj = File.ReadAllText(
        Path.Combine(root, "WhitehatSecurity.csproj"));
    var manifest = File.ReadAllText(
        Path.Combine(root, "app.manifest"));

    var declared = System.Text.RegularExpressions.Regex.Match(
        csproj, @"<Version>([^<]+)</Version>").Groups[1].Value;
    var manifestVersion = System.Text.RegularExpressions.Regex.Match(
        manifest, @"<assemblyIdentity version=""([^""]+)""").Groups[1].Value;

    Equal(declared, manifestVersion);

    var assemblyVersion =
        typeof(Installer).Assembly.GetName().Version
        ?? throw new InvalidOperationException("No assembly version.");
    Equal(Version.Parse(declared), assemblyVersion);
    Equal(
        assemblyVersion.ToString(3),
        Installer.ProductVersion);
});

Run("Upgrade detection compares major.minor.build", () =>
{
    Equal(true, Installer.IsUpgrade(
        new Version(7, 4, 4, 0), new Version(7, 4, 1, 0)));
    Equal(false, Installer.IsUpgrade(
        new Version(7, 4, 1, 0), new Version(7, 4, 3, 0)));
    Equal(false, Installer.IsUpgrade(
        new Version(7, 4, 4, 0), new Version(7, 4, 4, 0)));
    // The revision field is always 0 in release builds; a difference there
    // must not present itself to the user as an available update.
    Equal(false, Installer.IsUpgrade(
        new Version(7, 4, 4, 9), new Version(7, 4, 4, 0)));
    Equal(true, Installer.IsUpgrade(
        new Version(7, 5, 0, 0), new Version(7, 4, 9, 0)));
});

Run("Catalog-signed Windows executables are trusted", () =>
{
    var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    foreach (var name in new[] { "notepad.exe", "conhost.exe" })
    {
        var path = Path.Combine(system32, name);
        if (File.Exists(path) && !AuthenticodeVerifier.IsTrusted(path))
            throw new InvalidOperationException($"{path} was reported untrusted.");
    }
});

Run("CSV export neutralizes spreadsheet formulas", () =>
{
    Equal("'=cmd|calc", CsvSafety.Escape("=cmd|calc"));
    Equal("\"safe,value\"", CsvSafety.Escape("safe,value"));
});

Run("Threat paths normalize WMI driver formats", () =>
{
    var windows = Environment.GetFolderPath(
        Environment.SpecialFolder.Windows);
    var expected = Path.Combine(
        windows, "System32", "drivers", "example.sys");
    Equal(
        Path.GetFullPath(expected),
        ThreatPath.Normalize(
            @"\SystemRoot\System32\drivers\example.sys"));
    Equal(
        Path.GetFullPath(expected),
        ThreatPath.Normalize(
            "\"\\??\\" + expected + "\" -argument"));
    Equal<string?>(null, ThreatPath.Normalize(
        @"\Device\HarddiskVolume1\example.sys"));
});

Run("File inspection reports SHA-256 and quarantine is reversible", () =>
{
    var directory = Path.Combine(
        Path.GetTempPath(), $"whs-quarantine-test-{Guid.NewGuid():N}");
    var path = Path.Combine(directory, "sample.bin");
    Directory.CreateDirectory(directory);
    try
    {
        File.WriteAllText(path, "whitehat-quarantine-test");
        var inspection = FileInvestigator.Inspect(path);
        Equal(true, inspection.Exists);
        Equal(64, inspection.Sha256?.Length ?? 0);

        var quarantined = QuarantineManager.Quarantine(path);
        Equal(true, quarantined.Success);
        if (quarantined.Record is null)
            throw new InvalidOperationException(
                "Quarantine did not return a record.");
        Equal(false, File.Exists(path));
        Equal(true, File.Exists(
            quarantined.Record.QuarantinePath));

        var restored = QuarantineManager.Restore(
            quarantined.Record);
        Equal(true, restored.Success);
        Equal(true, File.Exists(path));
        Equal("whitehat-quarantine-test", File.ReadAllText(path));

        var quarantinedAgain =
            QuarantineManager.Quarantine(path);
        Equal(true, quarantinedAgain.Success);
        if (quarantinedAgain.Record is null)
            throw new InvalidOperationException(
                "Second quarantine did not return a record.");
        var deleted = QuarantineManager.DeletePermanently(
            quarantinedAgain.Record);
        Equal(true, deleted.Success);
        Equal(false, File.Exists(path));
        Equal(false, File.Exists(
            quarantinedAgain.Record.QuarantinePath));
    }
    finally
    {
        try { File.Delete(path); } catch { }
        try { Directory.Delete(directory); } catch { }
    }
});

Run("Quarantine rejects altered contents and malformed manifests", () =>
{
    var directory = Path.Combine(Path.GetTempPath(), $"whs-quarantine-integrity-{Guid.NewGuid():N}");
    Directory.CreateDirectory(directory);
    var path = Path.Combine(directory, "sample.bin");
    QuarantineRecord? record = null;
    try
    {
        File.WriteAllText(path, "original content");
        var result = QuarantineManager.Quarantine(path);
        Equal(true, result.Success);
        record = result.Record!;
        Equal(false, QuarantineManager.Restore(record with { Id = null! }).Success);
        Equal(false, QuarantineManager.Restore(record with { OriginalPath = "relative.bin" }).Success);
        Equal(false, QuarantineManager.Restore(record with { QuarantinePath = path }).Success);
        Equal(false, QuarantineManager.Restore(record with { Sha256 = null! }).Success);
        File.WriteAllText(record.QuarantinePath, "replacement content");
        Equal(false, QuarantineManager.Restore(record).Success);
        Equal(false, File.Exists(path));
        Equal(true, File.Exists(record.QuarantinePath));
        // The user can still permanently remove a changed quarantined file.
        Equal(true, QuarantineManager.DeletePermanently(record).Success);
    }
    finally
    {
        if (record is not null) QuarantineManager.DeletePermanently(record);
        Directory.Delete(directory, recursive: true);
    }
});

Run("Quarantine does not follow junctions in an ancestor directory", () =>
{
    var directory = Path.Combine(Path.GetTempPath(), $"whs-junction-{Guid.NewGuid():N}");
    var target = Path.Combine(directory, "target");
    var junction = Path.Combine(directory, "link");
    Directory.CreateDirectory(target);
    var path = Path.Combine(target, "sample.bin");
    File.WriteAllText(path, "must remain in place");
    try
    {
        Equal(0, RunPowerShellArguments(ElevationHelper.BuildInlineArguments(
            "New-Item -ItemType Junction -Path '" + junction.Replace("'", "''")
            + "' -Target '" + target.Replace("'", "''") + "' -ErrorAction Stop | Out-Null")));
        var alias = Path.Combine(junction, "sample.bin");
        Equal(true, ThreatPath.ContainsReparsePoint(alias));
        Equal(false, QuarantineManager.Quarantine(alias).Success);
        Equal("must remain in place", File.ReadAllText(path));
        File.Delete(path);
        Directory.Delete(target);
        Equal(0, RunPowerShellArguments(ElevationHelper.BuildInlineArguments(
            PrivilegedStorage.DnsBackupPowerShell
            + "if (-not (Test-WhsPathEntry -Path '" + junction.Replace("'", "''") + "')) { exit 2 }\r\n"
            + "$rejected = $false; try { Assert-WhsBackupPath -Path '" + junction.Replace("'", "''")
            + "' } catch { $rejected = $true }; if (-not $rejected) { exit 3 }")));
    }
    finally
    {
        try { Directory.Delete(junction); } catch (DirectoryNotFoundException) { }
        Directory.Delete(directory, recursive: true);
    }
});

Run("Registry rollback preserves value kind and rejects stale alerts", () =>
{
    var testKeyPath =
        $@"Software\WhitehatSecurity\SmokeTests\{Guid.NewGuid():N}";
    try
    {
        using var key = Registry.CurrentUser.CreateSubKey(
            testKeyPath, writable: true)
            ?? throw new InvalidOperationException(
                "Could not create HKCU test key.");
        key.SetValue("Value", 7, RegistryValueKind.DWord);
        var before = RegistryValueSnapshot.Capture(key, "Value");
        key.SetValue("Value", 9, RegistryValueKind.DWord);
        var after = RegistryValueSnapshot.Capture(key, "Value");
        var payload = new RegistryChangePayload(
            RegistryHive.CurrentUser,
            RegistryView.Registry64,
            testKeyPath,
            "Value",
            "changed",
            before,
            after);

        Equal(0, RegistryRollbackService.ApplyEncoded(
            payload.Encode()));
        Equal(7, Convert.ToInt32(key.GetValue("Value")));
        Equal(
            RegistryValueKind.DWord,
            key.GetValueKind("Value"));

        key.SetValue("Value", 11, RegistryValueKind.DWord);
        Equal(
            RegistryRollbackService.ExitConflict,
            RegistryRollbackService.ApplyEncoded(
                payload.Encode()));
        Equal(11, Convert.ToInt32(key.GetValue("Value")));

        key.SetValue("Added", "detected", RegistryValueKind.String);
        var addedAfter =
            RegistryValueSnapshot.Capture(key, "Added");
        var addedPayload = new RegistryChangePayload(
            RegistryHive.CurrentUser,
            RegistryView.Registry64,
            testKeyPath,
            "Added",
            "added",
            RegistryValueSnapshot.Missing,
            addedAfter);
        Equal(
            0,
            RegistryRollbackService.ApplyEncoded(
                addedPayload.Encode()));
        Equal(
            false,
            key.GetValueNames().Contains(
                "Added", StringComparer.OrdinalIgnoreCase));
    }
    finally
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(
                testKeyPath, throwOnMissingSubKey: false);
        }
        catch { }
    }
});

Run("Registry engine reports a Run-key change after its baseline", () =>
{
    // End-to-end for the engine the way MonitorHost drives it: baseline
    // first, change the registry afterwards, then scan. Both registry views
    // are watched, so a single change is expected to raise twice.
    const string runKey =
        @"Software\Microsoft\Windows\CurrentVersion\Run";
    var valueName = $"WhsSmokeTest_{Guid.NewGuid():N}"[..24];
    var logDir = Path.Combine(
        Path.GetTempPath(), $"whs-reg-{Guid.NewGuid():N}");
    Directory.CreateDirectory(logDir);
    try
    {
        var engine = new RegistryEngine(new Logger(logDir));
        engine.Initialize();
        // Only this test's value is asserted on. Other watched keys belong
        // to the machine and may legitimately change mid-run, which is not
        // this test's business.
        Equal(0, CountFor(engine.Scan(), valueName));

        // CreateSubKey, not OpenSubKey: a fresh Windows profile — a CI
        // runner, for instance — has no HKCU Run key until something writes
        // one, and the engine handles that case too.
        using (var key = Registry.CurrentUser.CreateSubKey(runKey, true)
            ?? throw new InvalidOperationException(
                "Could not open the HKCU Run key."))
        {
            key.SetValue(
                valueName, @"C:\example\persist.exe",
                RegistryValueKind.String);
        }

        var added = engine.Scan().ToList();
        var mine = added
            .Where(a => a.Message.Contains(valueName, StringComparison.Ordinal))
            .ToList();
        Equal(2, mine.Count);
        Equal(true, mine.All(a => a.Category == "Registry"));
        Equal(true, mine.All(a => a.Title == "REGISTRY ADDED"));
        // The payload is what makes the Undo button work.
        Equal(
            true,
            mine.All(a =>
                a.Extra is not null
                && a.Extra.ContainsKey(
                    RegistryRollbackService.PayloadMetadataKey)));

        // A rescan with nothing new must not repeat the finding, or the
        // alert list fills with it every ten seconds.
        Equal(0, CountFor(engine.Scan(), valueName));

        using (var key = Registry.CurrentUser.CreateSubKey(runKey, true)!)
            key.DeleteValue(valueName, false);

        var removed = engine.Scan()
            .Where(a => a.Message.Contains(valueName, StringComparison.Ordinal))
            .ToList();
        Equal(2, removed.Count);
        Equal(true, removed.All(a => a.Title == "REGISTRY REMOVED"));
    }
    finally
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(runKey, true);
            key?.DeleteValue(valueName, false);
        }
        catch { }
        try { Directory.Delete(logDir, recursive: true); } catch { }
    }

    static int CountFor(IEnumerable<Alert> alerts, string name) =>
        alerts.Count(
            a => a.Message.Contains(name, StringComparison.Ordinal));
});

Run("Registry snapshots preserve binary and multi-string data", () =>
{
    var testKeyPath =
        $@"Software\WhitehatSecurity\SmokeTests\{Guid.NewGuid():N}";
    try
    {
        using var key = Registry.CurrentUser.CreateSubKey(
            testKeyPath, writable: true)
            ?? throw new InvalidOperationException(
                "Could not create HKCU test key.");
        var binary = new byte[] { 0, 1, 2, 127, 255 };
        var multi = new[] { "first", "second" };
        key.SetValue("Binary", binary, RegistryValueKind.Binary);
        key.SetValue(
            "Multi", multi, RegistryValueKind.MultiString);
        var binarySnapshot =
            RegistryValueSnapshot.Capture(key, "Binary");
        var multiSnapshot =
            RegistryValueSnapshot.Capture(key, "Multi");
        Equal(
            Convert.ToBase64String(binary),
            binarySnapshot.Data);
        Equal(
            string.Join("|", multi),
            string.Join("|", (string[])multiSnapshot.ToRegistryValue()));
    }
    finally
    {
        try
        {
            Registry.CurrentUser.DeleteSubKeyTree(
                testKeyPath, throwOnMissingSubKey: false);
        }
        catch { }
    }
});

Run("Service remediation payload validation rejects path injection", () =>
{
    Equal(false, ServiceStatePayload.IsValidServiceName(
        @"service\..\other"));
    Equal(true, ServiceStatePayload.IsValidServiceName(
        "Example Service"));
    var encoded = new ServiceStatePayload(
        "Example Service", 3, true,
        @"C:\Program Files\Example\service.exe").Encode();
    Equal(true, ServiceStatePayload.TryDecode(
        encoded, out var decoded));
    Equal(3, decoded?.StartMode ?? -1);
});

Run("Alerts response controls fit the minimum dashboard size", () =>
{
    RunSta(() =>
    {
        var directory = Path.Combine(
            Path.GetTempPath(),
            $"whs-ui-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var filePath = Path.Combine(directory, "finding.bin");
        File.WriteAllText(filePath, "ui-layout-test");
        var logger = new Logger(directory);
        var config = NotifyConfig.Defaults();
        var sink = new DashboardSink();
        var console = new ConsoleSink();
        using var host = new MonitorHost(
            config, logger, TimeSpan.FromMinutes(1));
        using var form = new DashboardForm(
            config, logger, sink, console,
            Path.Combine(directory, "config.json"), host)
        {
            Size = new System.Drawing.Size(960, 600),
            ShowInTaskbar = false,
            Opacity = 0.01,
        };
        try
        {
            InvokePrivate(form, "ShowPage", "Alerts");
            form.Show();
            Application.DoEvents();

            var fileAlert = new Alert(
                DateTime.Now,
                "Memory",
                "TEST FILE FINDING",
                "Synthetic layout-only finding",
                AlertSeverity.High,
                Path: filePath);
            InvokePrivate(form, "ShowAlertDetail", fileAlert);
            Application.DoEvents();

            var detail = GetPrivateField<Panel>(
                form, "_alertDetail");
            var inspect = GetPrivateField<Button>(
                form, "_btnInspectThreat");
            var open = GetPrivateField<Button>(
                form, "_btnOpenLog");
            var remediate = GetPrivateField<Button>(
                form, "_btnRemediate");
            Equal(true, inspect.Visible);
            Equal(true, open.Visible);
            Equal(true, remediate.Visible);
            AssertInside(detail, inspect);
            AssertInside(detail, open);
            AssertInside(detail, remediate);

            var payload = new RegistryChangePayload(
                RegistryHive.CurrentUser,
                RegistryView.Registry64,
                @"Software\WhitehatSecurity\SmokeTests",
                "Value",
                "changed",
                new RegistryValueSnapshot(
                    true, RegistryValueKind.DWord, "0"),
                new RegistryValueSnapshot(
                    true, RegistryValueKind.DWord, "1"));
            var registryAlert = new Alert(
                DateTime.Now,
                "Registry",
                "TEST REGISTRY FINDING",
                "Synthetic layout-only finding",
                AlertSeverity.Med,
                Extra: new Dictionary<string, string>
                {
                    ["RegistryPath"] =
                        @"HKEY_CURRENT_USER\Software\WhitehatSecurity\SmokeTests",
                    [RegistryRollbackService.PayloadMetadataKey] =
                        payload.Encode(),
                });
            InvokePrivate(
                form, "ShowAlertDetail", registryAlert);
            Application.DoEvents();
            var regedit = GetPrivateField<Button>(
                form, "_btnRegedit");
            Equal(true, regedit.Visible);
            Equal("Undo Registry Change", remediate.Text);
            AssertInside(detail, regedit);
            AssertInside(detail, remediate);

            InvokePrivate(form, "ShowPage", "Settings");
            Application.DoEvents();
            var pages =
                GetPrivateField<Dictionary<string, Panel>>(
                    form, "_navPages");
            var dnsApply = GetPrivateField<Button>(
                form, "_dnsApplyButton");
            var dnsStatus = GetPrivateField<Label>(
                form, "_dnsStatusLabel");
            Equal("Apply / Repair", dnsApply.Text);
            AssertFitsWidth(pages["Settings"], dnsApply);
            AssertFitsWidth(pages["Settings"], dnsStatus);

            // Every right-click action must also exist as a button, or the
            // capability is invisible to anyone who never right-clicks.
            InvokePrivate(form, "ShowPage", "Alerts");
            InvokePrivate(form, "ShowAlertDetail", fileAlert);
            Application.DoEvents();
            foreach (var name in new[]
                     {
                         "_btnInspectThreat", "_btnOpenLog", "_btnRegedit",
                         "_btnRemediate", "_btnUndoRemediation",
                         "_btnIpLookup", "_btnBlockIp", "_btnKillProcess",
                         "_btnCopyRow", "_btnCopyMessage",
                     })
            {
                var button = GetPrivateField<Button>(form, name);
                if (button.Parent is null)
                    throw new InvalidOperationException(
                        $"{name} is not on the alert detail panel.");
            }
            Equal(true, GetPrivateField<Button>(form, "_btnCopyRow").Visible);
            Equal(
                true,
                GetPrivateField<Button>(form, "_btnCopyMessage").Visible);

            // Visible is not the same as on screen. A button with no size,
            // or one sitting in a strip that collapsed to zero height, is
            // invisible to the user while every Visible flag reads true.
            var actions = GetPrivateField<FlowLayoutPanel>(
                form, "_alertActions");
            if (actions.Height <= 0 || actions.Width <= 0)
                throw new InvalidOperationException(
                    $"Alert action strip has no size: {actions.Bounds}.");
            AssertInside(detail, actions);

            var shown = actions.Controls.Cast<Control>()
                .Where(c => c.Visible)
                .ToList();
            if (shown.Count == 0)
                throw new InvalidOperationException(
                    "No alert action button is visible.");
            foreach (var button in shown)
            {
                if (button.Width <= 0 || button.Height <= 0)
                    throw new InvalidOperationException(
                        $"{button.Text} has no size: {button.Bounds}.");
                AssertInside(actions, button);
            }

            // Response actions are unconditional now. A default-configured
            // install used to answer every alert with no buttons at all,
            // because the toggle that gated them shipped switched off.
            var fresh = NotifyConfig.Defaults();
            using var freshForm = new DashboardForm(
                fresh, logger, sink, console,
                Path.Combine(directory, "fresh.json"), host)
            {
                Size = new System.Drawing.Size(960, 600),
                ShowInTaskbar = false,
                Opacity = 0.01,
            };
            try
            {
                InvokePrivate(freshForm, "ShowPage", "Alerts");
                freshForm.Show();
                InvokePrivate(freshForm, "ShowAlertDetail", fileAlert);
                Application.DoEvents();
                Equal(
                    true,
                    GetPrivateField<Button>(
                        freshForm, "_btnInspectThreat").Visible);
                Equal(
                    true,
                    GetPrivateField<Button>(
                        freshForm, "_btnOpenLog").Visible);
            }
            finally { freshForm.Close(); }
        }
        finally
        {
            form.Close();
            try { File.Delete(filePath); } catch { }
            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch { }
        }
    });
});

Run("Every page lays out cleanly at every window size", () =>
{
    // Walks every control on every page at four window sizes and fails on
    // anything that leaves its parent, sits on top of a sibling, or clips
    // its own caption. This found the alerts list running ~450px past the
    // bottom of its page, the AI results list more than twice the page
    // width, and the Settings description struck through by three buttons —
    // all invisible to a test that only checked a handful of named controls.
    var problems = new List<string>();
    RunSta(() =>
    {
        var directory = Path.Combine(
            Path.GetTempPath(), $"whs-layout-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        try
        {
            var logger = new Logger(directory);
            var config = NotifyConfig.Defaults();
                var sink = new DashboardSink();
            var console = new ConsoleSink();
            using var host = new MonitorHost(
                config, logger, TimeSpan.FromMinutes(10));

            foreach (var size in new[]
                     {
                         new System.Drawing.Size(0, 0),   // MinimumSize
                         new System.Drawing.Size(960, 600),
                         new System.Drawing.Size(1280, 800),
                         new System.Drawing.Size(1920, 1080),
                     })
            {
                using var form = new DashboardForm(
                    config, logger, sink, console,
                    Path.Combine(directory, "config.json"), host)
                {
                    ShowInTaskbar = false,
                    Opacity = 0.01,
                };
                form.Size = size.IsEmpty ? form.MinimumSize : size;
                form.Show();
                Application.DoEvents();

                var pages = GetPrivateField<Dictionary<string, Panel>>(
                    form, "_navPages");
                foreach (var name in pages.Keys.ToArray())
                {
                    InvokePrivate(form, "ShowPage", name);
                    Application.DoEvents();
                    InspectLayout(
                        problems,
                        $"{form.Width}x{form.Height}/{name}",
                        pages[name]);
                }
                form.Close();
            }
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch { }
        }
    });

    if (problems.Count > 0)
        throw new InvalidOperationException(
            $"{problems.Count} layout problem(s):{Environment.NewLine}"
            + string.Join(Environment.NewLine, problems.Take(15)));
});

Run("BYOVD current scan does not suppress persistent findings", () =>
{
    var engine = new ByovdEngine();
    engine.Initialize();
    var first = engine.Scan().ToList();
    var current = engine.ScanCurrent().ToList();
    if (first.Count > 0 && current.Count == 0)
        throw new InvalidOperationException(
            "Current-state scan suppressed an existing finding.");
});

Run("An unreadable Security log is reported, not hidden", () =>
{
    // Reading the Security log needs elevation or membership of the local
    // "Event Log Readers" group, and the program ships as asInvoker. The
    // engine used to go inert in silence, so the Settings page advertised
    // remote-logon, failed-logon and new-account detection on a normal
    // install where none of it could ever fire.
    var logDir = Path.Combine(
        Path.GetTempPath(), $"whs-sec-{Guid.NewGuid():N}");
    Directory.CreateDirectory(logDir);
    try
    {
        var engine = new SecurityEventEngine(new Logger(logDir));
        engine.Initialize();
        _ = engine.Scan().ToList();

        // Probe independently rather than trusting the production helper.
        // The first version of this test asked the helper whether the log
        // was readable and then asserted the engine agreed with it — both
        // said yes on a machine where the log is not readable at all, and
        // the test passed while the feature was dead.
        bool readable;
        try
        {
            var strict = new System.Diagnostics.Eventing.Reader.EventLogQuery(
                "Security",
                System.Diagnostics.Eventing.Reader.PathType.LogName)
            {
                TolerateQueryErrors = false,
            };
            using var reader =
                new System.Diagnostics.Eventing.Reader.EventLogReader(strict);
            reader.ReadEvent(TimeSpan.FromSeconds(3))?.Dispose();
            readable = true;
        }
        catch { readable = false; }

        Equal(readable, SecurityEventEngine.CanReadSecurityLog());
        Equal(readable, engine.IsAvailable);

        var written = Directory.EnumerateFiles(logDir, "monitor_*.log")
            .SelectMany(File.ReadAllLines)
            .ToList();
        if (readable)
        {
            // Nothing to warn about when the log can be read.
            Equal(
                false,
                written.Any(l => l.Contains(
                    "Security event monitoring is OFF",
                    StringComparison.Ordinal)));
        }
        else
        {
            // The user has to be told, and told how to fix it.
            Equal(
                true,
                written.Any(l => l.Contains(
                    "Security event monitoring is OFF",
                    StringComparison.Ordinal)));
            Equal(
                true,
                written.Any(l => l.Contains(
                    "Event Log Readers", StringComparison.Ordinal)));
        }
    }
    finally
    {
        try { Directory.Delete(logDir, recursive: true); } catch { }
    }
});

Run("RDP and Security event engines scan without throwing", () =>
{
    IMonitorEngine[] engines =
    {
        new RdpEngine(),
        new SecurityEventEngine(),
    };
    foreach (var engine in engines)
    {
        engine.Initialize();
        _ = engine.Scan().ToList();
    }
});

if (failures.Count > 0)
{
    Console.Error.WriteLine($"{failures.Count} smoke test(s) failed:");
    foreach (var failure in failures)
        Console.Error.WriteLine($"  - {failure}");
    return 1;
}

Console.WriteLine("All Whitehat Security smoke tests passed.");
return 0;

void Run(string name, Action test)
{
    try
    {
        test();
        Console.WriteLine($"PASS  {name}");
    }
    catch (Exception ex)
    {
        failures.Add($"{name}: {ex.Message}");
    }
}

static void Equal<T>(T expected, T actual)
{
    if (!EqualityComparer<T>.Default.Equals(expected, actual))
        throw new InvalidOperationException(
            $"Expected '{expected}', got '{actual}'.");
}

static void Throws(Action action)
{
    try
    {
        action();
    }
    catch
    {
        return;
    }
    throw new InvalidOperationException("Expected an exception.");
}

static void Contains(string expected, string actual)
{
    if (!actual.Contains(expected, StringComparison.Ordinal))
        throw new InvalidOperationException(
            $"Expected script to contain '{expected}'.");
}

static void DoesNotContain(string unexpected, string actual)
{
    if (actual.Contains(unexpected, StringComparison.Ordinal))
        throw new InvalidOperationException(
            $"Script unexpectedly contains '{unexpected}'.");
}

static void AssertPowerShellParses(string script)
{
    var path = Path.Combine(
        Path.GetTempPath(),
        $"whs-dns-script-{Guid.NewGuid():N}.ps1");
    try
    {
        File.WriteAllText(path, script);
        var quotedPath = path.Replace("'", "''");
        var command =
            "$path='" + quotedPath + "';" +
            "$tokens=$null;$errors=$null;" +
            "[System.Management.Automation.Language.Parser]::" +
            "ParseFile($path,[ref]$tokens,[ref]$errors)|Out-Null;" +
            "if($errors.Count){$errors|ForEach-Object{" +
            "[Console]::Error.WriteLine($_.Message)};exit 1}";
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = "powershell.exe",
            ArgumentList =
            {
                "-NoProfile",
                "-Command",
                command,
            },
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
        }) ?? throw new InvalidOperationException(
            "Could not start the PowerShell parser.");
        if (!process.WaitForExit(10_000))
        {
            try { process.Kill(); } catch { }
            throw new TimeoutException(
                "PowerShell syntax check timed out.");
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                process.StandardError.ReadToEnd());
    }
    finally
    {
        try { File.Delete(path); } catch { }
    }
}

/// <summary>
/// Runs the production launcher command line unelevated and returns the
/// exit code. Deletes any stale error file first so its presence after the
/// run is meaningful.
/// </summary>
static int RunLauncher(string scriptPath, string errorPath)
{
    try { File.Delete(errorPath); } catch { }
    return RunPowerShellArguments(ElevationHelper.BuildLauncherArguments(
        scriptPath, errorPath, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(scriptPath)))));
}

static int RunPowerShellArguments(string arguments)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = ElevationHelper.PowerShellPath,
        UseShellExecute = false,
        CreateNoWindow = true,
    };
    foreach (var argument in arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        startInfo.ArgumentList.Add(argument);

    using var process = Process.Start(startInfo)
        ?? throw new InvalidOperationException(
            "Could not start the launcher.");
    if (!process.WaitForExit(30_000))
    {
        try { process.Kill(); } catch { }
        throw new TimeoutException("The launcher timed out.");
    }
    return process.ExitCode;
}

/// <summary>
/// Walks up from the test binary to the directory holding
/// WhitehatSecurity.csproj. Returns null when the sources are not present.
/// </summary>
/// <summary>
/// Sets a notification category by its key name, the same way the Settings
/// page does, so the test exercises the real property behind each toggle.
/// </summary>
static void SetCategory(NotifyConfig config, string category, bool value)
{
    var property = typeof(NotifyConfig).GetProperty(category)
        ?? throw new MissingMemberException(
            $"NotifyConfig has no property for category '{category}'.");
    property.SetValue(config, value);
}

static string? FindRepositoryRoot()
{
    var directory = new DirectoryInfo(AppContext.BaseDirectory);
    while (directory is not null)
    {
        if (File.Exists(Path.Combine(
                directory.FullName, "WhitehatSecurity.csproj")))
            return directory.FullName;
        directory = directory.Parent;
    }
    return null;
}

static void RunSta(Action action)
{
    Exception? failure = null;
    var thread = new Thread(() =>
    {
        try { action(); }
        catch (Exception ex) { failure = ex; }
    });
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    if (!thread.Join(TimeSpan.FromSeconds(20)))
        throw new TimeoutException("STA UI test timed out.");
    if (failure is not null)
        throw new InvalidOperationException(
            failure.Message, failure);
}

static void InvokePrivate(
    object instance, string methodName, params object[] args)
{
    var method = instance.GetType().GetMethod(
        methodName,
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingMethodException(methodName);
    try { method.Invoke(instance, args); }
    catch (TargetInvocationException ex)
    {
        throw ex.InnerException ?? ex;
    }
}

static T GetPrivateField<T>(object instance, string fieldName)
    where T : class
{
    var field = instance.GetType().GetField(
        fieldName,
        BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new MissingFieldException(fieldName);
    return field.GetValue(instance) as T
        ?? throw new InvalidOperationException(
            $"Field {fieldName} is not {typeof(T).Name}.");
}

/// <summary>
/// Recursively measures a page and records every control that overflows its
/// parent, overlaps a sibling, clips its caption, or has collapsed to
/// nothing.
/// </summary>
static void InspectLayout(List<string> problems, string context, Control root)
{
    var stack = new Stack<Control>();
    stack.Push(root);
    while (stack.Count > 0)
    {
        var parent = stack.Pop();
        var children = parent.Controls.Cast<Control>()
            .Where(c => c.Visible)
            .ToList();
        var scrolls = parent is ScrollableControl { AutoScroll: true };

        foreach (var child in children)
        {
            var label = $"[{context}] {Name(child)}";

            if (!(child.AutoSize && string.IsNullOrEmpty(child.Text))
                && (child.Width <= 0 || child.Height <= 0))
                problems.Add($"{label} has zero size");

            // A sideways scrollbar on a settings page is a layout fault, so
            // horizontal overflow is never acceptable; vertical overflow is
            // fine only inside a scrolling container.
            if (child.Left < 0 || child.Right > parent.ClientSize.Width)
                problems.Add(
                    $"{label} overflows horizontally: {child.Bounds} in {parent.ClientSize}");
            if (!scrolls
                && (child.Top < 0 || child.Bottom > parent.ClientSize.Height))
                problems.Add(
                    $"{label} overflows vertically: {child.Bounds} in {parent.ClientSize}");

            if (!child.AutoSize && !string.IsNullOrEmpty(child.Text))
            {
                // A Label wraps, so what matters is whether the wrapped text
                // fits the box; a Button or CheckBox renders on one line, so
                // the caption width is what matters.
                if (child is Label { AutoEllipsis: false } wrapping)
                {
                    var needed = TextRenderer.MeasureText(
                        wrapping.Text, wrapping.Font,
                        new System.Drawing.Size(wrapping.Width, int.MaxValue),
                        TextFormatFlags.WordBreak);
                    if (needed.Height > wrapping.Height)
                        problems.Add(
                            $"{label} clips its text: wraps to {needed.Height}px, has {wrapping.Height}px");
                }
                else if (child is Button or CheckBox)
                {
                    var needed = TextRenderer.MeasureText(
                        child.Text, child.Font);
                    var chrome = child is CheckBox ? 20 : 8;
                    if (needed.Width + chrome > child.Width)
                        problems.Add(
                            $"{label} clips its caption: needs {needed.Width + chrome}px, has {child.Width}px");
                }
            }

            stack.Push(child);
        }

        for (var i = 0; i < children.Count; i++)
        for (var j = i + 1; j < children.Count; j++)
        {
            if (children[i].Dock != DockStyle.None
                || children[j].Dock != DockStyle.None)
                continue;
            var overlap = System.Drawing.Rectangle.Intersect(
                children[i].Bounds, children[j].Bounds);
            if (overlap.Width > 1 && overlap.Height > 1)
                problems.Add(
                    $"[{context}] {Name(children[i])} overlaps {Name(children[j])} by {overlap.Width}x{overlap.Height}");
        }
    }

    static string Name(Control c)
    {
        var id = string.IsNullOrEmpty(c.Name) ? c.GetType().Name : c.Name;
        if (string.IsNullOrEmpty(c.Text)) return id;
        var text = c.Text.Replace("\n", " ");
        if (text.Length > 32) text = text[..32] + "…";
        return $"{id} \"{text}\"";
    }
}

static void AssertInside(Control parent, Control child)
{
    if (child.Left < 0
        || child.Top < 0
        || child.Right > parent.ClientSize.Width
        || child.Bottom > parent.ClientSize.Height)
        throw new InvalidOperationException(
            $"{child.Name}/{child.Text} is outside its parent: " +
            $"child={child.Bounds}, parent={parent.ClientSize}.");
}

static void AssertFitsWidth(Control parent, Control child)
{
    if (child.Left < 0 || child.Right > parent.ClientSize.Width)
        throw new InvalidOperationException(
            $"{child.Name}/{child.Text} exceeds its parent width: " +
            $"child={child.Bounds}, parent={parent.ClientSize}.");
}
