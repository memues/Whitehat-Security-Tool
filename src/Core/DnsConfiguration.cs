// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.Linq;

namespace WhitehatSecurity.Core;

/// <summary>
/// A DNS provider offered by the dashboard. All four resolver addresses are
/// kept together so provider switching and DNS-over-HTTPS cannot accidentally
/// configure only the primary resolver, or only one address family.
/// </summary>
public sealed record DnsProviderDefinition(
    string Name,
    string PrimaryIpv4,
    string SecondaryIpv4,
    string PrimaryIpv6,
    string SecondaryIpv6,
    string? DohTemplate)
{
    public string[] Ipv4Addresses => new[] { PrimaryIpv4, SecondaryIpv4 };
    public string[] Ipv6Addresses => new[] { PrimaryIpv6, SecondaryIpv6 };
}

/// <summary>
/// Builds the privileged PowerShell used for DNS changes. Keeping the script
/// generation separate makes the safety properties testable without changing
/// the machine's network configuration.
/// </summary>
public static class DnsConfiguration
{
    /// <summary>
    /// The name the dashboard shows for "leave DNS to DHCP". Kept here so the
    /// settings combo, the config validator and the script builder cannot
    /// disagree about the spelling.
    /// </summary>
    public const string AutomaticProviderName = "None";

    /// <summary>
    /// Declaration order is the order the settings combo lists the providers.
    /// Every other list of provider names in the program is derived from this
    /// one; earlier versions duplicated it in the designer, the config
    /// validator and two DoH capability checks, and the copies drifted.
    /// </summary>
    private static readonly DnsProviderDefinition[] ProviderList =
    {
        new("Cloudflare", "1.1.1.1", "1.0.0.1",
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            "https://cloudflare-dns.com/dns-query"),
        new("Quad9", "9.9.9.9", "149.112.112.112",
            "2620:fe::fe", "2620:fe::9",
            "https://dns.quad9.net/dns-query"),
        new("Google", "8.8.8.8", "8.8.4.4",
            "2001:4860:4860::8888", "2001:4860:4860::8844",
            "https://dns.google/dns-query"),
        new("OpenDNS", "208.67.222.222", "208.67.220.220",
            "2620:119:35::35", "2620:119:53::53", null),
        new("AdGuard", "94.140.14.14", "94.140.15.15",
            "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
            "https://dns.adguard.com/dns-query"),
    };

    // Case-insensitive on purpose: NotifyConfig accepted "cloudflare" from a
    // hand-edited JSON file while this lookup was ordinal, so the setting
    // validated at load time and then failed with -5 on every apply.
    private static readonly IReadOnlyDictionary<string, DnsProviderDefinition>
        Providers = ProviderList.ToDictionary(
            p => p.Name, StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Every selectable provider name, "None" first, in display order.
    /// </summary>
    public static IReadOnlyList<string> ProviderNames { get; } =
        new[] { AutomaticProviderName }
            .Concat(ProviderList.Select(p => p.Name))
            .ToArray();

    /// <summary>
    /// Both resolver addresses of every provider that this program can
    /// configure for DNS-over-HTTPS. The uninstaller uses this to remove the
    /// DoH registrations it created; hard-coding only the primaries left the
    /// secondary entries behind once v7.4.3 started configuring both.
    /// </summary>
    public static IReadOnlyList<string> ManagedDohAddresses { get; } =
        ProviderList
            .Where(p => p.DohTemplate is not null)
            .SelectMany(p => p.Ipv4Addresses.Concat(p.Ipv6Addresses))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static bool TryGetProvider(
        string? providerName,
        out DnsProviderDefinition? provider)
    {
        if (providerName is null)
        {
            provider = null;
            return false;
        }
        return Providers.TryGetValue(providerName, out provider);
    }

    /// <summary>
    /// Resolves user- or file-supplied text to the canonical provider name,
    /// so a config written as "cloudflare" behaves exactly like "Cloudflare".
    /// </summary>
    public static bool TryNormalizeProviderName(
        string? providerName,
        out string canonical)
    {
        if (string.Equals(
                providerName,
                AutomaticProviderName,
                StringComparison.OrdinalIgnoreCase))
        {
            canonical = AutomaticProviderName;
            return true;
        }
        if (TryGetProvider(providerName, out var provider)
            && provider is not null)
        {
            canonical = provider.Name;
            return true;
        }
        canonical = AutomaticProviderName;
        return false;
    }

    /// <summary>
    /// True when the provider has a DoH template this program knows how to
    /// register. "None" and OpenDNS do not.
    /// </summary>
    public static bool SupportsDoh(string? providerName) =>
        TryGetProvider(providerName, out var provider)
        && provider?.DohTemplate is not null;

    /// <summary>
    /// True when one of the provider's IPv6 resolvers is actually configured
    /// on a live interface. The apply script deliberately skips IPv6 on
    /// machines with no IPv6 default route, so the dashboard uses this to say
    /// so instead of leaving the user wondering why only IPv4 changed.
    /// </summary>
    public static bool IsProviderIpv6Active(DnsProviderDefinition provider)
    {
        ArgumentNullException.ThrowIfNull(provider);
        try
        {
            foreach (var nic in System.Net.NetworkInformation
                         .NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus
                    != System.Net.NetworkInformation.OperationalStatus.Up)
                    continue;
                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    if (dns.AddressFamily
                        != System.Net.Sockets.AddressFamily.InterNetworkV6)
                        continue;
                    foreach (var candidate in provider.Ipv6Addresses)
                        if (System.Net.IPAddress.TryParse(
                                candidate, out var parsed)
                            && parsed.Equals(dns))
                            return true;
                }
            }
        }
        catch { /* reporting only — never fail an apply over this */ }
        return false;
    }

    public static string BuildProviderScript(string providerName)
    {
        if (string.Equals(
                providerName,
                AutomaticProviderName,
                StringComparison.OrdinalIgnoreCase))
            return PrivilegedStorage.DnsBackupPowerShell + CommonPowerShell + ResetPowerShell;
        if (!TryGetProvider(providerName, out var provider)
            || provider is null)
            throw new ArgumentOutOfRangeException(
                nameof(providerName), providerName,
                "Unknown DNS provider.");

        return PrivilegedStorage.DnsBackupPowerShell + CommonPowerShell
            + ApplyProviderPowerShell
                .Replace("__PRIMARY6__", provider.PrimaryIpv6)
                .Replace("__SECONDARY6__", provider.SecondaryIpv6)
                .Replace("__PRIMARY__", provider.PrimaryIpv4)
                .Replace("__SECONDARY__", provider.SecondaryIpv4);
    }

    public static string BuildDohScript(
        bool enabled,
        string providerName)
    {
#if STORE_BUILD
        throw new NotSupportedException("Configure encrypted DNS in Windows Settings.");
#else
        if (!TryGetProvider(providerName, out var provider)
            || provider?.DohTemplate is null)
            throw new ArgumentOutOfRangeException(
                nameof(providerName), providerName,
                "The DNS provider does not support managed DoH.");

        var template = enabled
            ? EnableDohPowerShell
            : DisableDohPowerShell;
        return CommonPowerShell
            + template
                .Replace("__PRIMARY6__", provider.PrimaryIpv6)
                .Replace("__SECONDARY6__", provider.SecondaryIpv6)
                .Replace("__PRIMARY__", provider.PrimaryIpv4)
                .Replace("__SECONDARY__", provider.SecondaryIpv4)
                .Replace("__DOH_TEMPLATE__", provider.DohTemplate);
#endif
    }

    // Prefer interfaces that actually own a live default IPv4 route. This
    // avoids Hyper-V Default Switch and other "Up" virtual adapters that
    // reject Set-DnsClientServerAddress. The physical-adapter fallback keeps
    // the feature useful while a default route is briefly being renewed.
    internal const string CommonPowerShell = DnsCommonPowerShell
#if !STORE_BUILD
        + DohInterfacePowerShell
#endif
        + DnsVerificationPowerShell;

    private const string DnsCommonPowerShell = """

function Get-WhsDnsTargetIndices {
    $upAdapters = @(Get-NetAdapter -ErrorAction Stop |
        Where-Object { $_.Status -eq 'Up' })
    $upIndices = @($upAdapters |
        Select-Object -ExpandProperty ifIndex -Unique)
    $indices = @(Get-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Where-Object { $upIndices -contains [int]$_.InterfaceIndex } |
        Sort-Object RouteMetric |
        Select-Object -ExpandProperty InterfaceIndex -Unique)
    if ($indices.Count -eq 0) {
        $indices = @($upAdapters |
            Where-Object {
                $_.HardwareInterface -and -not $_.Virtual
            } |
            Select-Object -ExpandProperty ifIndex -Unique)
    }
    if ($indices.Count -eq 0) {
        throw 'No active IPv4 internet interface was found.'
    }
    return @($indices)
}

# Interfaces that carry a live IPv6 default route. A machine can hold
# router-advertised global IPv6 addresses and still have no IPv6 path to the
# internet; pointing DNS at public IPv6 resolvers there makes every lookup
# wait out a timeout before falling back to IPv4. So IPv6 resolvers are only
# configured where IPv6 actually routes.
function Get-WhsDnsIpv6Targets {
    param([int[]] $InterfaceIndices)
    $routed = @(Get-NetRoute -AddressFamily IPv6 `
            -DestinationPrefix '::/0' -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty InterfaceIndex -Unique)
    return @($InterfaceIndices |
        Where-Object { $routed -contains [int]$_ })
}

function Test-WhsDnsFamilyAutomatic {
    param([string] $InterfaceGuid, [string] $Family)
    $service = if ($Family -eq 'IPv6') { 'Tcpip6' } else { 'Tcpip' }
    $registryPath = 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\' + $service + '\Parameters\Interfaces\' + $InterfaceGuid
    $configured = ''
    try {
        $configured = [string](Get-ItemPropertyValue `
            -LiteralPath $registryPath -Name NameServer `
            -ErrorAction Stop)
    } catch {
        $configured = ''
    }
    return [string]::IsNullOrWhiteSpace($configured)
}

function Get-WhsDnsSnapshot {
    param([int[]] $InterfaceIndices)
    foreach ($index in $InterfaceIndices) {
        $adapter = Get-NetAdapter -InterfaceIndex $index `
            -ErrorAction Stop
        $dns4 = Get-DnsClientServerAddress `
            -InterfaceIndex $index -AddressFamily IPv4 `
            -ErrorAction Stop
        $dns6 = Get-DnsClientServerAddress `
            -InterfaceIndex $index -AddressFamily IPv6 `
            -ErrorAction SilentlyContinue
        [pscustomobject]@{
            InterfaceIndex = [int]$index
            InterfaceAlias = [string]$adapter.Name
            Automatic = Test-WhsDnsFamilyAutomatic `
                -InterfaceGuid $adapter.InterfaceGuid -Family 'IPv4'
            ServerAddresses = @($dns4.ServerAddresses)
            AutomaticV6 = Test-WhsDnsFamilyAutomatic `
                -InterfaceGuid $adapter.InterfaceGuid -Family 'IPv6'
            ServerAddressesV6 = @(
                if ($null -ne $dns6) { $dns6.ServerAddresses } else { @() })
        }
    }
}

function Restore-WhsDnsSnapshot {
    param([object[]] $Snapshot)
    foreach ($item in @($Snapshot)) {
        $adapter = Get-NetAdapter `
            -InterfaceIndex ([int]$item.InterfaceIndex) `
            -ErrorAction SilentlyContinue
        if ($null -eq $adapter) { continue }

        # Set-DnsClientServerAddress has no -AddressFamily switch, so
        # -ResetServerAddresses always clears BOTH families. Reset first,
        # then re-apply whichever families were statically configured.
        Set-DnsClientServerAddress `
            -InterfaceIndex ([int]$item.InterfaceIndex) `
            -ResetServerAddresses -ErrorAction Stop

        $restore = @()
        if (-not [bool]$item.Automatic) {
            $addresses = @($item.ServerAddresses)
            if ($addresses.Count -eq 0) {
                throw "Saved DNS configuration for interface $($item.InterfaceIndex) is empty."
            }
            $restore += $addresses
        }
        # AutomaticV6 is absent in backups written before v7.4.7; treating a
        # missing value as "automatic" keeps those files usable.
        if ($null -ne $item.PSObject.Properties['AutomaticV6'] -and
            -not [bool]$item.AutomaticV6) {
            $restore += @($item.ServerAddressesV6)
        }
        if ($restore.Count -gt 0) {
            Set-DnsClientServerAddress `
                -InterfaceIndex ([int]$item.InterfaceIndex) `
                -ServerAddresses $restore -ErrorAction Stop
        }
    }
}

function Assert-WhsDnsAddresses {
    param(
        [int] $InterfaceIndex,
        [string[]] $Expected,
        [string] $AddressFamily = 'IPv4')
    $actual = @((Get-DnsClientServerAddress `
        -InterfaceIndex $InterfaceIndex -AddressFamily $AddressFamily `
        -ErrorAction Stop).ServerAddresses)
    if ($actual.Count -ne $Expected.Count) {
        throw "DNS verification failed on interface $InterfaceIndex."
    }
    for ($i = 0; $i -lt $Expected.Count; $i++) {
        if ($actual[$i] -ne $Expected[$i]) {
            throw "DNS verification failed on interface $InterfaceIndex."
        }
    }
}

""";

    private const string DohInterfacePowerShell = """

# Per-interface DNS-over-HTTPS. Add-DnsClientDohServerAddress only fills the
# machine-wide catalogue of "servers known to speak DoH"; it does NOT switch
# an adapter to encrypted DNS. Windows decides that from
# Dnscache\InterfaceSpecificParameters\<guid>\DohInterfaceSettings\Doh\<ip>,
# which is also what the Settings app reads. Without these keys the dashboard
# reported "applied and verified" while Windows showed the adapter as
# unencrypted and kept resolving over plaintext UDP 53.
#
# DohFlags is a QWORD: 1 = use DoH, fall back to unencrypted if the resolver
# is unreachable. Microsoft does not document the values; 1 is the setting
# Windows itself writes for an automatic template and the only one verified
# here end to end. Fallback stays enabled on purpose — an unreachable DoH
# endpoint must not take name resolution down with it.
# IPv4 entries live under ...\DohInterfaceSettings\Doh, IPv6 under \Doh6.
function Get-WhsDohInterfacePath {
    param([int] $InterfaceIndex, [string] $AddressFamily = 'IPv4')
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex `
        -ErrorAction Stop
    $leaf = if ($AddressFamily -eq 'IPv6') { 'Doh6' } else { 'Doh' }
    return 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters\' + $adapter.InterfaceGuid + '\DohInterfaceSettings\' + $leaf
}

function Set-WhsDohInterface {
    param(
        [int[]] $InterfaceIndices,
        [string[]] $Addresses,
        [string] $Template,
        [string] $AddressFamily = 'IPv4')
    foreach ($index in $InterfaceIndices) {
        $path = Get-WhsDohInterfacePath -InterfaceIndex $index `
            -AddressFamily $AddressFamily
        New-Item -Path $path -Force -ErrorAction Stop | Out-Null
        # Entries for resolvers we are no longer configuring have to go, or
        # switching provider leaves the previous provider's addresses behind
        # and Windows keeps offering them.
        Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue |
            Where-Object { $Addresses -notcontains $_.PSChildName } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($address in $Addresses) {
            $entry = Join-Path $path $address
            New-Item -Path $entry -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $entry -Name DohFlags -Value 1 `
                -PropertyType QWord -Force -ErrorAction Stop | Out-Null
            New-ItemProperty -Path $entry -Name DohTemplate `
                -Value $Template -PropertyType String -Force `
                -ErrorAction Stop | Out-Null
        }
    }
}

# Clears both families. Leaving Doh6 behind after switching to an IPv4-only
# state would keep Windows offering the old provider's IPv6 resolvers.
function Remove-WhsDohInterface {
    param([int[]] $InterfaceIndices)
    foreach ($index in $InterfaceIndices) {
        foreach ($family in @('IPv4', 'IPv6')) {
            $path = Get-WhsDohInterfacePath -InterfaceIndex $index `
                -AddressFamily $family
            if (Test-Path -LiteralPath $path) {
                Get-ChildItem -LiteralPath $path `
                        -ErrorAction SilentlyContinue |
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Assert-WhsDohInterface {
    param(
        [int] $InterfaceIndex,
        [string[]] $Expected,
        [string] $Template,
        [string] $AddressFamily = 'IPv4')
    $path = Get-WhsDohInterfacePath -InterfaceIndex $InterfaceIndex `
        -AddressFamily $AddressFamily
    $names = @(Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty PSChildName)
    foreach ($address in $Expected) {
        if ($names -notcontains $address) {
            throw "Encrypted DNS was not enabled for $address on interface $InterfaceIndex."
        }
        $entry = Join-Path $path $address
        if ([int64](Get-ItemPropertyValue -LiteralPath $entry `
                -Name DohFlags -ErrorAction Stop) -ne 1) {
            throw "Encrypted DNS flag is wrong for $address on interface $InterfaceIndex."
        }
        if ([string](Get-ItemPropertyValue -LiteralPath $entry `
                -Name DohTemplate -ErrorAction Stop) -ne $Template) {
            throw "Encrypted DNS template is wrong for $address on interface $InterfaceIndex."
        }
    }
    foreach ($name in $names) {
        if ($Expected -notcontains $name) {
            throw "A stale encrypted-DNS entry for $name remains on interface $InterfaceIndex."
        }
    }
}

function Assert-WhsDohInterfaceCleared {
    param([int] $InterfaceIndex)
    foreach ($family in @('IPv4', 'IPv6')) {
        $path = Get-WhsDohInterfacePath -InterfaceIndex $InterfaceIndex `
            -AddressFamily $family
        $names = @(Get-ChildItem -LiteralPath $path `
                -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty PSChildName)
        if ($names.Count -gt 0) {
            throw "Encrypted DNS is still configured on interface $InterfaceIndex."
        }
    }
}

""";

    private const string DnsVerificationPowerShell = """

function Assert-WhsDnsAutomatic {
    param([int] $InterfaceIndex, [string[]] $Families = @('IPv4','IPv6'))
    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex `
        -ErrorAction Stop
    foreach ($family in $Families) {
        if (-not (Test-WhsDnsFamilyAutomatic `
                -InterfaceGuid $adapter.InterfaceGuid -Family $family)) {
            throw "Automatic DNS verification failed on interface $InterfaceIndex ($family)."
        }
    }
}

""";

    private const string ClearDohInterfacePowerShell =
#if STORE_BUILD
        "";
#else
        "Remove-WhsDohInterface -InterfaceIndices $targets\n";
#endif

    private const string VerifyDohClearedPowerShell =
#if STORE_BUILD
        "";
#else
        "foreach ($index in $targets) { Assert-WhsDohInterfaceCleared -InterfaceIndex $index }\n";
#endif

    private const string ApplyProviderPowerShell = """
$targets = @(Get-WhsDnsTargetIndices)
$beforeApply = @(Get-WhsDnsSnapshot -InterfaceIndices $targets)
$backup = Get-WhsDnsBackupPath -Create
$createdBackup = $false
try {
    if (-not (Test-Path -LiteralPath $backup)) {
        @($beforeApply) | ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $backup -Encoding UTF8 `
                -ErrorAction Stop
        $createdBackup = $true
        # Token default ownership can be the individual admin account.
        # Keep ownership at the administrator boundary as well as the ACL.
        $backupAcl = Get-Acl -LiteralPath $backup -ErrorAction Stop
        $backupAcl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')))
        Set-Acl -LiteralPath $backup -AclObject $backupAcl -ErrorAction Stop
        Assert-WhsBackupPath -Path $backup
    }
    $v6Targets = @(Get-WhsDnsIpv6Targets -InterfaceIndices $targets)
    foreach ($index in $targets) {
        $addresses = @('__PRIMARY__','__SECONDARY__')
        if ($v6Targets -contains [int]$index) {
            $addresses += @('__PRIMARY6__','__SECONDARY6__')
        }
        Set-DnsClientServerAddress -InterfaceIndex $index `
            -ServerAddresses $addresses -ErrorAction Stop
    }
    foreach ($index in $targets) {
        Assert-WhsDnsAddresses -InterfaceIndex $index `
            -Expected @('__PRIMARY__','__SECONDARY__') `
            -AddressFamily IPv4
        if ($v6Targets -contains [int]$index) {
            Assert-WhsDnsAddresses -InterfaceIndex $index `
                -Expected @('__PRIMARY6__','__SECONDARY6__') `
                -AddressFamily IPv6
        }
    }
    # The previous provider's per-interface DoH entries name resolvers that
    # are no longer configured. Encrypted DNS is re-applied afterwards by the
    # DoH script when the user has it switched on.
""" + "\n" + ClearDohInterfacePowerShell + """
    Clear-DnsClientCache -ErrorAction Stop
} catch {
    $failure = $_
    try {
        Restore-WhsDnsSnapshot -Snapshot $beforeApply
        if ($createdBackup) {
            Remove-Item -LiteralPath $backup -Force `
                -ErrorAction SilentlyContinue
        }
    } catch {
        throw "DNS apply failed and rollback also failed: $failure / $_"
    }
    throw $failure
}
""";

    private const string ResetPowerShell = """
$targets = @(Get-WhsDnsTargetIndices)
$beforeReset = @(Get-WhsDnsSnapshot -InterfaceIndices $targets)
$backup = Get-WhsDnsBackupPath
try {
    if (Test-Path -LiteralPath $backup) {
        $saved = @(Get-Content -LiteralPath $backup -Raw `
            -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
        $targetSet = @{}
        foreach ($index in $targets) {
            $targetSet[[int]$index] = $true
        }
        $saved = @($saved | Where-Object {
            $targetSet.ContainsKey([int]$_.InterfaceIndex)
        })
        if ($saved.Count -gt 0) {
            Restore-WhsDnsSnapshot -Snapshot $saved
            foreach ($item in $saved) {
                if ([bool]$item.Automatic) {
                    Assert-WhsDnsAutomatic `
                        -InterfaceIndex ([int]$item.InterfaceIndex) -Families @('IPv4')
                } else {
                    Assert-WhsDnsAddresses `
                        -InterfaceIndex ([int]$item.InterfaceIndex) `
                        -Expected @($item.ServerAddresses)
                }
                if ($null -eq $item.PSObject.Properties['AutomaticV6'] -or [bool]$item.AutomaticV6) {
                    Assert-WhsDnsAutomatic `
                        -InterfaceIndex ([int]$item.InterfaceIndex) -Families @('IPv6')
                } else {
                    Assert-WhsDnsAddresses `
                        -InterfaceIndex ([int]$item.InterfaceIndex) `
                        -Expected @($item.ServerAddressesV6) -AddressFamily IPv6
                }
            }
        } else {
            foreach ($index in $targets) {
                Set-DnsClientServerAddress -InterfaceIndex $index `
                    -ResetServerAddresses -ErrorAction Stop
                Assert-WhsDnsAutomatic -InterfaceIndex $index
            }
        }
        Remove-Item -LiteralPath $backup -Force `
            -ErrorAction Stop
    } else {
        foreach ($index in $targets) {
            Set-DnsClientServerAddress -InterfaceIndex $index `
                -ResetServerAddresses -ErrorAction Stop
            Assert-WhsDnsAutomatic -InterfaceIndex $index
        }
    }
    # Going back to automatic DNS must also drop encrypted-DNS entries;
    # otherwise Windows keeps them pinned to resolvers we no longer set.
""" + "\n" + ClearDohInterfacePowerShell + VerifyDohClearedPowerShell + """
    Clear-DnsClientCache -ErrorAction Stop
} catch {
    $failure = $_
    try {
        Restore-WhsDnsSnapshot -Snapshot $beforeReset
    } catch {
        throw "DNS reset failed and rollback also failed: $failure / $_"
    }
    throw $failure
}
""";

    private const string EnableDohPowerShell = """
if (-not (Get-Command Add-DnsClientDohServerAddress `
    -ErrorAction SilentlyContinue)) {
    exit 6
}
$addresses = @('__PRIMARY__','__SECONDARY__')
$addresses6 = @('__PRIMARY6__','__SECONDARY6__')
$targets = @(Get-WhsDnsTargetIndices)
$v6Targets = @(Get-WhsDnsIpv6Targets -InterfaceIndices $targets)
# Only register the IPv6 resolvers in the machine-wide catalogue when some
# interface will actually use them, so a machine without routed IPv6 is not
# left advertising resolvers it can never reach.
$catalogue = @($addresses)
if ($v6Targets.Count -gt 0) { $catalogue += $addresses6 }
$beforeDns = @(Get-WhsDnsSnapshot -InterfaceIndices $targets)
$beforeDoh = foreach ($address in $catalogue) {
    $entry = Get-DnsClientDohServerAddress `
        -ServerAddress $address -ErrorAction SilentlyContinue
    if ($null -eq $entry) {
        [pscustomobject]@{
            ServerAddress = $address
            Exists = $false
        }
    } else {
        [pscustomobject]@{
            ServerAddress = $address
            Exists = $true
            DohTemplate = [string]$entry.DohTemplate
            AllowFallbackToUdp = [bool]$entry.AllowFallbackToUdp
            AutoUpgrade = [bool]$entry.AutoUpgrade
        }
    }
}
try {
    foreach ($address in $catalogue) {
        $entry = Get-DnsClientDohServerAddress `
            -ServerAddress $address -ErrorAction SilentlyContinue
        if ($null -eq $entry) {
            Add-DnsClientDohServerAddress `
                -ServerAddress $address `
                -DohTemplate '__DOH_TEMPLATE__' `
                -AllowFallbackToUdp $false -AutoUpgrade $true `
                -ErrorAction Stop
        } else {
            Set-DnsClientDohServerAddress `
                -ServerAddress $address `
                -DohTemplate '__DOH_TEMPLATE__' `
                -AllowFallbackToUdp $false -AutoUpgrade $true `
                -ErrorAction Stop
        }
    }
    foreach ($index in $targets) {
        $wanted = @($addresses)
        if ($v6Targets -contains [int]$index) { $wanted += $addresses6 }
        Set-DnsClientServerAddress -InterfaceIndex $index `
            -ServerAddresses $wanted -ErrorAction Stop
        Assert-WhsDnsAddresses -InterfaceIndex $index `
            -Expected $addresses -AddressFamily IPv4
        if ($v6Targets -contains [int]$index) {
            Assert-WhsDnsAddresses -InterfaceIndex $index `
                -Expected $addresses6 -AddressFamily IPv6
        }
    }
    foreach ($address in $catalogue) {
        $entry = Get-DnsClientDohServerAddress `
            -ServerAddress $address -ErrorAction Stop
        if (-not [bool]$entry.AutoUpgrade -or
            [string]$entry.DohTemplate -ne '__DOH_TEMPLATE__') {
            throw "DoH verification failed for $address."
        }
    }
    # This is the step that actually turns the adapter encrypted. Verifying
    # only the machine-wide catalogue above is what let earlier versions
    # report success while Windows kept resolving in the clear.
    Set-WhsDohInterface -InterfaceIndices $targets `
        -Addresses $addresses -Template '__DOH_TEMPLATE__' `
        -AddressFamily IPv4
    if ($v6Targets.Count -gt 0) {
        Set-WhsDohInterface -InterfaceIndices $v6Targets `
            -Addresses $addresses6 -Template '__DOH_TEMPLATE__' `
            -AddressFamily IPv6
    }
    foreach ($index in $targets) {
        Assert-WhsDohInterface -InterfaceIndex $index `
            -Expected $addresses -Template '__DOH_TEMPLATE__' `
            -AddressFamily IPv4
        if ($v6Targets -contains [int]$index) {
            Assert-WhsDohInterface -InterfaceIndex $index `
                -Expected $addresses6 -Template '__DOH_TEMPLATE__' `
                -AddressFamily IPv6
        }
    }
    # Re-apply the servers so the DNS client re-reads the interface
    # configuration instead of waiting for the next network change.
    foreach ($index in $targets) {
        $wanted = @($addresses)
        if ($v6Targets -contains [int]$index) { $wanted += $addresses6 }
        Set-DnsClientServerAddress -InterfaceIndex $index `
            -ServerAddresses $wanted -ErrorAction Stop
    }
    Clear-DnsClientCache -ErrorAction Stop
} catch {
    $failure = $_
    try {
        Remove-WhsDohInterface -InterfaceIndices $targets
        Restore-WhsDnsSnapshot -Snapshot $beforeDns
        foreach ($item in $beforeDoh) {
            if ([bool]$item.Exists) {
                Set-DnsClientDohServerAddress `
                    -ServerAddress $item.ServerAddress `
                    -DohTemplate $item.DohTemplate `
                    -AllowFallbackToUdp ([bool]$item.AllowFallbackToUdp) `
                    -AutoUpgrade ([bool]$item.AutoUpgrade) `
                    -ErrorAction Stop
            } else {
                Remove-DnsClientDohServerAddress `
                    -ServerAddress $item.ServerAddress `
                    -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    } catch {
        throw "DoH apply failed and rollback also failed: $failure / $_"
    }
    throw $failure
}
""";

    private const string DisableDohPowerShell = """
if (-not (Get-Command Set-DnsClientDohServerAddress `
    -ErrorAction SilentlyContinue)) {
    exit 6
}
$addresses = @('__PRIMARY__','__SECONDARY__')
$addresses6 = @('__PRIMARY6__','__SECONDARY6__')
$targets = @(Get-WhsDnsTargetIndices)
$v6Targets = @(Get-WhsDnsIpv6Targets -InterfaceIndices $targets)
$beforeDoh = foreach ($address in ($addresses + $addresses6)) {
    $entry = Get-DnsClientDohServerAddress `
        -ServerAddress $address -ErrorAction SilentlyContinue
    if ($null -ne $entry) {
        [pscustomobject]@{
            ServerAddress = $address
            DohTemplate = [string]$entry.DohTemplate
            AllowFallbackToUdp = [bool]$entry.AllowFallbackToUdp
            AutoUpgrade = [bool]$entry.AutoUpgrade
        }
    }
}
try {
    # Clearing the per-interface entries is what returns the adapter to
    # unencrypted. Only lowering AutoUpgrade in the machine-wide catalogue
    # left Windows resolving over DoH with the dashboard showing it off.
    Remove-WhsDohInterface -InterfaceIndices $targets
    foreach ($index in $targets) {
        Assert-WhsDohInterfaceCleared -InterfaceIndex $index
    }
    foreach ($item in @($beforeDoh)) {
        Set-DnsClientDohServerAddress `
            -ServerAddress $item.ServerAddress `
            -DohTemplate $item.DohTemplate `
            -AllowFallbackToUdp ([bool]$item.AllowFallbackToUdp) `
            -AutoUpgrade $false -ErrorAction Stop
    }
    foreach ($item in @($beforeDoh)) {
        $entry = Get-DnsClientDohServerAddress `
            -ServerAddress $item.ServerAddress -ErrorAction Stop
        if ([bool]$entry.AutoUpgrade) {
            throw "DoH disable verification failed for $($item.ServerAddress)."
        }
    }
    foreach ($index in $targets) {
        $wanted = @($addresses)
        if ($v6Targets -contains [int]$index) { $wanted += $addresses6 }
        Set-DnsClientServerAddress -InterfaceIndex $index `
            -ServerAddresses $wanted -ErrorAction Stop
    }
    Clear-DnsClientCache -ErrorAction Stop
} catch {
    $failure = $_
    try {
        foreach ($item in @($beforeDoh)) {
            Set-DnsClientDohServerAddress `
                -ServerAddress $item.ServerAddress `
                -DohTemplate $item.DohTemplate `
                -AllowFallbackToUdp ([bool]$item.AllowFallbackToUdp) `
                -AutoUpgrade ([bool]$item.AutoUpgrade) `
                -ErrorAction Stop
        }
    } catch {
        throw "DoH disable failed and rollback also failed: $failure / $_"
    }
    throw $failure
}
""";
}
