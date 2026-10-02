// SPDX-License-Identifier: MIT
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace WhitehatSecurity.Core;

/// <summary>
/// Reads the identity assigned by Windows, rather than inferring packaging
/// from a build flag or a directory name. Unpacked development builds still
/// use the desktop lifecycle; a registered MSIX uses Windows deployment.
/// </summary>
public static class PackageRuntime
{
    private const int ErrorInsufficientBuffer = 122;
    private const int AppModelErrorNoPackage = 15700;
    private static readonly Lazy<string?> FamilyName = new(ReadFamilyName);

    public static string? PackageFamilyName => FamilyName.Value;
    public static bool IsPackaged => PackageFamilyName is not null;

    /// <summary>Stable across package updates, separate from the EXE edition.</summary>
    public static string GetInstanceObjectName(string suffix)
    {
        if (string.IsNullOrEmpty(suffix)
            || suffix.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
            throw new ArgumentException("An instance object suffix must use ASCII letters, digits or hyphens.", nameof(suffix));

        if (!IsPackaged) return $"Global\\WhitehatSecurity-7.4-{suffix}";
        using var identity = WindowsIdentity.GetCurrent();
        var sid = identity.User?.Value
            ?? throw new InvalidOperationException("The current Windows user has no SID.");
        // Local is scoped to this logon session. Including the user SID also
        // keeps administrator/standard-user activation from sharing an event.
        return $"Local\\{PackageFamilyName}.{sid}.{suffix}";
    }

    /// <summary>
    /// Windows owns the packaged startup choice. Opening Settings does not
    /// enable startup, write Run keys or override a user's disabled state.
    /// </summary>
    public static void OpenStartupSettings()
    {
        Process.Start(new ProcessStartInfo("ms-settings:startupapps")
        {
            UseShellExecute = true,
        });
    }

    private static string? ReadFamilyName()
    {
        uint length = 0;
        var result = GetCurrentPackageFullName(ref length, null);
        if (result == AppModelErrorNoPackage) return null;
        if (result != ErrorInsufficientBuffer)
            throw new Win32Exception(result, "Windows package identity could not be determined.");

        // Do not fall back to EXE setup if identity lookup fails. A damaged
        // package must never install a second copy or uninstall the EXE edition.
        length = 0;
        result = GetCurrentPackageFamilyName(ref length, null);
        if (result != ErrorInsufficientBuffer || length is 0 or > 32768)
            throw new Win32Exception(result, "Windows package family could not be determined.");
        var family = new StringBuilder(checked((int)length));
        result = GetCurrentPackageFamilyName(ref length, family);
        if (result != 0)
            throw new Win32Exception(result, "Windows package family could not be read.");
        if (family.Length == 0)
            throw new InvalidOperationException("Windows returned an empty package family name.");
        return family.ToString();
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetCurrentPackageFullName(ref uint packageFullNameLength, StringBuilder? packageFullName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetCurrentPackageFamilyName(ref uint packageFamilyNameLength, StringBuilder? packageFamilyName);
}
