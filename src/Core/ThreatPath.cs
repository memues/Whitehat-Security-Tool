// SPDX-License-Identifier: MIT

using System;
using System.IO;
using System.Text.RegularExpressions;

namespace WhitehatSecurity.Core;

/// <summary>
/// Converts the executable/driver path formats returned by WMI into a
/// canonical local file path. It intentionally rejects NT device paths that
/// cannot be mapped safely without querying the object manager.
/// </summary>
public static partial class ThreatPath
{
    [GeneratedRegex(
        @"^(?<path>.+?\.(?:exe|dll|sys|com|scr|bat|cmd|ps1|vbs|js|msi))(?=\s|$)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ExecutableWithArgumentsRegex();

    public static string? Normalize(string? rawPath)
    {
        if (string.IsNullOrWhiteSpace(rawPath)) return null;

        var value = Environment.ExpandEnvironmentVariables(rawPath.Trim());
        if (value.Length > 1 && value[0] == '"')
        {
            var closingQuote = value.IndexOf('"', 1);
            if (closingQuote <= 1) return null;
            value = value[1..closingQuote];
        }
        else if (!File.Exists(value))
        {
            var match = ExecutableWithArgumentsRegex().Match(value);
            if (match.Success)
                value = match.Groups["path"].Value.Trim();
        }

        if (value.StartsWith(@"\??\", StringComparison.Ordinal))
            value = value[4..];
        else if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
            value = value[4..];

        if (value.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            value = Path.Combine(windows, value[12..]);
        }
        else if (value.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            value = Path.Combine(windows, value);
        }

        if (value.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            return null;

        try
        {
            return Path.GetFullPath(value);
        }
        catch
        {
            return null;
        }
    }

    public static bool IsProtectedSystemPath(string path)
    {
        var normalized = Normalize(path);
        if (normalized is null) return true;

        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (IsUnder(normalized, windows)) return true;

        var self = Environment.ProcessPath;
        return self is not null
            && string.Equals(
                normalized, Path.GetFullPath(self),
                StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Do not perform remediation through links or junctions.</summary>
    public static bool ContainsReparsePoint(string path)
    {
        try
        {
            var current = Path.GetFullPath(path);
            while (!string.IsNullOrEmpty(current))
            {
                try
                {
                    if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                        return true;
                }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
                current = Path.GetDirectoryName(current);
            }
            return false;
        }
        catch { return true; }
    }

    private static bool IsUnder(string path, string directory)
    {
        if (string.IsNullOrWhiteSpace(directory)) return false;
        var root = Path.GetFullPath(directory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
            + Path.DirectorySeparatorChar;
        return path.StartsWith(root, StringComparison.OrdinalIgnoreCase);
    }
}
