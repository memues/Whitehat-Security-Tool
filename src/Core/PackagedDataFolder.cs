// SPDX-License-Identifier: MIT
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows.Forms;

namespace WhitehatSecurity.Core;

/// <summary>
/// Keeps package recovery data in an explicitly chosen local directory.
/// Only its pointer is package-owned. Reset/removal can discard that pointer;
/// choosing the same directory again reopens its existing records.
/// </summary>
public static class PackagedDataFolder
{
    private const string MarkerName = ".whitehat-data-directory.json";
    private const int MetadataLimit = 8192;
    private static Selection? _selection;

    private sealed record Selection(int Version, string Directory, Guid DirectoryId);
    private sealed record Marker(int Version, string Product, Guid DirectoryId);

    public static bool Initialize(bool interactive)
    {
        if (!PackageRuntime.IsPackaged) return true;
        try
        {
            var pointer = GetPointerPath();
            var error = "";
            if (File.Exists(pointer))
            {
                try
                {
                    if (ThreatPath.ContainsReparsePoint(pointer))
                        throw new IOException("The saved data-folder pointer passes through a link or junction.");
                    if (!TryParseSelection(ReadMetadata(pointer), out var directory, out var id))
                        throw new IOException("The saved data-folder pointer is invalid.");
                    _selection = new Selection(1, directory, id);
                    if (TryEnsureAvailable(out error)) return true;
                }
                catch (Exception ex) { error = ex.Message; }
                _selection = null;
            }

            // Startup tasks and unattended invocations must not display a
            // picker, invent a temporary data root, or start monitoring.
            if (!interactive) return false;
            if (error.Length > 0)
                MessageBox.Show(
                    "The saved data folder cannot be used. No recovery data was moved or deleted.\n\n" +
                    error + "\n\nSelect the original folder to reopen its records, or choose a new folder.",
                    "Whitehat Security Tool - Data folder", MessageBoxButtons.OK, MessageBoxIcon.Warning);

            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var suggested = Path.Combine(profile, "Whitehat Security Tool Data");
            var answer = MessageBox.Show(
                "Choose where to keep settings, logs, quarantined files and recovery records.\n\n" +
                "These files will remain after you reset or uninstall the app. After reinstalling, " +
                "choose the same folder to reopen them. The app will not move or delete existing data.\n\n" +
                "Use a local folder that is not synced to cloud storage. Suggested folder:\n" +
                suggested + "\n\nYes: use this folder. No: choose or reopen another folder. Cancel: exit.",
                "Whitehat Security Tool - Keep recovery data", MessageBoxButtons.YesNoCancel,
                MessageBoxIcon.Information, MessageBoxDefaultButton.Button2);
            if (answer == DialogResult.Cancel) return false;

            var selected = suggested;
            if (answer == DialogResult.No)
            {
                using var picker = new FolderBrowserDialog
                {
                    Description = "Select a local data/recovery folder outside AppData, system and cloud folders.",
                    UseDescriptionForTitle = true,
                    ShowNewFolderButton = true,
                    SelectedPath = profile,
                };
                if (picker.ShowDialog() != DialogResult.OK) return false;
                selected = picker.SelectedPath;
                if (MessageBox.Show(
                        "Use this folder for settings, logs, quarantine and recovery records?\n\n" +
                        selected + "\n\nExisting records will be reopened. Data remains after app reset or uninstall. " +
                        "Choose a local folder that is not shared or synced to cloud storage.",
                        "Whitehat Security Tool - Confirm data folder", MessageBoxButtons.YesNo,
                        MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                    return false;
            }

            if (!TryValidatePath(selected, out var normalized, out error))
                throw new IOException(error);
            Directory.CreateDirectory(normalized);
            if (!TryValidatePath(normalized, out normalized, out error))
                throw new IOException(error);
            var markerPath = Path.Combine(normalized, MarkerName);
            Guid directoryId;
            if (File.Exists(markerPath))
                directoryId = ReadDirectoryId(markerPath);
            else
            {
                directoryId = Guid.NewGuid();
                WriteNewMetadata(markerPath, new Marker(1, "Whitehat Security Tool", directoryId));
            }
            _selection = new Selection(1, normalized, directoryId);
            if (!TryEnsureAvailable(out error)) throw new IOException(error);
            SavePointer(pointer, _selection);
            return true;
        }
        catch (Exception ex)
        {
            _selection = null;
            if (interactive)
                MessageBox.Show(
                    "The app has not started because its data folder could not be prepared. " +
                    "Any existing files have been retained.\n\n" + ex.Message +
                    "\n\nLaunch the app manually to select a usable local folder.",
                    "Whitehat Security Tool - Data folder unavailable", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
    }

    public static string GetDataDirectory()
    {
        var selection = _selection
            ?? throw new IOException("Launch Whitehat Security Tool manually and select a recovery data folder first.");
        if (!TryValidatePath(selection.Directory, out var normalized, out var error))
            throw new IOException(error);
        if (!Directory.Exists(normalized))
            throw new IOException("The recovery data folder is missing. Reopen the original folder before continuing.");
        if (ReadDirectoryId(Path.Combine(normalized, MarkerName)) != selection.DirectoryId)
            throw new IOException("The recovery folder identity changed. Restart and explicitly reopen the correct folder.");
        return normalized;
    }

    /// <summary>Call before changing files or settings so recovery storage fails closed.</summary>
    public static bool TryEnsureAvailable(out string error)
    {
        error = "";
        if (!PackageRuntime.IsPackaged) return true;
        try
        {
            var directory = GetDataDirectory();
            var probe = Path.Combine(directory, ".whitehat-write-check-" + Guid.NewGuid().ToString("N"));
            try
            {
                using (var stream = new FileStream(probe, FileMode.CreateNew, FileAccess.ReadWrite,
                           FileShare.None, 1, FileOptions.WriteThrough))
                {
                    stream.WriteByte(0);
                    stream.Flush(flushToDisk: true);
                }
                File.Delete(probe);
            }
            finally
            {
                // Delete only this call's random probe, never user records.
                if (File.Exists(probe)) File.Delete(probe);
            }
            return true;
        }
        catch (Exception ex)
        {
            error = "Recovery storage is unavailable; no action should be applied. " + ex.Message;
            return false;
        }
    }

    /// <summary>Read-only validation. It never creates the selected directory.</summary>
    public static bool TryValidatePath(string? candidate, out string normalized, out string error)
    {
        normalized = "";
        error = "Select a fully qualified folder on a local fixed drive.";
        try
        {
            if (string.IsNullOrWhiteSpace(candidate) || candidate != candidate.Trim()) return false;
            var value = candidate.Replace('/', '\\');
            // Reject UNC, device namespace, drive-relative, ADS and ambiguous
            // Windows trailing-dot/space aliases before canonicalization.
            if (value.Length < 4 || !char.IsAsciiLetter(value[0]) || value[1] != ':' || value[2] != '\\'
                || value[2..].Any(c => c == ':' || c < 32 || "\"<>|?*".Contains(c))) return false;
            var segments = value[3..].Split('\\', StringSplitOptions.RemoveEmptyEntries);
            if (segments.Length == 0 || segments.Any(s => s is "." or ".." || s.EndsWith('.') || s.EndsWith(' ')))
                return false;
            normalized = Path.GetFullPath(value).TrimEnd('\\');
            var drive = new DriveInfo(Path.GetPathRoot(normalized)!);
            if (drive.DriveType != DriveType.Fixed) return false;

            // SUBST aliases are not reparse points; resolve their DOS device
            // before comparing textual roots. Drive aliases must not turn a
            // protected or cloud directory into an apparently unrelated path.
            var device = new StringBuilder(32768);
            if (QueryDosDeviceW(normalized[..2], device, device.Capacity) == 0)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "The selected drive could not be resolved.");
            if (device.ToString().StartsWith(@"\??\", StringComparison.Ordinal))
            {
                error = "Choose the original local drive and full folder name instead of a substituted drive.";
                return false;
            }

            if (!HasCanonicalExistingParent(normalized, out error)) return false;

            foreach (var forbidden in GetForbiddenDirectories())
            {
                if (string.IsNullOrWhiteSpace(forbidden)) continue;
                if (IsSameOrUnder(normalized, forbidden) || IsSameOrUnder(forbidden, normalized))
                {
                    error = "Use a dedicated folder outside Windows, Program Files, AppData, temporary, app and known OneDrive locations.";
                    return false;
                }
            }
            if (File.Exists(normalized))
            {
                error = "The selected path is a file, not a directory.";
                return false;
            }
            if (ThreatPath.ContainsReparsePoint(normalized))
            {
                error = "The data folder must not pass through symbolic links, junctions or cloud placeholders.";
                return false;
            }
            error = "";
            return true;
        }
        catch (Exception ex)
        {
            error = "The data folder could not be validated: " + ex.Message;
            return false;
        }
    }

    public static bool IsSameOrUnder(string path, string directory)
    {
        var fullPath = Path.GetFullPath(path).TrimEnd('\\', '/');
        var fullDirectory = Path.GetFullPath(directory).TrimEnd('\\', '/');
        return string.Equals(fullPath, fullDirectory, StringComparison.OrdinalIgnoreCase)
            || fullPath.StartsWith(fullDirectory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static bool HasCanonicalExistingParent(string path, out string error)
    {
        error = "";
        var ancestor = path;
        while (true)
        {
            try
            {
                var attributes = File.GetAttributes(ancestor);
                if ((attributes & FileAttributes.Directory) == 0)
                {
                    error = "The selected path has a file where a directory is required.";
                    return false;
                }
                break;
            }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
            ancestor = Path.GetDirectoryName(ancestor)
                ?? throw new IOException("The selected folder has no accessible local parent.");
        }

        const uint openExisting = 3;
        const uint backupSemantics = 0x02000000;
        // Opening directories for metadata only is supported without elevated
        // access. Following aliases here lets the normalized final name reveal
        // short names and junctions before a folder is created or adopted.
        using var handle = CreateFileW(ancestor, 0, FileShare.ReadWrite | FileShare.Delete,
            IntPtr.Zero, openExisting, backupSemantics, IntPtr.Zero);
        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "The selected parent folder could not be inspected.");
        var final = new StringBuilder(32768);
        var length = GetFinalPathNameByHandleW(handle, final, final.Capacity, 0);
        if (length == 0 || length >= final.Capacity)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "The selected parent folder could not be resolved.");
        if (!MatchesCanonicalDirectory(ancestor, final.ToString()))
        {
            error = "Choose the full original folder path, without short names, drive aliases, links or junctions.";
            return false;
        }
        return true;
    }

    /// <summary>Compares a selected ancestor to the normalized DOS path returned by Windows.</summary>
    public static bool MatchesCanonicalDirectory(string selected, string resolved)
    {
        if (!resolved.StartsWith(@"\\?\", StringComparison.Ordinal)
            || resolved.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return false;
        // The caller already supplied a full path. Re-running GetFullPath here
        // can expand a short name and hide a mismatch we are trying to detect.
        return string.Equals(selected.Replace('/', '\\').TrimEnd('\\'),
            resolved[4..].TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Parses bounded pointer metadata without creating folders or changing the active selection.</summary>
    public static bool TryParseSelection(string json, out string directory, out Guid directoryId)
    {
        directory = "";
        directoryId = Guid.Empty;
        try
        {
            if (json.Length > MetadataLimit) return false;
            var selection = JsonSerializer.Deserialize<Selection>(json);
            if (selection is null || selection.Version != 1 || selection.DirectoryId == Guid.Empty
                || !TryValidatePath(selection.Directory, out directory, out _)) return false;
            directoryId = selection.DirectoryId;
            return true;
        }
        catch { return false; }
    }

    /// <summary>Checks the durable marker without adopting, creating or modifying a data folder.</summary>
    public static bool TryReadDirectoryMarker(string directory, out Guid directoryId, out string error)
    {
        directoryId = Guid.Empty;
        error = "";
        try
        {
            directoryId = ReadDirectoryId(Path.Combine(directory, MarkerName));
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static IEnumerable<string> GetForbiddenDirectories()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.Combine(profile, "AppData"),
            AppContext.BaseDirectory,
            Path.GetTempPath(),
        };
        foreach (var name in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
        {
            var value = Environment.GetEnvironmentVariable(name);
            if (!string.IsNullOrWhiteSpace(value)) roots.Add(value);
        }
        using var accounts = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\OneDrive\Accounts");
        if (accounts is not null)
            foreach (var name in accounts.GetSubKeyNames())
            {
                using var account = accounts.OpenSubKey(name);
                if (account?.GetValue("UserFolder") is string value && !string.IsNullOrWhiteSpace(value))
                    roots.Add(value);
            }
        return roots;
    }

    private static string GetPointerPath()
    {
        var family = PackageRuntime.PackageFamilyName;
        if (string.IsNullOrWhiteSpace(family)
            || family.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '-' or '_')))
            throw new IOException("The package family is unavailable.");
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(local)) throw new IOException("Local application storage is unavailable.");
        return Path.Combine(local, "Packages", family, "LocalState", "whitehat-data-folder.json");
    }

    private static string ReadMetadata(string path)
    {
        if (ThreatPath.ContainsReparsePoint(path)) throw new IOException("Recovery metadata must not be a link or junction.");
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (stream.Length > MetadataLimit) throw new IOException("Recovery metadata is too large.");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }

    private static Guid ReadDirectoryId(string markerPath)
    {
        var marker = JsonSerializer.Deserialize<Marker>(ReadMetadata(markerPath));
        if (marker is null || marker.Version != 1 || marker.Product != "Whitehat Security Tool"
            || marker.DirectoryId == Guid.Empty)
            throw new IOException("The recovery folder marker is invalid. Existing contents have been left unchanged.");
        return marker.DirectoryId;
    }

    private static void WriteNewMetadata<T>(string path, T value)
    {
        if (ThreatPath.ContainsReparsePoint(path)) throw new IOException("Recovery metadata must not be a link or junction.");
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        JsonSerializer.Serialize(stream, value);
        stream.Flush(flushToDisk: true);
    }

    private static void SavePointer(string pointer, Selection selection)
    {
        if (ThreatPath.ContainsReparsePoint(pointer)) throw new IOException("Package storage passes through a link or junction.");
        Directory.CreateDirectory(Path.GetDirectoryName(pointer)!);
        var temporary = pointer + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            WriteNewMetadata(temporary, selection);
            File.Move(temporary, pointer, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, FileShare shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder path, int pathLength, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    private static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, int targetLength);
}
