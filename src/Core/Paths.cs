// SPDX-License-Identifier: MIT
// Resolves the runtime data directory. Three cases:
// Packaged copies first require an explicitly selected durable recovery
// directory. They never use the desktop fallbacks below.
//
//   1. The .exe lives under %ProgramFiles% (the canonical install dir)
//      → ALWAYS use %LOCALAPPDATA%\Whitehat Security\, even if the
//        process happens to be elevated and could technically write to
//        the install dir. This is the deterministic case the user sees
//        on a real install.
//
//   2. The .exe lives somewhere else AND that location is writable
//      (developer build, Downloads folder, portable USB stick)
//      → write next to the .exe so config + logs travel with it.
//
//   3. The .exe lives somewhere else but the location is read-only
//      (e.g. removable media set read-only)
//      → fall back to %LOCALAPPDATA%, then %TEMP% as last resort.
//
// v7.2.x had a hard crash when this returned Program Files for a
// non-writable location. v7.3.0 added the IsWritable probe but that
// gave a non-deterministic answer for elevated installs (sometimes
// Program Files, sometimes LocalAppData). v7.3.3 makes the install-dir
// case deterministic so a fresh install ALWAYS gets fresh defaults
// from the same well-known location.

using System;
using System.IO;

namespace WhitehatSecurity.Core;

public static class Paths
{
    /// <summary>
    /// %LOCALAPPDATA%\Whitehat Security — always the user-data location
    /// for an installed copy of the program. Exposed so the uninstaller
    /// can delete it cleanly.
    /// </summary>
    public static string UserDataDir { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Whitehat Security");

    private static readonly Lazy<string> DesktopDataDir = new(ResolveDataDir);

    /// <summary>Where the program reads/writes config, logs and recovery records.</summary>
    public static string DataDir => PackageRuntime.IsPackaged
        ? PackagedDataFolder.GetDataDirectory()
        : DesktopDataDir.Value;

    public static string ConfigPath  => Path.Combine(DataDir, "notification_config.json");
    public static string LogsDir     => Path.Combine(DataDir, "Logs");
    public static string BaselineDir => Path.Combine(DataDir, "Baselines");
    public static string QuarantineDir => Path.Combine(DataDir, "Quarantine");
    public static string RemediationDir => Path.Combine(DataDir, "Remediation");
    /// <summary>
    /// Durable alert history replayed into the Alerts page at startup.
    /// </summary>
    public static string AlertHistoryPath =>
        Path.Combine(DataDir, "alert-history.jsonl");

    private static string ResolveDataDir()
    {
        // Case 1: running from the installed location → always LocalAppData.
        // This avoids the "sometimes Program Files, sometimes LocalAppData"
        // race that would happen on an elevated launch in v7.3.x.
        if (IsRunningFromProgramFiles())
            return EnsureLocalAppDataDir();

        // Case 2: portable / dev build — write next to the .exe if possible.
        var preferred = AppContext.BaseDirectory;
        if (IsWritable(preferred)) return preferred;

        // Case 3: read-only portable location → LocalAppData fallback.
        return EnsureLocalAppDataDir();
    }

    private static bool IsRunningFromProgramFiles()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) return false;
            var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            var pf64 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            return (!string.IsNullOrEmpty(pf64) && exe.StartsWith(pf64, StringComparison.OrdinalIgnoreCase))
                || (!string.IsNullOrEmpty(pf86) && exe.StartsWith(pf86, StringComparison.OrdinalIgnoreCase));
        }
        catch { return false; }
    }

    private static string EnsureLocalAppDataDir()
    {
        try
        {
            Directory.CreateDirectory(UserDataDir);
            return UserDataDir;
        }
        catch
        {
            // Last-ditch fallback: temp folder. Should be writable for any
            // user account that can run the .exe at all.
            var tmp = Path.Combine(Path.GetTempPath(), "WhitehatSecurity");
            try { Directory.CreateDirectory(tmp); } catch { }
            return tmp;
        }
    }

    private static bool IsWritable(string dir)
    {
        if (!Directory.Exists(dir)) return false;
        var probe = Path.Combine(dir, $".whs_write_probe_{Guid.NewGuid():N}");
        bool wrote = false;
        try
        {
            File.WriteAllText(probe, "");
            wrote = true;
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            // Always try to clean up the probe even if a concurrent AV scan
            // (or, in theory, a permission flip between the Write and the
            // Delete) prevented the original delete. Without this, the
            // probe could be left as a stray .whs_write_probe_XXX file in
            // the install dir or LocalAppData over time.
            if (wrote)
            {
                try { File.Delete(probe); } catch { }
            }
        }
    }
}
