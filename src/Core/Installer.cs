// SPDX-License-Identifier: MIT
// Self-installer / self-uninstaller. The single .exe is its own setup
// program: when launched from outside Program Files it offers to install
// itself system-wide, when launched with --uninstall it cleans up.
//
// Install location: %ProgramFiles%\Whitehat Security\WhitehatSecurity.exe
// Add/Remove key:   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WhitehatSecurity
// Start menu link:  %ProgramData%\Microsoft\Windows\Start Menu\Programs\Whitehat Security.lnk
// Desktop link:     %PUBLIC%\Desktop\Whitehat Security.lnk
//
// All file copies and registry writes happen elevated. Self-deletion of the
// installed binary during uninstall uses an inline, encoded Windows
// PowerShell command because Windows will not remove a running .exe.

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using Microsoft.Win32;

namespace WhitehatSecurity.Core;

public static class Installer
{
    public const string ProductName    = "Whitehat Security";
    public const string Publisher      = "Whitehat Security";
    public const string AppId          = "WhitehatSecurity";

    /// <summary>
    /// Read from the assembly rather than hard-coded. The constant used to be
    /// maintained by hand next to &lt;Version&gt; in the .csproj, the manifest
    /// and the dashboard caption, and the copies drifted apart between
    /// releases — the shipped 7.4.3 still described itself as 7.4.0 in its
    /// application manifest.
    /// </summary>
    public static string ProductVersion { get; } = ReadProductVersion();

    private static string ReadProductVersion()
    {
        var version = typeof(Installer).Assembly.GetName().Version;
        return version is null
            ? "0.0.0"
            : $"{version.Major}.{version.Minor}.{version.Build}";
    }

    public const string UninstallKeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WhitehatSecurity";

    public static string DefaultInstallDir =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ProductName);

    public static string DefaultInstallExePath =>
        Path.Combine(DefaultInstallDir, "WhitehatSecurity.exe");

    public static string StartMenuShortcut =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
            "Programs",
            ProductName + ".lnk");

    public static string PublicDesktopShortcut =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            ProductName + ".lnk");

    /// <summary>
    /// Path to the per-user Desktop shortcut. On systems with OneDrive
    /// "Known Folder Move" enabled, this resolves to the redirected
    /// OneDrive\Desktop folder, which is exactly the directory the user
    /// actually sees on their screen — the Public Desktop entry alone is
    /// invisible there. We create both to cover both setups.
    /// </summary>
    public static string UserDesktopShortcut =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            ProductName + ".lnk");

    /// <summary>
    /// Where Windows looks for system-wide auto-start entries. A new entry
    /// is written only after explicit --autostart consent. Upgrades leave
    /// the existing entry and Windows Startup preferences unchanged.
    /// </summary>
    public const string RunKeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    public const string RunValueName = "WhitehatSecurity";

    public static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static bool IsInstalledImagePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try
        {
            return string.Equals(Path.GetFullPath(path),
                Path.GetFullPath(DefaultInstallExePath), StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException) { return false; }
        catch (NotSupportedException) { return false; }
    }

    /// <summary>
    /// Returns true when the running .exe lives inside the canonical install
    /// directory. The first-run flow uses this to decide whether to show the
    /// install prompt.
    /// </summary>
    public static bool IsRunningFromInstallDir()
    {
        return IsInstalledImagePath(Environment.ProcessPath);
    }

    public static bool IsAlreadyInstalled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(UninstallKeyPath);
            return key is not null;
        }
        catch { return false; }
    }

    /// <summary>
    /// Version of the copy currently sitting in the install directory, or
    /// null when nothing is installed. Read from the binary itself rather
    /// than the Add/Remove Programs DisplayVersion, so a half-finished
    /// install cannot report a version the file on disk does not have.
    /// </summary>
    public static Version? GetInstalledVersion()
    {
        try
        {
            var exe = DefaultInstallExePath;
            if (!File.Exists(exe)) return null;
            var raw = FileVersionInfo
                .GetVersionInfo(exe).FileVersion;
            return Version.TryParse(raw, out var parsed) ? parsed : null;
        }
        catch { return null; }
    }

    /// <summary>Version of the .exe that is executing right now.</summary>
    public static Version RunningVersion { get; } =
        typeof(Installer).Assembly.GetName().Version
        ?? new Version(0, 0, 0, 0);

    /// <summary>
    /// True when an older copy is installed and this (newer) copy is running
    /// from somewhere else — the case where the user downloaded a fresh
    /// release but the installed copy would otherwise stay behind forever.
    /// Versions are compared on major.minor.build; the revision field is
    /// always 0 in this project's release builds.
    /// </summary>
    public static bool IsUpgradeAvailableForInstalledCopy(
        out Version? installedVersion)
    {
        installedVersion = GetInstalledVersion();
        if (installedVersion is null) return false;
        if (IsRunningFromInstallDir()) return false;
        return IsUpgrade(RunningVersion, installedVersion);
    }

    /// <summary>
    /// Pure comparison behind <see cref="IsUpgradeAvailableForInstalledCopy"/>,
    /// exposed so the smoke tests can cover it without an installed copy.
    /// </summary>
    public static bool IsUpgrade(Version running, Version installed)
    {
        ArgumentNullException.ThrowIfNull(running);
        ArgumentNullException.ThrowIfNull(installed);
        return Truncate(running) > Truncate(installed);
    }

    private static Version Truncate(Version version) =>
        new(version.Major, version.Minor, Math.Max(version.Build, 0));

    // ========================================================================
    //  INSTALL
    // ========================================================================

    /// <summary>
    /// Copies the running .exe to %ProgramFiles%\Whitehat Security\,
    /// registers in Add/Remove Programs, and creates Start Menu and Public
    /// Desktop shortcuts. Must be called from an elevated process.
    /// </summary>
    public static void InstallElevated(Logger? logger = null, bool enableAutostart = false,
        int setupParentProcessId = 0)
    {
        RequireElevation();
        var src = Environment.ProcessPath
            ?? throw new InvalidOperationException("Cannot determine current exe path");
        var dstDir = DefaultInstallDir;
        var dstExe = DefaultInstallExePath;

        Directory.CreateDirectory(dstDir);

        // An upgrade over a running copy used to fall through to File.Replace,
        // which swaps the file on disk but leaves the OLD build running and
        // still holding the tray icon — so the user saw "installed 7.4.3"
        // while 7.4.1 kept monitoring. Stop the installed instances first.
        StopInstalledInstances(logger, setupParentProcessId);

        // Copy the binary to a temp name then atomically swap it into place.
        // We try plain Move first; if the destination is locked (the previous
        // version is still running), File.Replace handles the swap by routing
        // through a backup file.
        var tmp = dstExe + ".new";
        File.Copy(src, tmp, overwrite: true);

        if (!File.Exists(dstExe))
        {
            File.Move(tmp, dstExe);
        }
        else
        {
            try
            {
                File.Delete(dstExe);
                File.Move(tmp, dstExe);
            }
            catch (IOException)
            {
                // Locked — the .exe is in use. Use File.Replace to swap
                // through a backup, which works even when the target is open.
                var bak = dstExe + ".bak";
                try { File.Delete(bak); } catch { }
                File.Replace(tmp, dstExe, bak, ignoreMetadataErrors: true);
                try { File.Delete(bak); } catch { }
            }
        }
        logger?.Info($"Installed binary to {dstExe}");

        // Settings that have been withdrawn leave their enforcement behind.
        // Removing "Block All Outbound" from the UI without this would strand
        // anyone who had it switched on: the rule stays in Windows Firewall
        // with no checkbox left to clear it.
        var retired = ElevationHelper.RemoveRetiredFirewallRules(logger);
        if (retired != 0)
            throw new InvalidOperationException($"Retired firewall rule cleanup failed (exit {retired}).");
        else
            logger?.Info("Checked for retired firewall rules");

        // Register in Add/Remove Programs
        WriteUninstallKey(dstExe, dstDir);
        logger?.Info("Registered in Add/Remove Programs");

        // Shortcuts — create on every plausible desktop location so it shows
        // up regardless of OneDrive Known Folder Move state. The installer
        // also drops one in the Common Desktop and the Common Start Menu so
        // every user on the machine sees it.
        CreateShortcut(StartMenuShortcut, dstExe);
        CreateShortcut(PublicDesktopShortcut, dstExe);
        CreateShortcut(UserDesktopShortcut, dstExe);

        // Do not re-enable startup on updates: Windows Startup settings may
        // have disabled the existing entry. An explicit command is consent
        // to create/update the Run value, but never clears StartupApproved.
        if (enableAutostart)
        {
            using var run = Registry.LocalMachine.CreateSubKey(RunKeyPath, writable: true);
            if (run is null) throw new InvalidOperationException("Cannot create startup key.");
            run.SetValue(RunValueName, $"\"{dstExe}\" --silent", RegistryValueKind.String);
            logger?.Info("Auto-start at logon enabled (HKLM Run key)");
        }
    }

    /// <summary>
    /// Terminates every process running the binary at the install path,
    /// skipping this process. Matching is by full image path, so a portable
    /// copy running from Downloads is never touched.
    /// </summary>
    private static void StopInstalledInstances(Logger? logger, int setupParentProcessId)
    {
        if (!File.Exists(DefaultInstallExePath)) return;

        var self = Environment.ProcessId;
        var candidates = Process.GetProcessesByName("WhitehatSecurity");
        var failures = new System.Collections.Generic.List<Exception>();

        foreach (var process in candidates)
        {
            try
            {
                // The unelevated setup launcher must remain alive to return
                // this elevated child's exit code to the Store/caller.
                if (process.Id == self || process.Id == setupParentProcessId) continue;
                string? path = null;
                try { path = process.MainModule?.FileName; }
                catch { /* exited or inaccessible — skip it */ }
                if (!IsInstalledImagePath(path))
                    continue;
                logger?.Info(
                    $"Stopping installed instance PID {process.Id} for setup");
                process.Kill(entireProcessTree: false);
                if (!process.WaitForExit(5000))
                    throw new TimeoutException($"Installed process {process.Id} did not exit.");
            }
            catch (Exception ex)
            {
                logger?.Warn(
                    $"Could not stop PID {process.Id}: {ex.Message}");
                failures.Add(ex);
            }
            finally
            {
                try { process.Dispose(); } catch { }
            }
        }
        if (failures.Count != 0)
            throw new AggregateException("Could not stop the installed application.", failures);
    }

    private static void WriteUninstallKey(string installedExe, string installDir)
    {
        using var key = Registry.LocalMachine.CreateSubKey(UninstallKeyPath, writable: true);
        if (key is null) throw new InvalidOperationException("Cannot create uninstall key");

        long sizeKb = 0;
        try { sizeKb = new FileInfo(installedExe).Length / 1024; } catch { }

        key.SetValue("DisplayName",     ProductName);
        key.SetValue("DisplayVersion",  ProductVersion);
        key.SetValue("Publisher",       Publisher);
        key.SetValue("DisplayIcon",     installedExe);
        key.SetValue("InstallLocation", installDir);
        key.SetValue("UninstallString", $"\"{installedExe}\" --uninstall");
        key.SetValue("QuietUninstallString", $"\"{installedExe}\" --uninstall --quiet");
        key.SetValue("InstallDate",     DateTime.Now.ToString("yyyyMMdd"));
        key.SetValue("EstimatedSize",   (int)sizeKb, RegistryValueKind.DWord);
        key.SetValue("NoModify",        1, RegistryValueKind.DWord);
        key.SetValue("NoRepair",        1, RegistryValueKind.DWord);
        key.SetValue("URLInfoAbout",    "https://github.com/memues/Whitehat-Security-Tool");
    }

    private static void CreateShortcut(string lnkPath, string targetExe)
    {
        // Use the WScript.Shell COM object via reflection so we don't pull in
        // an extra package reference (Interop.Shell32 etc.). Same approach
        // the PowerShell port uses internally.
        var dir = Path.GetDirectoryName(lnkPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);

        var t = Type.GetTypeFromProgID("WScript.Shell");
        if (t is null) throw new InvalidOperationException("WScript.Shell not registered");
        dynamic? shell = Activator.CreateInstance(t);
        if (shell is null) throw new InvalidOperationException("WScript.Shell instance is null");
        dynamic? sc = null;
        try
        {
            sc = shell.CreateShortcut(lnkPath);
            sc.TargetPath       = targetExe;
            sc.WorkingDirectory = Path.GetDirectoryName(targetExe) ?? "";
            sc.IconLocation     = targetExe + ",0";
            sc.Description      = ProductName;
            sc.Save();
        }
        finally
        {
            // Both COM objects must be released. Releasing only the outer
            // WScript.Shell left the inner ShellLink object pinned in the
            // CLR's RCW table, leaking one COM handle per shortcut written.
            if (sc is not null)
            {
                try { System.Runtime.InteropServices.Marshal.FinalReleaseComObject(sc); } catch { }
            }
            try { System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell); } catch { }
        }
    }

    // ========================================================================
    //  UNINSTALL
    // ========================================================================

    /// <summary>
    /// Removes the installed copy, registry entry, and shortcuts. Returns
    /// true when the final file/registration cleanup must wait for this
    /// executable to exit. User settings, logs and recovery records remain.
    /// </summary>
    public static bool UninstallElevated(Logger? logger = null, int setupParentProcessId = 0)
    {
        RequireElevation();
        StopInstalledInstances(logger, setupParentProcessId);

        var cleanupCode = ElevationHelper.CleanupManagedChanges(logger);
        if (cleanupCode != 0)
            throw new InvalidOperationException(
                $"Managed firewall/hosts/DNS cleanup failed (exit {cleanupCode}). " +
                "The application remains registered so removal can be retried.");

        // Auto-start Run key
        using (var run = Registry.LocalMachine.OpenSubKey(RunKeyPath, writable: true))
        {
            if (run is not null && run.GetValue(RunValueName) is not null)
            {
                run.DeleteValue(RunValueName, throwOnMissingValue: false);
                logger?.Info("Removed auto-start Run key");
            }
        }

        // Shortcuts
        DeleteShortcut(StartMenuShortcut, logger);
        DeleteShortcut(PublicDesktopShortcut, logger);
        DeleteShortcut(UserDesktopShortcut, logger);

        // Keep user-authored settings, diagnostic logs and remediation
        // recovery journals. Silent setup must not destroy those records.
        logger?.Info($"Retained user data at {Paths.UserDataDir}");

        var installDir   = DefaultInstallDir;

        // If we're not the installed exe, just delete the install dir directly
        if (!IsRunningFromInstallDir())
        {
            if (Directory.Exists(installDir))
            {
                Directory.Delete(installDir, recursive: true);
                logger?.Info($"Removed {installDir}");
            }
            Registry.LocalMachine.DeleteSubKeyTree(UninstallKeyPath, throwOnMissingSubKey: false);
            return false;
        }

        // Keep the delayed command in the child process arguments. A batch
        // file in user temp could be replaced while waiting for us to exit.
        logger?.Info("Scheduled self-delete; exiting");

        var psi = new ProcessStartInfo
        {
            FileName        = ElevationHelper.PowerShellPath,
            Arguments       = BuildSelfDeleteArguments(
                installDir, Environment.ProcessId, removeUninstallRegistration: true,
                waitForLauncherProcessId: setupParentProcessId),
            UseShellExecute = false,
            CreateNoWindow  = true,
            WindowStyle     = ProcessWindowStyle.Hidden,
        };
        using var helper = Process.Start(psi)
            ?? throw new InvalidOperationException("Could not start final uninstall cleanup.");
        // The caller (Program.Main) returns immediately after this and the
        // process exits, freeing the file lock so the helper can delete us.
        // The helper keeps Apps & Features registered if file deletion fails.
        return true;
    }

    public static string BuildSelfDeleteArguments(
        string installDir, int waitForProcessId = 0, bool removeUninstallRegistration = false,
        int waitForLauncherProcessId = 0)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(waitForProcessId);
        ArgumentOutOfRangeException.ThrowIfNegative(waitForLauncherProcessId);
        var fullPath = Path.GetFullPath(installDir);
        if (string.Equals(fullPath.TrimEnd('\\', '/'),
                Path.GetPathRoot(fullPath)?.TrimEnd('\\', '/'),
                StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Cannot remove a drive root.", nameof(installDir));
        // Only the canonical installation can request machine registration
        // removal; test callers use an inert temporary directory.
        if (removeUninstallRegistration && !string.Equals(
                fullPath.TrimEnd('\\', '/'), DefaultInstallDir.TrimEnd('\\', '/'),
                StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Uninstall registration belongs to the installation directory.", nameof(installDir));

        var wait = BuildWaitForProcessScript(waitForProcessId)
            + BuildWaitForProcessScript(waitForLauncherProcessId);
        var unregister = removeUninstallRegistration
            ? "[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree('" + UninstallKeyPath + "', $false)\r\n"
            : "";
        return ElevationHelper.BuildInlineArguments(
            "$ErrorActionPreference = 'Stop'\r\n" + wait +
            "$directory = " + ElevationHelper.BuildPathExpression(fullPath) + "\r\n" +
            // Retrying handles transient antivirus/indexer file handles.
            "for ($attempt = 0; $attempt -lt 30; $attempt++) {\r\n" +
            "    try {\r\n" +
            "        if ([System.IO.Directory]::Exists($directory)) { [System.IO.Directory]::Delete($directory, $true) }\r\n" +
            "        break\r\n" +
            "    } catch {\r\n" +
            "        if ($attempt -eq 29) { exit 1603 }\r\n" +
            "        Start-Sleep -Milliseconds 500\r\n" +
            "    }\r\n" +
            "}\r\n" + unregister + "exit 0\r\n");
    }

    private static string BuildWaitForProcessScript(int processId) => processId == 0 ? "" :
        "$parent = $null\r\n" +
        $"try {{ $parent = [System.Diagnostics.Process]::GetProcessById({processId}) }} catch [System.ArgumentException] {{ }}\r\n" +
        "if ($null -ne $parent) { try { $parent.WaitForExit() } finally { $parent.Dispose() } }\r\n";

    private static void DeleteShortcut(string path, Logger? logger)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
            logger?.Info($"Removed {path}");
        }
    }

    private static void RequireElevation()
    {
        if (!IsElevated())
            throw new System.ComponentModel.Win32Exception(InstallerExitCodes.ElevationRequired);
    }
}
