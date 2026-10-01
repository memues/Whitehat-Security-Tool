// SPDX-License-Identifier: MIT
// Application entry point. Three modes:
//
//   WhitehatSecurity.exe                normal run (tray + dashboard)
//   WhitehatSecurity.exe --silent       normal run, no dashboard auto-open
//   WhitehatSecurity.exe --install      copy self to Program Files, register
//                                       in Add/Remove Programs, exit
//   WhitehatSecurity.exe --uninstall    remove install dir / shortcuts /
//                                       registry, exit
//
// Runtime data (logs, config) is written to whichever directory is
// writable: next to the .exe for portable use, or %LOCALAPPDATA%\Whitehat
// Security when running from Program Files (because asInvoker has no write
// access to Program Files — this was the v7.2.0/v7.2.1 crash bug).
//
// On first run from outside the install directory, the .exe shows a small
// dialog offering to install itself system-wide so it appears in the Windows
// "Apps & Features" list and can be uninstalled the normal way.

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using WhitehatSecurity.Core;
using WhitehatSecurity.Engines;
using WhitehatSecurity.Ui;

namespace WhitehatSecurity;

internal static class Program
{
    private const string MutexName = "Global\\WhitehatSecurity-7.4-singleinstance";
    private const string ShowEventName =
        "Global\\WhitehatSecurity-7.4-show-dashboard";

    /// <summary>
    /// UTC start time of the process. Captured at the very top of Main so
    /// the Status page can show "Started: HH:mm:ss" relative to when the
    /// program actually launched (instead of when the dashboard form was
    /// constructed, which can be hours later if the user only opens the
    /// dashboard from the tray after a long uptime).
    /// </summary>
    public static readonly DateTime StartedAt = DateTime.Now;

    [STAThread]
    private static int Main(string[] args)
    {
        // Always wrap the entire entry point so an unhandled exception
        // surfaces as a MessageBox instead of a silent crash. The v7.2.0
        // bug was a Logger constructor crash that left zero diagnostic
        // information for the user; never letting that happen again.
        try
        {
            return MainCore(args);
        }
        catch (Exception ex)
        {
            try
            {
                MessageBox.Show(
                    $"Whitehat Security crashed during startup.\n\n{ex.GetType().Name}: {ex.Message}\n\n{ex.StackTrace}",
                    "Whitehat Security - Fatal",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch { }
            return 1;
        }
    }

    private static int MainCore(string[] args)
    {
        ApplicationConfiguration.Initialize();

        // ── Mode dispatch ───────────────────────────────────────────────
        bool silent    = HasFlag(args, "--silent",    "-Silent");
        bool install   = HasFlag(args, "--install",   "-Install");
        bool uninstall = HasFlag(args, "--uninstall", "-Uninstall");
        bool quiet     = HasFlag(args, "--quiet",     "-Quiet");
        var registryRollback = GetOption(
            args, "--apply-registry-rollback");
        var disableAlertService = GetOption(
            args, "--disable-alert-service");
        var restoreAlertService = GetOption(
            args, "--restore-alert-service");
        var initialTab = GetOption(args, "--tab");
        if (initialTab is not null
            && initialTab is not ("Status" or "Alerts" or "AI"
                or "Settings" or "Logs" or "Console"))
            initialTab = null;

        if (registryRollback is not null)
            return RegistryRollbackService.ApplyEncoded(registryRollback);
        if (disableAlertService is not null)
            return ServiceRemediationService.ApplyDisableEncoded(
                disableAlertService);
        if (restoreAlertService is not null)
            return ServiceRemediationService.ApplyRestoreEncoded(
                restoreAlertService);
        if (install)   return RunInstall(quiet);
        if (uninstall) return RunUninstall(quiet);

        // ── First-run install prompt ────────────────────────────────────
        // Done BEFORE acquiring the mutex so the launched installed copy
        // does not race with this process for mutex ownership.
        if (!silent && !Installer.IsRunningFromInstallDir())
        {
            string? prompt = null;
            if (!Installer.IsAlreadyInstalled())
            {
                prompt =
                    $"Install {Installer.ProductName} {Installer.ProductVersion} to:\n\n" +
                    $"    {Installer.DefaultInstallDir}\n\n" +
                    "This adds the program to Windows Apps & Features so it can\n" +
                    "be uninstalled the normal way, and creates Start Menu and\n" +
                    "Desktop shortcuts.\n\n" +
                    "Click Yes to install, No to just run this copy once.";
            }
            else if (Installer.IsUpgradeAvailableForInstalledCopy(
                         out var installedVersion))
            {
                // Before v7.4.4 this branch did not exist: once anything was
                // installed, a newer .exe run from Downloads silently started
                // in portable mode and the installed copy — the one that
                // actually auto-starts at logon — stayed on the old build.
                prompt =
                    $"{Installer.ProductName} {installedVersion?.ToString(3)} is installed at:\n\n" +
                    $"    {Installer.DefaultInstallDir}\n\n" +
                    $"This copy is version {Installer.ProductVersion}.\n\n" +
                    "Click Yes to update the installed copy (it will be\n" +
                    "restarted), No to just run this copy once.";
            }

            if (prompt is not null)
            {
                var answer = MessageBox.Show(
                    prompt,
                    "Whitehat Security - Installer",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Question);

                if (answer == DialogResult.Cancel) return 0;
                if (answer == DialogResult.Yes)
                {
                    var rc = LaunchSelfElevated("--install");
                    if (rc != 0)
                    {
                        MessageBox.Show(
                            rc == -2
                                ? "Install was cancelled (UAC prompt declined)."
                                : $"Install failed (exit code {rc}). Check the Windows Application event log for details.",
                            "Whitehat Security",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        return rc;
                    }

                    // Install succeeded. Launch the installed copy in --silent
                    // mode so it goes straight to the system tray. We do NOT
                    // hold a single-instance mutex here, so there is no race
                    // for the launched copy to fight against.
                    var installed = Installer.DefaultInstallExePath;
                    if (File.Exists(installed))
                    {
                        try
                        {
                            Process.Start(new ProcessStartInfo(installed)
                            {
                                Arguments       = "--silent",
                                UseShellExecute = true,
                            });
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(
                                $"Installed but could not auto-launch:\n{ex.Message}\n\nLaunch it from the Start Menu.",
                                "Whitehat Security",
                                MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        }
                    }
                    return 0;
                }
            }
            // No / nothing to do → fall through and run from current location
        }

        // ── Single-instance mutex ───────────────────────────────────────
        using var mutex = new Mutex(initiallyOwned: true, MutexName, out bool createdNew);
        using var showEvent = new EventWaitHandle(
            false, EventResetMode.AutoReset, ShowEventName);
        if (!createdNew)
        {
            try { showEvent.Set(); } catch { }
            return 0;
        }

        // ── Resolve writable data directory ─────────────────────────────
        // Paths.DataDir falls back to %LOCALAPPDATA%\Whitehat Security
        // when the .exe lives in a read-only directory like Program Files.
        var configPath = Paths.ConfigPath;
        var logsDir    = Paths.LogsDir;

        // ── Load config + logger ────────────────────────────────────────
        var config       = NotifyConfig.LoadOrCreate(configPath);
        var logger       = new Logger(logsDir);
        var consoleSink  = new ConsoleSink();
        // Prune log files older than 30 days so the disk footprint stays
        // bounded over months of running. Best-effort — never throws.
        logger.CleanupOldLogs(30);
        logger.Info($"=== WhitehatSecurity {Installer.ProductVersion} starting (silent={silent}) ===");
        logger.Info($"Exe:         {Environment.ProcessPath}");
        logger.Info($"Data dir:    {Paths.DataDir}");
        logger.Info($"Config path: {configPath}");
        logger.Info($"Logs dir:    {logsDir}");
        consoleSink.WriteLine($"Whitehat Security {Installer.ProductVersion} starting (silent={silent})");
        consoleSink.WriteLine($"Data dir: {Paths.DataDir}");

        // ── Build the monitor host with every engine ────────────────────
        var host = new MonitorHost(config, logger, TimeSpan.FromSeconds(10));
        host.Register(new ConnectionEngine());
        host.Register(new ListenerEngine());
        host.Register(new ProcessEngine());
        host.Register(new DriverEngine());
        host.Register(new ServiceEngine());
        host.Register(new RegistryEngine(logger));
        host.Register(new HostsEngine());
        host.Register(new FirmwareEngine());
        host.Register(new RdpEngine());
        host.Register(new SecurityEventEngine(logger));
        // v7.3.0 — three new "AI" engines that re-use the existing P/Invoke
        // surface in NativeMethods.cs.
        host.Register(new HiddenProcessEngine());
        host.Register(new MemoryScannerEngine());
        host.Register(new ByovdEngine());

        // ── Tray context owns the message pump ──────────────────────────
        try
        {
            using var ctx = new TrayApplicationContext(
                config, logger, host, consoleSink, configPath, showEvent);
            if (!silent || initialTab is not null)
                ctx.OpenDashboard(initialTab);
            Application.Run(ctx);
        }
        catch (Exception ex)
        {
            logger.Error($"Fatal: {ex}");
            return 1;
        }
        finally
        {
            host.Dispose();
            logger.Info("=== WhitehatSecurity stopped ===");
        }

        return 0;
    }

    // ------------------------------------------------------------------------

    private static int RunInstall(bool quiet)
    {
        try
        {
            // Do not append privileged diagnostics to predictable files in
            // user temp: a planted link could redirect the write. Failures
            // still reach the installer dialog and process exit code.
            Installer.InstallElevated();
            if (!quiet)
                MessageBox.Show(
                    $"Installed to:\n{Installer.DefaultInstallDir}\n\n" +
                    "You can now uninstall via Settings > Apps > Apps & Features.",
                    "Whitehat Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            if (!quiet)
                MessageBox.Show($"Install failed:\n{ex.GetType().Name}: {ex.Message}",
                    "Whitehat Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private static int RunUninstall(bool quiet)
    {
        try
        {
            Installer.UninstallElevated();
            if (!quiet)
                MessageBox.Show(
                    $"{Installer.ProductName} has been removed.",
                    "Whitehat Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }
        catch (Exception ex)
        {
            if (!quiet)
                MessageBox.Show($"Uninstall failed:\n{ex.GetType().Name}: {ex.Message}",
                    "Whitehat Security",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }

    private static int LaunchSelfElevated(string arguments)
    {
        var self = Environment.ProcessPath
            ?? throw new InvalidOperationException("ProcessPath null");
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName        = self,
                Arguments       = arguments,
                Verb            = "runas",   // UAC
                UseShellExecute = true,
            };
            using var p = Process.Start(psi);
            if (p is null) return -1;
            if (!p.WaitForExit(120_000))
                return -3;
            return p.ExitCode;
        }
        catch (Exception)
        {
            // User denied UAC
            return -2;
        }
    }

    private static bool HasFlag(string[] args, params string[] aliases)
    {
        foreach (var a in args)
            foreach (var f in aliases)
                if (a.Equals(f, StringComparison.OrdinalIgnoreCase))
                    return true;
        return false;
    }

    private static string? GetOption(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
            if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
                return args[i + 1];
        return null;
    }
}
