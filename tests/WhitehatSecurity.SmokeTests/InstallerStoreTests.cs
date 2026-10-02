// SPDX-License-Identifier: MIT
using System.ComponentModel;
using System.Diagnostics;
using WhitehatSecurity.Core;

internal static class InstallerStoreTests
{
    public static void Run(Action<string, Action> run)
    {
        run("Installer retains Windows error codes for unattended callers", () =>
        {
            Equal(740, InstallerExitCodes.FromException(new Win32Exception(740)));
            Equal(1223, InstallerExitCodes.FromException(new Win32Exception(1223)));
            Equal(5, InstallerExitCodes.FromException(new UnauthorizedAccessException()));
            Equal(87, InstallerExitCodes.FromException(new ArgumentException()));
            Equal(1460, InstallerExitCodes.FromException(new TimeoutException()));
            Equal(1603, InstallerExitCodes.FromException(new IOException()));
        });

        run("Installer targets the installed image and leaves portable copies alone", () =>
        {
            Equal(true, Installer.IsInstalledImagePath(Installer.DefaultInstallExePath));
            Equal(true, Installer.IsInstalledImagePath(Installer.DefaultInstallExePath.ToUpperInvariant()));
            Equal(false, Installer.IsInstalledImagePath(null));
            Equal(false, Installer.IsInstalledImagePath(Path.Combine(
                Path.GetTempPath(), "WhitehatSecurity.exe")));
            Equal(false, Installer.IsInstalledImagePath(Installer.DefaultInstallExePath + ".other"));
        });

        run("Uninstall helper waits for setup and its launcher before deleting an inert directory", () =>
        {
            var directory = NewTestDirectory();
            var marker = Path.Combine(directory, "keep-test-parent-running");
            var launcherMarker = Path.Combine(directory, "keep-test-launcher-running");
            Process? parent = null;
            Process? launcher = null;
            Process? cleanup = null;
            try
            {
                File.WriteAllText(marker, "test synchronization only");
                File.WriteAllText(launcherMarker, "test synchronization only");
                parent = StartPowerShell(ElevationHelper.BuildInlineArguments(
                    "while ([System.IO.File]::Exists(" +
                    ElevationHelper.BuildPathExpression(marker) +
                    ")) { Start-Sleep -Milliseconds 100 }"));
                launcher = StartPowerShell(ElevationHelper.BuildInlineArguments(
                    "while ([System.IO.File]::Exists(" +
                    ElevationHelper.BuildPathExpression(launcherMarker) +
                    ")) { Start-Sleep -Milliseconds 100 }"));
                cleanup = StartPowerShell(Installer.BuildSelfDeleteArguments(directory, parent.Id,
                    waitForLauncherProcessId: launcher.Id));
                Thread.Sleep(750);
                Equal(false, parent.HasExited);
                Equal(false, cleanup.HasExited);
                Equal(true, Directory.Exists(directory));

                File.Delete(marker);
                Wait(parent);
                Equal(false, cleanup.HasExited);
                Equal(true, Directory.Exists(directory));
                File.Delete(launcherMarker);
                Wait(launcher);
                Wait(cleanup);
                Equal(0, cleanup.ExitCode);
                Equal(false, Directory.Exists(directory));
            }
            finally
            {
                try { File.Delete(marker); } catch { }
                try { File.Delete(launcherMarker); } catch { }
                Stop(cleanup);
                Stop(parent);
                Stop(launcher);
                if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            }
        });

        run("Uninstall helper recovers after a temporary file lock", () =>
        {
            var directory = NewTestDirectory();
            Process? cleanup = null;
            try
            {
                var lockedPath = Path.Combine(directory, "locked.txt");
                using (var locked = new FileStream(lockedPath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    cleanup = StartPowerShell(Installer.BuildSelfDeleteArguments(directory));
                    Thread.Sleep(1500);
                    Equal(false, cleanup.HasExited);
                    Equal(true, File.Exists(lockedPath));
                }
                Wait(cleanup);
                Equal(0, cleanup.ExitCode);
                Equal(false, Directory.Exists(directory));
            }
            finally
            {
                Stop(cleanup);
                if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
            }
        });

        run("Uninstall test paths cannot remove application registration", () =>
        {
            var directory = Path.Combine(Path.GetTempPath(), "whs-inert-cleanup");
            Throws<ArgumentException>(() => Installer.BuildSelfDeleteArguments(
                directory, removeUninstallRegistration: true));
            Throws<ArgumentOutOfRangeException>(() => Installer.BuildSelfDeleteArguments(directory, -1));
            Throws<ArgumentOutOfRangeException>(() => Installer.BuildSelfDeleteArguments(directory,
                waitForLauncherProcessId: -1));
        });

        run("Protected security services allow legacy recovery but cannot be disabled", () =>
        {
            foreach (var service in new[] { "WinDefend", "WdNisSvc", "SecurityHealthService", "wscsvc",
                "Sense", "SgrmBroker", "AppIDSvc", "TrustedInstaller", "wuauserv" })
            {
                for (var startMode = 0; startMode < 4; startMode++)
                    Equal(true, ServiceRemediationService.IsRestoreAllowed(service, startMode));
                Equal(false, ServiceRemediationService.IsRestoreAllowed(service, 4));
                // The deny check precedes service lookup and cannot mutate
                // a service, even if this test runs on an elevated CI agent.
                Equal(ServiceRemediationService.ExitProtectedService,
                    ServiceRemediationService.ApplyDisableEncoded(
                        new ServiceStatePayload(service, 3, false, null).Encode()));
                Equal(ServiceRemediationService.ExitProtectedService,
                    ServiceRemediationService.ApplyRestoreEncoded(
                        new ServiceStatePayload(service, 4, false, null).Encode()));
            }
            Equal(true, ServiceRemediationService.IsRestoreAllowed("WINDEFEND", 2));
            Equal(false, ServiceRemediationService.IsRestoreAllowed("RpcSs", 2));
            Equal(false, ServiceRemediationService.IsRestoreAllowed("WinDefend", -1));
            Equal(false, ServiceRemediationService.IsRestoreAllowed("WinDefend", 5));
            Equal(false, ServiceRemediationService.IsRestoreAllowed("invalid/name", 2));
        });
    }

    private static string NewTestDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "whs-store-installer-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }

    private static Process StartPowerShell(string arguments) => Process.Start(new ProcessStartInfo
    {
        FileName = ElevationHelper.PowerShellPath,
        Arguments = arguments,
        UseShellExecute = false,
        CreateNoWindow = true,
        WindowStyle = ProcessWindowStyle.Hidden,
    }) ?? throw new InvalidOperationException("Could not start the inert cleanup test.");

    private static void Wait(Process process)
    {
        if (!process.WaitForExit(20_000))
            throw new TimeoutException("Inert cleanup test timed out.");
    }

    private static void Stop(Process? process)
    {
        if (process is null) return;
        try { if (!process.HasExited) process.Kill(); } catch { }
        process.Dispose();
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
    }

    private static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
}
