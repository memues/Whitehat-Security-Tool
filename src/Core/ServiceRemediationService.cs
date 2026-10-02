// SPDX-License-Identifier: MIT

using System;
using System.Collections.Generic;
using System.ServiceProcess;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace WhitehatSecurity.Core;

public sealed record ServiceStatePayload(
    string ServiceName,
    int StartMode,
    bool WasRunning,
    string? ImagePath)
{
    public string Encode()
        => Convert.ToBase64String(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this)));

    public static bool TryDecode(
        string encoded, out ServiceStatePayload? payload)
    {
        payload = null;
        try
        {
            payload = JsonSerializer.Deserialize<ServiceStatePayload>(
                Encoding.UTF8.GetString(
                    Convert.FromBase64String(encoded)));
            return payload is not null
                && IsValidServiceName(payload.ServiceName)
                && payload.StartMode is >= 0 and <= 4;
        }
        catch
        {
            return false;
        }
    }

    public static bool IsValidServiceName(string value)
        => !string.IsNullOrWhiteSpace(value)
            && value.Length <= 256
            && !value.Contains('\\')
            && !value.Contains('/')
            && !value.Contains('\0');
}

public sealed record ServiceRemediationResult(
    bool Success,
    string Message,
    string? RestorePayload = null);

public static class ServiceRemediationService
{
    public const int ExitInvalidPayload = 20;
    public const int ExitProtectedService = 21;
    public const int ExitMissingService = 22;
    public const int ExitFailure = 23;
    public const int ExitServiceChanged = 24;

    private static readonly HashSet<string> ProtectedServices =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "RpcSs", "DcomLaunch", "PlugPlay", "Power", "EventLog",
            "Winmgmt", "SamSs", "LSM", "ProfSvc", "Schedule", "CryptSvc",
            "Dhcp", "Dnscache", "nsi", "BFE", "mpssvc",
            "WinDefend", "WdNisSvc", "SecurityHealthService", "wscsvc",
            "Sense", "SgrmBroker", "AppIDSvc", "TrustedInstaller", "wuauserv",
        };

    // Earlier versions allowed deactivating these services. Keep a narrow
    // recovery path for their saved journals without allowing a restore
    // payload to disable a platform protection service.
    private static readonly HashSet<string> ReenableOnlyServices =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "WinDefend", "WdNisSvc", "SecurityHealthService", "wscsvc",
            "Sense", "SgrmBroker", "AppIDSvc", "TrustedInstaller", "wuauserv",
        };

    public static bool IsRestoreAllowed(string serviceName, int startMode)
        => ServiceStatePayload.IsValidServiceName(serviceName)
            && startMode is >= 0 and <= 4
            && (!ProtectedServices.Contains(serviceName)
                || (ReenableOnlyServices.Contains(serviceName) && startMode != 4));

    public static string Inspect(string serviceName)
    {
        if (!TryCapture(serviceName, out var payload, out var error))
            return error;

        try
        {
            using var service = new ServiceController(serviceName);
            return
                $"Service:      {service.ServiceName}{Environment.NewLine}" +
                $"Display name: {service.DisplayName}{Environment.NewLine}" +
                $"State:        {service.Status}{Environment.NewLine}" +
                $"Start mode:   {StartModeName(payload!.StartMode)}";
        }
        catch (Exception ex)
        {
            return $"Service inspection failed: {ex.Message}";
        }
    }

    public static ServiceRemediationResult Disable(
        string serviceName, Logger? logger = null)
    {
        if (!TryCapture(serviceName, out var state, out var error))
            return new ServiceRemediationResult(false, error);
        if (ProtectedServices.Contains(serviceName))
            return new ServiceRemediationResult(
                false, "This service is protected from automatic deactivation.");

        var encoded = state!.Encode();
        var rc = ElevationHelper.RunSelfElevated(
            $"--disable-alert-service {encoded}", logger, 45_000);
        return rc switch
        {
            0 => new ServiceRemediationResult(
                true,
                SaveRestoreState(state, out var journalWarning)
                    ? "The service was stopped where possible and disabled. A loaded driver may require a restart to unload."
                    : "The service was disabled, but its persistent restore journal could not be saved. Keep this application open if you may need to restore it. " + journalWarning,
                encoded),
            ExitProtectedService => new ServiceRemediationResult(
                false, "This service is protected from automatic deactivation."),
            ExitServiceChanged => new ServiceRemediationResult(
                false, "The service path changed during confirmation. The action was cancelled."),
            -2 or -3 => new ServiceRemediationResult(
                false, "Administrator approval was cancelled or unavailable."),
            _ => new ServiceRemediationResult(
                false, $"Service deactivation failed (exit {rc})."),
        };
    }

    public static ServiceRemediationResult Restore(
        string encoded, Logger? logger = null)
    {
        if (!ServiceStatePayload.TryDecode(encoded, out _))
            return new ServiceRemediationResult(
                false, "The saved service state is invalid.");
        var rc = ElevationHelper.RunSelfElevated(
            $"--restore-alert-service {encoded}", logger, 45_000);
        if (rc == 0)
        {
            if (ServiceStatePayload.TryDecode(encoded, out var state))
                TryDeleteJournal(state!.ServiceName);
            return new ServiceRemediationResult(
                true, "The original service start mode and running state were restored.");
        }
        return new ServiceRemediationResult(
            false, rc is -2 or -3
                ? "Administrator approval was cancelled or unavailable."
                : rc == ExitServiceChanged
                    ? "The service path changed after deactivation. Automatic restore was cancelled."
                    : $"Service restoration failed (exit {rc}).");
    }

    public static int ApplyDisableEncoded(string encoded)
    {
        if (!ServiceStatePayload.TryDecode(encoded, out var payload))
            return ExitInvalidPayload;
        if (ProtectedServices.Contains(payload!.ServiceName))
            return ExitProtectedService;
        if (!ServiceExists(payload.ServiceName))
            return ExitMissingService;

        try
        {
            if (!ServiceImagePathMatches(payload))
                return ExitServiceChanged;
            TryStop(payload.ServiceName);
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{payload.ServiceName}",
                writable: true);
            if (key is null) return ExitMissingService;
            key.SetValue("Start", 4, RegistryValueKind.DWord);
            return Convert.ToInt32(key.GetValue("Start", -1)) == 4
                ? 0
                : ExitFailure;
        }
        catch
        {
            return ExitFailure;
        }
    }

    public static int ApplyRestoreEncoded(string encoded)
    {
        if (!ServiceStatePayload.TryDecode(encoded, out var payload))
            return ExitInvalidPayload;
        if (!IsRestoreAllowed(payload!.ServiceName, payload.StartMode))
            return ExitProtectedService;
        if (!ServiceExists(payload!.ServiceName))
            return ExitMissingService;

        try
        {
            if (!ServiceImagePathMatches(payload))
                return ExitServiceChanged;
            using (var key = Registry.LocalMachine.OpenSubKey(
                       $@"SYSTEM\CurrentControlSet\Services\{payload.ServiceName}",
                       writable: true))
            {
                if (key is null) return ExitMissingService;
                key.SetValue(
                    "Start", payload.StartMode,
                    RegistryValueKind.DWord);
            }

            if (payload.WasRunning && payload.StartMode != 4)
            {
                try
                {
                    using var service =
                        new ServiceController(payload.ServiceName);
                    if (service.Status == ServiceControllerStatus.Stopped)
                    {
                        service.Start();
                        service.WaitForStatus(
                            ServiceControllerStatus.Running,
                            TimeSpan.FromSeconds(15));
                    }
                }
                catch
                {
                    // Boot/system drivers can only restart on reboot. The
                    // restored Start value is still the important rollback.
                }
            }

            using var verify = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{payload.ServiceName}");
            return Convert.ToInt32(verify?.GetValue("Start", -1))
                    == payload.StartMode
                ? 0
                : ExitFailure;
        }
        catch
        {
            return ExitFailure;
        }
    }

    private static bool TryCapture(
        string serviceName,
        out ServiceStatePayload? payload,
        out string error)
    {
        payload = null;
        error = "";
        if (!ServiceStatePayload.IsValidServiceName(serviceName))
        {
            error = "The service name is invalid.";
            return false;
        }
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{serviceName}");
            if (key is null)
            {
                error = "The service no longer exists.";
                return false;
            }
            var startMode = Convert.ToInt32(key.GetValue("Start", -1));
            if (startMode is < 0 or > 4)
            {
                error = "The service start mode could not be read.";
                return false;
            }

            var imagePath = key.GetValue(
                "ImagePath", null,
                RegistryValueOptions.DoNotExpandEnvironmentNames)
                ?.ToString();
            using var service = new ServiceController(serviceName);
            var running = service.Status is
                ServiceControllerStatus.Running
                or ServiceControllerStatus.StartPending
                or ServiceControllerStatus.PausePending
                or ServiceControllerStatus.Paused;
            payload = new ServiceStatePayload(
                serviceName, startMode, running, imagePath);
            return true;
        }
        catch (Exception ex)
        {
            error = $"Service inspection failed: {ex.Message}";
            return false;
        }
    }

    private static bool ServiceExists(string name)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                $@"SYSTEM\CurrentControlSet\Services\{name}");
            return key is not null;
        }
        catch { return false; }
    }

    public static string? FindRestorePayload(string serviceName)
    {
        if (!ServiceStatePayload.IsValidServiceName(serviceName))
            return null;
        try
        {
            var path = JournalPath(serviceName);
            if (!File.Exists(path)) return null;
            var encoded = File.ReadAllText(path).Trim();
            return ServiceStatePayload.TryDecode(
                    encoded, out var state)
                && string.Equals(
                    state!.ServiceName, serviceName,
                    StringComparison.OrdinalIgnoreCase)
                && ServiceImagePathMatches(state)
                ? encoded
                : null;
        }
        catch { return null; }
    }

    private static bool SaveRestoreState(
        ServiceStatePayload state, out string warning)
    {
        warning = "";
        try
        {
            Directory.CreateDirectory(Paths.RemediationDir);
            var path = JournalPath(state.ServiceName);
            var temp = path + ".tmp";
            File.WriteAllText(temp, state.Encode());
            File.Move(temp, path, overwrite: true);
            return true;
        }
        catch (Exception ex)
        {
            warning = ex.Message;
            return false;
        }
    }

    private static void TryDeleteJournal(string serviceName)
    {
        try { File.Delete(JournalPath(serviceName)); } catch { }
    }

    private static string JournalPath(string serviceName)
    {
        var hash = Convert.ToHexString(
            SHA256.HashData(
                Encoding.UTF8.GetBytes(
                    serviceName.ToUpperInvariant())));
        return Path.Combine(
            Paths.RemediationDir,
            "service-" + hash + ".state");
    }

    private static bool ServiceImagePathMatches(
        ServiceStatePayload payload)
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{payload.ServiceName}");
        var current = key?.GetValue(
            "ImagePath", null,
            RegistryValueOptions.DoNotExpandEnvironmentNames)
            ?.ToString();
        return string.Equals(
            current, payload.ImagePath,
            StringComparison.OrdinalIgnoreCase);
    }

    private static void TryStop(string name)
    {
        try
        {
            using var service = new ServiceController(name);
            if (service.Status is ServiceControllerStatus.Stopped
                or ServiceControllerStatus.StopPending)
                return;
            if (!service.CanStop) return;
            service.Stop();
            service.WaitForStatus(
                ServiceControllerStatus.Stopped,
                TimeSpan.FromSeconds(15));
        }
        catch
        {
            // Disabling startup is still useful if an in-use driver/service
            // cannot be stopped without a restart.
        }
    }

    private static string StartModeName(int value)
        => value switch
        {
            0 => "Boot",
            1 => "System",
            2 => "Automatic",
            3 => "Manual",
            4 => "Disabled",
            _ => $"Unknown ({value})",
        };
}
