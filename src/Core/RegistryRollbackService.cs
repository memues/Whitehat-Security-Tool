// SPDX-License-Identifier: MIT

using System;
using System.Globalization;
using System.Security;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace WhitehatSecurity.Core;

public sealed record RegistryValueSnapshot(
    bool Exists,
    RegistryValueKind Kind,
    string Data)
{
    public static RegistryValueSnapshot Missing { get; } =
        new(false, RegistryValueKind.None, "");

    public static RegistryValueSnapshot Capture(
        RegistryKey key, string valueName)
    {
        if (!Array.Exists(
                key.GetValueNames(),
                name => string.Equals(
                    name, valueName,
                    StringComparison.OrdinalIgnoreCase)))
            return Missing;

        var kind = key.GetValueKind(valueName);
        var value = key.GetValue(
            valueName, null,
            RegistryValueOptions.DoNotExpandEnvironmentNames);
        return new RegistryValueSnapshot(true, kind, Serialize(kind, value));
    }

    public object ToRegistryValue()
        => Kind switch
        {
            RegistryValueKind.Binary =>
                Convert.FromBase64String(Data),
            RegistryValueKind.MultiString =>
                JsonSerializer.Deserialize<string[]>(Data)
                    ?? Array.Empty<string>(),
            RegistryValueKind.DWord =>
                int.Parse(Data, NumberStyles.Integer, CultureInfo.InvariantCulture),
            RegistryValueKind.QWord =>
                long.Parse(Data, NumberStyles.Integer, CultureInfo.InvariantCulture),
            _ => Data,
        };

    public string ToDisplayText()
    {
        if (!Exists) return "(missing)";
        var value = Kind == RegistryValueKind.Binary
            ? $"<{Convert.FromBase64String(Data).Length} binary bytes>"
            : Kind == RegistryValueKind.MultiString
                ? string.Join("; ", JsonSerializer.Deserialize<string[]>(Data)
                    ?? Array.Empty<string>())
                : Data;
        if (value.Length > 240) value = value[..240] + "...";
        return $"{value} [{Kind}]";
    }

    private static string Serialize(
        RegistryValueKind kind, object? value)
        => kind switch
        {
            RegistryValueKind.Binary =>
                Convert.ToBase64String(value as byte[] ?? Array.Empty<byte>()),
            RegistryValueKind.MultiString =>
                JsonSerializer.Serialize(value as string[] ?? Array.Empty<string>()),
            RegistryValueKind.DWord =>
                Convert.ToInt32(value, CultureInfo.InvariantCulture)
                    .ToString(CultureInfo.InvariantCulture),
            RegistryValueKind.QWord =>
                Convert.ToInt64(value, CultureInfo.InvariantCulture)
                    .ToString(CultureInfo.InvariantCulture),
            _ => value?.ToString() ?? "",
        };
}

public sealed record RegistryChangePayload(
    RegistryHive Hive,
    RegistryView View,
    string KeyPath,
    string ValueName,
    string ChangeKind,
    RegistryValueSnapshot Before,
    RegistryValueSnapshot After)
{
    public string Encode()
        => Convert.ToBase64String(
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(this)));

    public RegistryChangePayload Reverse()
        => this with
        {
            ChangeKind = "reapply",
            Before = After,
            After = Before,
        };

    public static bool TryDecode(
        string encoded, out RegistryChangePayload? payload)
    {
        payload = null;
        try
        {
            var json = Encoding.UTF8.GetString(
                Convert.FromBase64String(encoded));
            payload = JsonSerializer.Deserialize<RegistryChangePayload>(json);
            return payload is not null && payload.IsValid();
        }
        catch
        {
            return false;
        }
    }

    private bool IsValid()
        => Hive is RegistryHive.LocalMachine or RegistryHive.CurrentUser
            && View is RegistryView.Registry32 or RegistryView.Registry64
            && !string.IsNullOrWhiteSpace(KeyPath)
            && KeyPath.Length <= 1024
            && !KeyPath.Contains('\0')
            && !string.IsNullOrWhiteSpace(ValueName)
            && ValueName.Length <= 16383
            && !ValueName.Contains('\0');
}

public sealed record RegistryRollbackResult(
    bool Success,
    bool Conflict,
    string Message);

public static class RegistryRollbackService
{
    public const string PayloadMetadataKey = "_RegistryChangePayload";
    public const int ExitConflict = 10;
    public const int ExitInvalidPayload = 11;
    public const int ExitFailure = 12;
    public const int ExitUnsupportedPolicy = 13;
    private const string UnsupportedPolicyMessage =
        "This edition supports registry rollback only for Windows Run and RunOnce startup entries. " +
        "Restore other Windows settings with their supported Windows controls.";

    /// <summary>
    /// Exact startup-key allowlist for the Store edition. Do not normalize
    /// separators or trim input: alternate spellings must not widen it.
    /// </summary>
    public static bool IsStoreRollbackPath(string? keyPath)
        => string.Equals(keyPath, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                StringComparison.OrdinalIgnoreCase)
            || string.Equals(keyPath, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                StringComparison.OrdinalIgnoreCase);

    private static bool IsSupportedRollback(RegistryChangePayload payload)
    {
#if STORE_BUILD
        return IsStoreRollbackPath(payload.KeyPath);
#else
        return true;
#endif
    }

    public static bool CanRollback(Alert alert)
        => alert.Extra is not null
            && alert.Extra.TryGetValue(
                PayloadMetadataKey, out var encoded)
            && RegistryChangePayload.TryDecode(encoded, out var payload)
            && IsSupportedRollback(payload!);

    public static string Inspect(Alert alert)
    {
        if (!TryGetPayload(alert, out _, out var payload))
            return "This alert does not contain typed registry change metadata.";
        if (!IsSupportedRollback(payload!))
            return UnsupportedPolicyMessage;

        try
        {
            var change = payload!;
            var current = CaptureCurrent(change);
            return
                $"Registry key: {HiveName(change.Hive)}\\{change.KeyPath}{Environment.NewLine}" +
                $"View:         {(change.View == RegistryView.Registry32 ? "32-bit" : "64-bit")}{Environment.NewLine}" +
                $"Value:        {change.ValueName}{Environment.NewLine}" +
                $"Detected:     {change.After.ToDisplayText()}{Environment.NewLine}" +
                $"Current:      {current.ToDisplayText()}{Environment.NewLine}" +
                $"Rollback to:  {change.Before.ToDisplayText()}";
        }
        catch (Exception ex)
        {
            return $"Registry inspection failed: {ex.Message}";
        }
    }

    public static RegistryRollbackResult Rollback(
        Alert alert, Logger? logger = null)
    {
        if (!TryGetPayload(alert, out var encoded, out var payload))
            return new RegistryRollbackResult(
                false, false, "Typed rollback metadata is unavailable.");

        // Reject unsupported targets before requesting elevation or reading
        // the registry, including payloads loaded from older alert history.
        if (!IsSupportedRollback(payload!))
            return FromExitCode(ExitUnsupportedPolicy);

        if (payload!.Hive == RegistryHive.LocalMachine)
        {
            var rc = ElevationHelper.RunSelfElevated(
                $"--apply-registry-rollback {encoded}", logger);
            return FromExitCode(rc);
        }

        var code = ApplyEncoded(encoded!);
        return FromExitCode(code);
    }

    /// <summary>
    /// Runs in the elevated helper process. It performs optimistic
    /// concurrency checking before changing anything.
    /// </summary>
    public static int ApplyEncoded(string encoded)
    {
        if (!RegistryChangePayload.TryDecode(encoded, out var payload))
            return ExitInvalidPayload;
        if (!IsSupportedRollback(payload!))
            return ExitUnsupportedPolicy;
        try
        {
            var current = CaptureCurrent(payload!);
            if (current != payload!.After)
                return ExitConflict;

            using var root = RegistryKey.OpenBaseKey(
                payload.Hive, payload.View);
            if (payload.Before.Exists)
            {
                using var key = root.CreateSubKey(
                    payload.KeyPath, writable: true);
                if (key is null) return ExitFailure;
                key.SetValue(
                    payload.ValueName,
                    payload.Before.ToRegistryValue(),
                    payload.Before.Kind);
            }
            else
            {
                using var key = root.OpenSubKey(
                    payload.KeyPath, writable: true);
                key?.DeleteValue(
                    payload.ValueName, throwOnMissingValue: false);
            }

            return CaptureCurrent(payload) == payload.Before
                ? 0
                : ExitFailure;
        }
        catch (UnauthorizedAccessException)
        {
            return ExitFailure;
        }
        catch (SecurityException)
        {
            return ExitFailure;
        }
        catch
        {
            return ExitFailure;
        }
    }

    private static RegistryValueSnapshot CaptureCurrent(
        RegistryChangePayload payload)
    {
        using var root = RegistryKey.OpenBaseKey(
            payload.Hive, payload.View);
        using var key = root.OpenSubKey(payload.KeyPath);
        return key is null
            ? RegistryValueSnapshot.Missing
            : RegistryValueSnapshot.Capture(key, payload.ValueName);
    }

    private static bool TryGetPayload(
        Alert alert,
        out string? encoded,
        out RegistryChangePayload? payload)
    {
        encoded = null;
        payload = null;
        return alert.Extra is not null
            && alert.Extra.TryGetValue(
                PayloadMetadataKey, out encoded)
            && RegistryChangePayload.TryDecode(
                encoded, out payload);
    }

    private static RegistryRollbackResult FromExitCode(int code)
        => code switch
        {
            0 => new RegistryRollbackResult(
                true, false, "The detected registry change was rolled back and verified."),
            ExitConflict => new RegistryRollbackResult(
                false, true,
                "Rollback cancelled: the current value changed again after this alert."),
            ExitUnsupportedPolicy => new RegistryRollbackResult(
                false, false, UnsupportedPolicyMessage),
            -2 or -3 => new RegistryRollbackResult(
                false, false, "Administrator approval was cancelled or unavailable."),
            _ => new RegistryRollbackResult(
                false, false, $"Registry rollback failed (exit {code})."),
        };

    public static string HiveName(RegistryHive hive)
        => hive switch
        {
            RegistryHive.LocalMachine => "HKEY_LOCAL_MACHINE",
            RegistryHive.CurrentUser => "HKEY_CURRENT_USER",
            _ => hive.ToString(),
        };
}
