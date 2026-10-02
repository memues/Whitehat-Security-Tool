// SPDX-License-Identifier: MIT
using Microsoft.Win32;
using WhitehatSecurity.Core;

internal static class RegistryStoreTests
{
    public static void Run(Action<string, Action> run)
    {
        run("Store registry rollback accepts only exact Windows startup key paths", () =>
        {
            const string runKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
            Equal(true, RegistryRollbackService.IsStoreRollbackPath(runKey));
            Equal(true, RegistryRollbackService.IsStoreRollbackPath(runKey.ToLowerInvariant()));
            Equal(true, RegistryRollbackService.IsStoreRollbackPath(runKey + "Once"));
            foreach (var rejected in new string?[]
            {
                null, "", " " + runKey, runKey + " ", "\\" + runKey,
                runKey + "\\", runKey + "\\Child", runKey + "OnceEx",
                runKey.Replace('\\', '/'), runKey.Replace("\\", "\\\\"),
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\.\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\..\Run",
                @"HKEY_LOCAL_MACHINE\" + runKey,
            })
                Equal(false, RegistryRollbackService.IsStoreRollbackPath(rejected));
        });

#if STORE_BUILD
        run("Store registry rollback rejects Windows security targets before accessing the registry", () =>
        {
            var targets = new[]
            {
                (@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA"),
                (@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall"),
                (@"SYSTEM\CurrentControlSet\Services\WinDefend", "Start"),
                (@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run\", "SyntheticTestValue"),
            };
            foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            foreach (var (path, valueName) in targets)
            {
                // Missing snapshots ensure a broken guard still cannot
                // replace a real security value: optimistic concurrency
                // would reject an existing value. No setup/registry write
                // is intentionally exercised by this policy test.
                var payload = new RegistryChangePayload(hive, view, path, valueName,
                    "changed", RegistryValueSnapshot.Missing, RegistryValueSnapshot.Missing);
                var encoded = payload.Encode();
                Equal(RegistryRollbackService.ExitUnsupportedPolicy,
                    RegistryRollbackService.ApplyEncoded(encoded));
                var alert = new Alert(DateTime.Now, "Registry", "Synthetic policy test",
                    "No system setting should be accessed", AlertSeverity.Info,
                    Extra: new Dictionary<string, string>
                    {
                        [RegistryRollbackService.PayloadMetadataKey] = encoded,
                    });
                Equal(false, RegistryRollbackService.CanRollback(alert));
                var result = RegistryRollbackService.Rollback(alert);
                Equal(false, result.Success);
                Equal(false, result.Conflict);
                Contains("only for Windows Run and RunOnce", result.Message);
                Contains("only for Windows Run and RunOnce", RegistryRollbackService.Inspect(alert));
            }
        });
#endif
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
    }

    private static void Contains(string expected, string actual)
    {
        if (!actual.Contains(expected, StringComparison.Ordinal))
            throw new InvalidOperationException($"Expected message to contain '{expected}'.");
    }
}
