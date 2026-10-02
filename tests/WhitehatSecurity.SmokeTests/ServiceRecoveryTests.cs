// SPDX-License-Identifier: MIT
using WhitehatSecurity.Core;

internal static class ServiceRecoveryTests
{
    public static void Run(Action<string, Action> run)
    {
        run("Service deactivation saves durable recovery before invoking any privileged action", () =>
        {
            InTemporaryDirectory(directory =>
            {
                var original = new ServiceStatePayload("WhitehatSyntheticService", 3, true, @"C:\Example\synthetic.exe");
                var invoked = 0;
                var result = ServiceRemediationService.ExecuteDisableWithRecovery(original, directory, encoded =>
                {
                    invoked++;
                    Equal(original.Encode(), encoded);
                    var path = Directory.GetFiles(directory, "service-*.state").Single();
                    Equal(original.Encode(), File.ReadAllText(path));
                    return 0;
                });
                Equal(true, result.Success);
                Equal(1, invoked);
                Equal(original.Encode(), result.RestorePayload);
                Equal(1, Directory.GetFiles(directory, "service-*.state").Length);
            });
        });

        run("Service deactivation stops before elevation when the journal cannot be written or existing state conflicts", () =>
        {
            InTemporaryDirectory(directory =>
            {
                var original = new ServiceStatePayload("WhitehatSyntheticService", 3, true, @"C:\Example\synthetic.exe");
                var invoked = false;
                var blocker = Path.Combine(directory, "not-a-directory");
                File.WriteAllText(blocker, "Retain this file.");
                var unwritable = ServiceRemediationService.ExecuteDisableWithRecovery(original, blocker,
                    _ => { invoked = true; return 0; });
                Equal(false, unwritable.Success);
                Equal(false, invoked);
                Equal("Retain this file.", File.ReadAllText(blocker));

                var first = ServiceRemediationService.ExecuteDisableWithRecovery(original, directory, _ => -3);
                Equal(false, first.Success);
                var path = Directory.GetFiles(directory, "service-*.state").Single();
                foreach (var saved in new[] { "broken-record", (original with { StartMode = 2 }).Encode(),
                             (original with { ImagePath = @"C:\Changed\other.exe" }).Encode() })
                {
                    File.WriteAllText(path, saved);
                    var rejected = ServiceRemediationService.ExecuteDisableWithRecovery(original, directory,
                        _ => { invoked = true; return 0; });
                    Equal(false, rejected.Success);
                    Equal(false, invoked);
                    Equal(saved, File.ReadAllText(path));
                }
            });
        });

        run("Service cancellation and partial failures retain original recovery across retries", () =>
        {
            InTemporaryDirectory(directory =>
            {
                var original = new ServiceStatePayload("WhitehatSyntheticService", 3, true, @"C:\Example\synthetic.exe");
                foreach (var exitCode in new[] { -3, -2, ServiceRemediationService.ExitFailure })
                {
                    var result = ServiceRemediationService.ExecuteDisableWithRecovery(original, directory, _ => exitCode);
                    Equal(false, result.Success);
                    Equal(original.Encode(), result.RestorePayload);
                    Equal(original.Encode(), File.ReadAllText(Directory.GetFiles(directory, "service-*.state").Single()));
                }
                var exception = ServiceRemediationService.ExecuteDisableWithRecovery(original, directory,
                    _ => throw new IOException("Synthetic launch outcome failure."));
                Equal(false, exception.Success);
                Equal(original.Encode(), exception.RestorePayload);

                var alreadyDisabled = original with { StartMode = 4, WasRunning = false };
                var repeated = ServiceRemediationService.ExecuteDisableWithRecovery(alreadyDisabled, directory, encoded =>
                {
                    Equal(alreadyDisabled.Encode(), encoded);
                    return 0;
                });
                Equal(true, repeated.Success);
                Equal(original.Encode(), repeated.RestorePayload);
                Equal(original.Encode(), File.ReadAllText(Directory.GetFiles(directory, "service-*.state").Single()));
            });
        });
    }

    private static void InTemporaryDirectory(Action<string> test)
    {
        var directory = Path.Combine(Path.GetTempPath(), "whs-service-journal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try { test(directory); }
        finally
        {
            // Tests create only direct inert files, never services or subtrees.
            foreach (var file in Directory.GetFiles(directory)) File.Delete(file);
            Directory.Delete(directory);
        }
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
    }
}
