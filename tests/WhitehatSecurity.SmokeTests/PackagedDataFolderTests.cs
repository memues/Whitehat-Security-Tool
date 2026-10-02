// SPDX-License-Identifier: MIT
using System.Text.Json;
using WhitehatSecurity.Core;

internal static class PackagedDataFolderTests
{
    public static void Run(Action<string, Action> run)
    {
        run("Packaged data path boundaries reject aliases and system-managed locations without writes", () =>
        {
            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var candidate = Path.Combine(profile, "whs-selection-test-" + Guid.NewGuid().ToString("N"));
            Equal(false, Directory.Exists(candidate));
            Equal(true, PackagedDataFolder.TryValidatePath(candidate, out var normalized, out _));
            Equal(candidate, normalized);
            Equal(false, Directory.Exists(candidate));

            foreach (var rejected in new string?[]
            {
                null, "", "relative-data", @"C:relative", @"C:\", @"\\server\share\data",
                @"\\?\C:\data", @"\??\C:\data", candidate + ":stream", candidate + ".",
                candidate + " ", candidate + @"\..\data", candidate + @"\.\data", profile,
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                Path.Combine(profile, "AppData", "LocalLow", "Whitehat"),
                AppContext.BaseDirectory,
                Path.Combine(Path.GetTempPath(), "Whitehat-unreliable-data"),
            })
                if (PackagedDataFolder.TryValidatePath(rejected, out _, out _))
                    throw new InvalidOperationException($"Unsafe data path was accepted: '{rejected}'.");
            Equal(false, Directory.Exists(candidate));

            var boundary = Path.Combine(profile, "SampleFolder");
            Equal(true, PackagedDataFolder.IsSameOrUnder(boundary.ToUpperInvariant(), boundary));
            Equal(true, PackagedDataFolder.IsSameOrUnder(Path.Combine(boundary, "child"), boundary));
            Equal(false, PackagedDataFolder.IsSameOrUnder(boundary + "Sibling", boundary));
            Equal(true, PackagedDataFolder.MatchesCanonicalDirectory(@"C:\Users\Example", @"\\?\C:\Users\EXAMPLE"));
            Equal(false, PackagedDataFolder.MatchesCanonicalDirectory(@"C:\PROGRA~1", @"\\?\C:\Program Files"));
            Equal(false, PackagedDataFolder.MatchesCanonicalDirectory(@"X:\Data", @"\\?\C:\Windows\Data"));
            Equal(false, PackagedDataFolder.MatchesCanonicalDirectory(@"C:\Data", @"\\?\UNC\server\share\Data"));
        });

        run("Packaged data selection pointers reject missing identity and unsafe or oversized metadata", () =>
        {
            var candidate = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "whs-pointer-test-" + Guid.NewGuid().ToString("N"));
            var id = Guid.NewGuid();
            string Pointer(int version, string directory, Guid directoryId)
                => JsonSerializer.Serialize(new { Version = version, Directory = directory, DirectoryId = directoryId });

            Equal(true, PackagedDataFolder.TryParseSelection(Pointer(1, candidate, id), out var selected, out var parsedId));
            Equal(candidate, selected);
            Equal(id, parsedId);
            foreach (var invalid in new[]
            {
                "{bad-json", "null", "{}", Pointer(2, candidate, id),
                Pointer(1, candidate, Guid.Empty), Pointer(1, "relative", id),
                Pointer(1, Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), id),
                Pointer(1, candidate, id) + new string(' ', 8193),
            })
                Equal(false, PackagedDataFolder.TryParseSelection(invalid, out _, out _));
            Equal(false, Directory.Exists(candidate));
        });

        run("Packaged recovery markers reopen existing identity and never repair corrupted records silently", () =>
        {
            var temporary = Path.Combine(Path.GetTempPath(), "whs-data-marker-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temporary);
            var marker = Path.Combine(temporary, ".whitehat-data-directory.json");
            var record = Path.Combine(temporary, "retained-recovery-record.txt");
            try
            {
                File.WriteAllText(record, "Existing recovery data must remain unchanged.");
                var id = Guid.NewGuid();
                var valid = JsonSerializer.Serialize(new { Version = 1, Product = "Whitehat Security Tool", DirectoryId = id });
                File.WriteAllText(marker, valid);
                Equal(true, PackagedDataFolder.TryReadDirectoryMarker(temporary, out var readId, out _));
                Equal(id, readId);
                Equal(valid, File.ReadAllText(marker));

                foreach (var invalid in new[]
                {
                    "{incomplete", "null", "{}",
                    JsonSerializer.Serialize(new { Version = 2, Product = "Whitehat Security Tool", DirectoryId = id }),
                    JsonSerializer.Serialize(new { Version = 1, Product = "Another app", DirectoryId = id }),
                    JsonSerializer.Serialize(new { Version = 1, Product = "Whitehat Security Tool", DirectoryId = Guid.Empty }),
                    valid + new string(' ', 8193),
                })
                {
                    File.WriteAllText(marker, invalid);
                    Equal(false, PackagedDataFolder.TryReadDirectoryMarker(temporary, out _, out _));
                    Equal(invalid, File.ReadAllText(marker));
                    Equal("Existing recovery data must remain unchanged.", File.ReadAllText(record));
                }
                File.Delete(marker);
                Equal(false, PackagedDataFolder.TryReadDirectoryMarker(temporary, out _, out _));
                Equal(false, File.Exists(marker));
            }
            finally
            {
                File.Delete(marker);
                File.Delete(record);
                Directory.Delete(temporary);
            }
        });
    }

    private static void Equal<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
            throw new InvalidOperationException($"Expected '{expected}', got '{actual}'.");
    }
}
