// SPDX-License-Identifier: MIT

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;

namespace WhitehatSecurity.Core;

public sealed record QuarantineRecord(
    string Id,
    string OriginalPath,
    string QuarantinePath,
    string Sha256,
    DateTime CreatedUtc);

public sealed record QuarantineResult(
    bool Success,
    string Message,
    QuarantineRecord? Record = null);

/// <summary>
/// Recoverable file quarantine. Files are moved under the application's
/// user-data directory and accompanied by a metadata manifest. Windows and
/// application binaries are deliberately excluded; loaded drivers should be
/// disabled through their service entry instead of moving an in-use system
/// file.
/// </summary>
public static class QuarantineManager
{
    private static readonly JsonSerializerOptions JsonOptions =
        new() { WriteIndented = true };

    public static QuarantineResult Quarantine(string rawPath)
    {
        var path = ThreatPath.Normalize(rawPath);
        if (path is null || !File.Exists(path))
            return new QuarantineResult(false, "The file no longer exists.");
        if (ThreatPath.IsProtectedSystemPath(path))
            return new QuarantineResult(
                false,
                "System and application files cannot be moved. Disable the associated driver or service instead.");
        if (ThreatPath.ContainsReparsePoint(path)
            || ThreatPath.ContainsReparsePoint(Paths.QuarantineDir))
            return new QuarantineResult(false, "Quarantine paths must not pass through links or junctions.");

        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                return new QuarantineResult(
                    false, "Reparse-point files are not quarantined automatically.");

            Directory.CreateDirectory(Paths.QuarantineDir);
            var id = Guid.NewGuid().ToString("N");
            var quarantinePath = Path.Combine(Paths.QuarantineDir, id + ".quarantine");
            var manifestPath = Path.Combine(Paths.QuarantineDir, id + ".json");
            var sha256 = ComputeSha256(path);
            var record = new QuarantineRecord(
                id, path, quarantinePath, sha256, DateTime.UtcNow);
            WriteManifestAtomic(manifestPath, record);
            try
            {
                File.Move(path, quarantinePath);
                if (File.Exists(path) || !File.Exists(quarantinePath))
                    throw new IOException("Post-move verification failed.");
            }
            catch
            {
                TryDelete(manifestPath);
                throw;
            }
            return new QuarantineResult(
                true, $"File moved to recoverable quarantine ({id}).", record);
        }
        catch (UnauthorizedAccessException)
        {
            return new QuarantineResult(
                false,
                "Access was denied. Protected system locations must be remediated through the associated service or driver.");
        }
        catch (Exception ex)
        {
            return new QuarantineResult(false, $"Quarantine failed: {ex.Message}");
        }
    }

    public static QuarantineResult Restore(QuarantineRecord record)
    {
        if (!IsValidRecord(record, out var error))
            return new QuarantineResult(false, error);
        if (!File.Exists(record.QuarantinePath))
            return new QuarantineResult(false, "The quarantined copy is missing.");
        if (File.Exists(record.OriginalPath))
            return new QuarantineResult(
                false, "Restore cancelled because a file already exists at the original path.");

        try
        {
            if (!string.Equals(ComputeSha256(record.QuarantinePath), record.Sha256,
                    StringComparison.OrdinalIgnoreCase))
                return new QuarantineResult(false, "The quarantined file changed. Restore was cancelled.");
            var directory = Path.GetDirectoryName(record.OriginalPath);
            if (string.IsNullOrWhiteSpace(directory))
                return new QuarantineResult(false, "The original directory is invalid.");
            Directory.CreateDirectory(directory);
            File.Move(record.QuarantinePath, record.OriginalPath);
            if (!File.Exists(record.OriginalPath)
                || File.Exists(record.QuarantinePath))
                throw new IOException("Post-restore verification failed.");

            TryDelete(ManifestPath(record.Id));
            return new QuarantineResult(
                true, $"File restored to {record.OriginalPath}.", record);
        }
        catch (Exception ex)
        {
            return new QuarantineResult(false, $"Restore failed: {ex.Message}");
        }
    }

    public static QuarantineResult DeletePermanently(QuarantineRecord record)
    {
        if (!IsValidRecord(record, out var error))
            return new QuarantineResult(false, error);

        try
        {
            if (File.Exists(record.QuarantinePath))
                File.Delete(record.QuarantinePath);
            if (File.Exists(record.QuarantinePath))
                throw new IOException("Post-delete verification failed.");
            TryDelete(ManifestPath(record.Id));
            return new QuarantineResult(
                true, "The quarantined copy was permanently deleted.");
        }
        catch (Exception ex)
        {
            return new QuarantineResult(
                false, $"Permanent deletion failed: {ex.Message}");
        }
    }

    public static QuarantineRecord? FindByOriginalPath(string rawPath)
    {
        var path = ThreatPath.Normalize(rawPath);
        if (path is null || !Directory.Exists(Paths.QuarantineDir))
            return null;

        foreach (var manifest in Directory.EnumerateFiles(
                     Paths.QuarantineDir, "*.json",
                     SearchOption.TopDirectoryOnly))
        {
            try
            {
                var record = JsonSerializer.Deserialize<QuarantineRecord>(
                    File.ReadAllText(manifest), JsonOptions);
                if (record is not null
                    && string.Equals(
                        record.OriginalPath, path,
                        StringComparison.OrdinalIgnoreCase)
                    && IsValidRecord(record, out _)
                    && File.Exists(record.QuarantinePath))
                    return record;
            }
            catch { }
        }
        return null;
    }

    private static bool IsValidRecord(
        QuarantineRecord record, out string error)
    {
        error = "";
        if (string.IsNullOrEmpty(record.Id) || record.Id.Length != 32
            || !record.Id.All(Uri.IsHexDigit))
        {
            error = "The quarantine record ID is invalid.";
            return false;
        }

        try
        {
            var expected = Path.GetFullPath(
                Path.Combine(Paths.QuarantineDir, record.Id + ".quarantine"));
            if (!string.Equals(
                    expected, Path.GetFullPath(record.QuarantinePath),
                    StringComparison.OrdinalIgnoreCase))
            {
                error = "The quarantine record path failed validation.";
                return false;
            }
            if (!Path.IsPathFullyQualified(record.OriginalPath)
                || string.IsNullOrEmpty(record.Sha256) || record.Sha256.Length != 64
                || !record.Sha256.All(Uri.IsHexDigit)
                || ThreatPath.ContainsReparsePoint(record.QuarantinePath)
                || ThreatPath.ContainsReparsePoint(record.OriginalPath)
                || ThreatPath.ContainsReparsePoint(ManifestPath(record.Id)))
            {
                error = "The quarantine record contains an unsafe path or invalid hash.";
                return false;
            }
            if (ThreatPath.IsProtectedSystemPath(record.OriginalPath))
            {
                error = "Restoring into a protected system path is not allowed.";
                return false;
            }
            return true;
        }
        catch
        {
            error = "The quarantine record contains an invalid path.";
            return false;
        }
    }

    private static string ComputeSha256(string path)
    {
        using var stream = new FileStream(
            path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void WriteManifestAtomic(
        string manifestPath, QuarantineRecord record)
    {
        var tempPath = manifestPath + ".tmp";
        File.WriteAllText(tempPath, JsonSerializer.Serialize(record, JsonOptions));
        File.Move(tempPath, manifestPath);
    }

    private static string ManifestPath(string id)
        => Path.Combine(Paths.QuarantineDir, id + ".json");

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { }
    }
}
