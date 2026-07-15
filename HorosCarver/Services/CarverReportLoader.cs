using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HorosCarver.Services;

public static class CarverReportLoader
{
    public static CarverReportSummary? TryLoad(string outputDirectory)
    {
        var reportPath = Path.Combine(outputDirectory, "carving_report.json");
        if (!File.Exists(reportPath))
            return null;

        try
        {
            var json = File.ReadAllText(reportPath);
            var doc = JsonSerializer.Deserialize<CarverReportJson>(json);
            if (doc is null)
                return null;

            var rawTotal = doc.Raw?
                .Where(kv => !IsMetaKey(kv.Key))
                .Sum(kv => kv.Value) ?? 0;

            var recent = CollectRecentFiles(outputDirectory, 12);

            return new CarverReportSummary
            {
                FsRecovered = doc.Fs?.Recovered ?? 0,
                FsFound = doc.Fs?.Found ?? 0,
                RawTotal = rawTotal,
                ElapsedSeconds = doc.ElapsedS,
                SpeedBps = doc.SpeedBps,
                RecentFiles = recent,
            };
        }
        catch
        {
            return null;
        }
    }

    private static bool IsMetaKey(string key) =>
        key is "bad_sectors" or "hits_raw" or "invalid" or "too_small"
            or "dedup" or "entropy_skipped";

    private static List<RecoveredFileInfo> CollectRecentFiles(string outputDir, int max)
    {
        var root = Path.GetFullPath(outputDir);
        if (!Directory.Exists(root))
            return [];

        return Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Where(f => !f.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                        && !f.Contains(".xcarver_session", StringComparison.Ordinal))
            .Select(f => new FileInfo(f))
            .OrderByDescending(f => f.LastWriteTimeUtc)
            .Take(max)
            .Select(f => new RecoveredFileInfo
            {
                Name = f.Name,
                RelativePath = Path.GetRelativePath(root, f.FullName),
                SizeBytes = f.Length,
                Category = GuessCategory(f.FullName),
            })
            .ToList();
    }

    private static string GuessCategory(string path)
    {
        var parent = Path.GetDirectoryName(path)?.Replace('\\', '/');
        if (parent?.Contains("fs_recovered", StringComparison.OrdinalIgnoreCase) == true)
            return "FS";
        if (parent?.Contains("/raw/", StringComparison.OrdinalIgnoreCase) == true)
        {
            var part = parent.Split('/', '\\').LastOrDefault(s => s != "raw") ?? "raw";
            return part.ToUpperInvariant();
        }
        return "RAW";
    }

    private sealed class CarverReportJson
    {
        [JsonPropertyName("elapsed_s")]
        public double ElapsedS { get; set; }

        [JsonPropertyName("speed_bps")]
        public long SpeedBps { get; set; }

        [JsonPropertyName("fs")]
        public FsBlock? Fs { get; set; }

        [JsonPropertyName("raw")]
        public Dictionary<string, int>? Raw { get; set; }
    }

    private sealed class FsBlock
    {
        [JsonPropertyName("found")]
        public int Found { get; set; }

        [JsonPropertyName("recovered")]
        public int Recovered { get; set; }
    }
}

public sealed class CarverReportSummary
{
    public int FsRecovered { get; init; }
    public int FsFound { get; init; }
    public int RawTotal { get; init; }
    public double ElapsedSeconds { get; init; }
    public long SpeedBps { get; init; }
    public List<RecoveredFileInfo> RecentFiles { get; init; } = [];
}

public sealed class RecoveredFileInfo
{
    public required string Name { get; init; }
    public required string RelativePath { get; init; }
    public long SizeBytes { get; init; }
    public required string Category { get; init; }
}
