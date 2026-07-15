using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using HorosCarver.Models;

namespace HorosCarver.Services;

public sealed class CarverService
{
    public string? FindCarverScript()
    {
        var candidates = new List<string>();

        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 6 && !string.IsNullOrEmpty(dir); i++)
        {
            candidates.Add(Path.Combine(dir, "carver.py"));
            dir = Path.GetDirectoryName(dir);
        }

        var cwd = Directory.GetCurrentDirectory();
        candidates.Add(Path.Combine(cwd, "carver.py"));
        candidates.Add(Path.Combine(cwd, "..", "carver.py"));

        return candidates
            .Select(Path.GetFullPath)
            .Distinct()
            .FirstOrDefault(File.Exists);
    }

    public async Task<IReadOnlyList<DeviceInfo>> ListDevicesAsync(
        CancellationToken cancellationToken = default)
    {
        var script = FindCarverScript()
            ?? throw new FileNotFoundException("carver.py nicht gefunden.");

        var psi = new ProcessStartInfo
        {
            FileName = "python",
            Arguments = $"\"{script}\" --list-devices-json",
            WorkingDirectory = Path.GetDirectoryName(script) ?? Directory.GetCurrentDirectory(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Geräteliste konnte nicht gestartet werden.");

        var stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderr = await process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);

        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(stderr)
                    ? $"Geräteliste fehlgeschlagen (Code {process.ExitCode})."
                    : stderr.Trim());

        if (string.IsNullOrWhiteSpace(stdout))
            return Array.Empty<DeviceInfo>();

        return JsonSerializer.Deserialize<List<DeviceInfo>>(stdout) ?? [];
    }

    public async Task<int> RunAsync(
        CarverRunOptions options,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var script = FindCarverScript()
            ?? throw new FileNotFoundException("carver.py nicht gefunden.");

        var args = BuildArguments(script, options);
        var psi = new ProcessStartInfo
        {
            FileName = "python",
            Arguments = args,
            WorkingDirectory = Path.GetDirectoryName(script) ?? cwdFallback(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        using var process = new Process { StartInfo = psi, EnableRaisingEvents = true };

        process.OutputDataReceived += (_, e) =>
        {
            if (!string.IsNullOrEmpty(e.Data))
                progress?.Report(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (!string.IsNullOrEmpty(e.Data))
                progress?.Report(e.Data);
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        await using var reg = cancellationToken.Register(() =>
        {
            try
            {
                if (!process.HasExited)
                    process.Kill(entireProcessTree: true);
            }
            catch
            {
                // ignore
            }
        });

        try
        {
            await process.WaitForExitAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
            {
                try { process.Kill(entireProcessTree: true); } catch { /* ignore */ }
            }
            throw;
        }

        cancellationToken.ThrowIfCancellationRequested();
        return process.ExitCode;

        static string cwdFallback() => Directory.GetCurrentDirectory();
    }

    internal static string BuildArguments(string script, CarverRunOptions o)
    {
        var sb = new StringBuilder();
        sb.Append('"').Append(script).Append('"');
        sb.Append(" \"").Append(o.SourcePath.Replace("\"", "\\\"")).Append('"');
        sb.Append(" -o \"").Append(o.OutputDirectory.Replace("\"", "\\\"")).Append('"');
        sb.Append(" --threads ").Append(o.ThreadCount);

        if (o.FsOnly)
            sb.Append(" --fs-only");
        else if (o.RawOnly)
            sb.Append(" --raw-only");

        if (!string.IsNullOrWhiteSpace(o.TypeFilter))
            sb.Append(" --types \"").Append(o.TypeFilter).Append('"');

        if (o.EntropySkip)
            sb.Append(" --entropy-skip");
        if (o.Resume)
            sb.Append(" --resume");

        return sb.ToString();
    }
}

public sealed class CarverRunOptions
{
    public required string SourcePath { get; init; }
    public required string OutputDirectory { get; init; }
    public int ThreadCount { get; init; } = 4;
    public bool FsOnly { get; init; }
    public bool RawOnly { get; init; }
    public string? TypeFilter { get; init; }
    public bool EntropySkip { get; init; }
    public bool Resume { get; init; }
}
