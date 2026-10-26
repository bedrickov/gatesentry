using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.RegularExpressions;
using GateSentry.Core.Analysis;
using GateSentry.Core.Config;
using GateSentry.Core.Models;
using GateSentry.Core.Rules;

namespace GateSentry.Core.Engine;

public sealed class ScannerEngine
{
    private readonly IReadOnlyList<CompiledRule> _rules;
    private readonly GateSentryOptions _options;

    public ScannerEngine(GateSentryOptions? options = null, IEnumerable<RuleDefinition>? customRules = null)
    {
        _options = options ?? new GateSentryOptions();
        var allRules = (customRules ?? BuiltinRules.All).ToList();
        _rules = allRules.Select(r => new CompiledRule(r)).ToList();
    }

    public async Task<ScanReport> ScanDirectoryAsync(
        string directoryPath,
        HashSet<string>? baselineFingerprints = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        var fullPath = Path.GetFullPath(directoryPath);

        if (!Directory.Exists(fullPath))
        {
            throw new DirectoryNotFoundException($"Target directory does not exist: {fullPath}");
        }

        var candidateFiles = DiscoverFiles(fullPath);
        var findings = new ConcurrentBag<Finding>();
        int scannedCount = 0;
        int ignoredCount = 0;
        long totalBytes = 0;

        await Parallel.ForEachAsync(candidateFiles, new ParallelOptions
        {
            CancellationToken = cancellationToken,
            MaxDegreeOfParallelism = Environment.ProcessorCount
        }, async (filePath, ct) =>
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Length > _options.MaxFileSizeBytes)
            {
                Interlocked.Increment(ref ignoredCount);
                return;
            }

            Interlocked.Increment(ref scannedCount);
            Interlocked.Add(ref totalBytes, fileInfo.Length);

            var relativePath = Path.GetRelativePath(fullPath, filePath);
            var fileFindings = await ScanFileAsync(filePath, relativePath, baselineFingerprints, ct);

            foreach (var f in fileFindings)
            {
                findings.Add(f);
            }

            progress?.Report(scannedCount);
        });

        stopwatch.Stop();

        var findingsList = findings.OrderByDescending(f => f.Severity).ThenBy(f => f.FilePath).ToList();

        var metrics = new ScanMetrics(
            TotalFilesScanned: scannedCount,
            TotalFilesIgnored: ignoredCount,
            TotalBytesScanned: totalBytes,
            Duration: stopwatch.Elapsed,
            CriticalSeverityCount: findingsList.Count(f => f.Severity == SeverityLevel.Critical),
            HighSeverityCount: findingsList.Count(f => f.Severity == SeverityLevel.High),
            MediumSeverityCount: findingsList.Count(f => f.Severity == SeverityLevel.Medium),
            LowSeverityCount: findingsList.Count(f => f.Severity == SeverityLevel.Low),
            InfoSeverityCount: findingsList.Count(f => f.Severity == SeverityLevel.Info)
        );

        return new ScanReport(
            TargetPath: fullPath,
            Timestamp: DateTimeOffset.UtcNow,
            Metrics: metrics,
            Findings: findingsList,
            ScannedRules: _rules.Select(r => r.Definition.Id).ToList()
        );
    }

    private async Task<List<Finding>> ScanFileAsync(
        string absolutePath,
        string relativePath,
        HashSet<string>? baseline,
        CancellationToken ct)
    {
        var result = new List<Finding>();
        string extension = Path.GetExtension(absolutePath).ToLowerInvariant();

        string[] lines;
        try
        {
            lines = await File.ReadAllLinesAsync(absolutePath, ct);
        }
        catch
        {
            // Binary or locked file
            return result;
        }

        for (int lineIndex = 0; lineIndex < lines.Length; lineIndex++)
        {
            var line = lines[lineIndex];
            if (string.IsNullOrWhiteSpace(line))
                continue;

            // Check inline ignore annotation e.g. // gatesentry:ignore or # gatesentry:ignore
            if (line.Contains("gatesentry:ignore", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("pragma: allowlist secret", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            foreach (var rule in _rules)
            {
                // Extension filter check
                if (rule.Definition.TargetExtensions is { Length: > 0 } targetExts)
                {
                    bool extMatch = false;
                    foreach (var ext in targetExts)
                    {
                        if (string.Equals(ext, extension, StringComparison.OrdinalIgnoreCase) ||
                            Path.GetFileName(absolutePath).Equals(ext, StringComparison.OrdinalIgnoreCase))
                        {
                            extMatch = true;
                            break;
                        }
                    }
                    if (!extMatch)
                        continue;
                }

                Match match;
                try
                {
                    match = rule.Regex.Match(line);
                }
                catch (RegexMatchTimeoutException)
                {
                    continue;
                }

                if (!match.Success)
                    continue;

                // Value for entropy verification
                string secretCandidate = match.Groups.Count > 1 ? match.Groups[^1].Value : match.Value;

                if (rule.MinEntropy > 0)
                {
                    double entropy = ShannonEntropy.Calculate(secretCandidate);
                    if (entropy < rule.MinEntropy)
                    {
                        // Entropy too low, likely sample/dummy string (e.g. 00000000000000000000)
                        continue;
                    }
                }

                int colStart = match.Index + 1;
                int colEnd = match.Index + match.Length + 1;
                string redacted = RedactionService.Mask(secretCandidate);
                string redactedLine = line.Replace(secretCandidate, redacted);

                string fingerprint = RedactionService.ComputeFingerprint(rule.Definition.Id, relativePath, lineIndex + 1, match.Value);

                if (baseline != null && baseline.Contains(fingerprint))
                {
                    // Suppressed via baseline
                    continue;
                }

                result.Add(new Finding(
                    RuleId: rule.Definition.Id,
                    RuleName: rule.Definition.Name,
                    Category: rule.Definition.Category,
                    Severity: rule.Definition.Severity,
                    FilePath: relativePath,
                    Location: new CodeSnippet(lineIndex + 1, line, colStart, colEnd, redactedLine),
                    Description: rule.Definition.Description,
                    Remediation: rule.Definition.RemediationGuide,
                    Fingerprint: fingerprint
                ));
            }
        }

        return result;
    }

    private List<string> DiscoverFiles(string rootPath)
    {
        var files = new List<string>();
        var dirsToTraverse = new Stack<string>();
        dirsToTraverse.Push(rootPath);

        while (dirsToTraverse.Count > 0)
        {
            var currentDir = dirsToTraverse.Pop();

            try
            {
                foreach (var subDir in Directory.GetDirectories(currentDir))
                {
                    var dirName = Path.GetFileName(subDir);
                    if (!_options.IgnoredDirectories.Contains(dirName))
                    {
                        dirsToTraverse.Push(subDir);
                    }
                }

                foreach (var file in Directory.GetFiles(currentDir))
                {
                    var ext = Path.GetExtension(file);
                    if (!_options.IgnoredExtensions.Contains(ext))
                    {
                        files.Add(file);
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Skip restricted paths
            }
        }

        return files;
    }
}
