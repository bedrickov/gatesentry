using GateSentry.Cli.Rendering;
using GateSentry.Core.Analysis;
using GateSentry.Core.Config;
using GateSentry.Core.Engine;
using GateSentry.Core.Formatters;
using GateSentry.Core.Models;
using GateSentry.Core.Rules;

namespace GateSentry.Cli;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        ConsoleRenderer.PrintBanner();

        if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
        {
            PrintUsage();
            return 0;
        }

        string command = args[0].ToLowerInvariant();

        return command switch
        {
            "scan" => await RunScanCommandAsync(args[1..]),
            "baseline" => await RunBaselineCommandAsync(args[1..]),
            "rules" => RunListRulesCommand(),
            "entropy" => RunEntropyCommand(args[1..]),
            _ => RunUnknownCommand(command)
        };
    }

    private static void PrintUsage()
    {
        Console.WriteLine("Usage: gatesentry <command> [options]\n");
        Console.WriteLine("Commands:");
        Console.WriteLine("  scan [path]        Scan source tree for leaked secrets, API keys and security flaws");
        Console.WriteLine("  baseline [path]    Generate a baseline suppression file (.gatesentry-baseline.json)");
        Console.WriteLine("  rules              Display all active security detection rules and metadata");
        Console.WriteLine("  entropy <string>   Evaluate Shannon entropy score of given candidate string");
        Console.WriteLine("\nOptions for scan:");
        Console.WriteLine("  --sarif <file>     Export findings in standard OASIS SARIF v2.1 format for CI/CD");
        Console.WriteLine("  --json <file>      Export findings in full JSON report format");
        Console.WriteLine("  --baseline <file>  Use baseline file to suppress already known issues");
        Console.WriteLine("  --fail-on <level>  Failure threshold: Critical, High, Medium, Low (Default: High)");
    }

    private static int RunListRulesCommand()
    {
        Console.WriteLine($"{"ID",-8} {"SEVERITY",-10} {"CATEGORY",-18} {"NAME"}");
        Console.WriteLine(new string('-', 75));
        foreach (var rule in BuiltinRules.All)
        {
            Console.WriteLine($"{rule.Id,-8} {rule.Severity,-10} {rule.Category,-18} {rule.Name}");
        }
        return 0;
    }

    private static int RunEntropyCommand(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Error: provide a string to calculate entropy.");
            return 1;
        }

        string text = args[0];
        double score = ShannonEntropy.Calculate(text);
        Console.WriteLine($"Input: {text}");
        Console.WriteLine($"Entropy: {score:F4} bits");
        Console.WriteLine(score >= 3.75 ? "Verdict: HIGH ENTROPY (Likely cryptographic key or token)" : "Verdict: Low/Medium randomness (Likely human text or low-variance token)");
        return 0;
    }

    private static int RunUnknownCommand(string cmd)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Unknown command '{cmd}'. Run 'gatesentry --help' for details.");
        Console.ResetColor();
        return 1;
    }

    private static async Task<int> RunScanCommandAsync(string[] args)
    {
        string targetDir = ".";
        string? sarifPath = null;
        string? jsonPath = null;
        string? baselinePath = null;
        SeverityLevel failOn = SeverityLevel.High;

        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--sarif" && i + 1 < args.Length)
            {
                sarifPath = args[++i];
            }
            else if (args[i] == "--json" && i + 1 < args.Length)
            {
                jsonPath = args[++i];
            }
            else if (args[i] == "--baseline" && i + 1 < args.Length)
            {
                baselinePath = args[++i];
            }
            else if (args[i] == "--fail-on" && i + 1 < args.Length)
            {
                if (Enum.TryParse<SeverityLevel>(args[++i], true, out var lvl))
                {
                    failOn = lvl;
                }
            }
            else if (!args[i].StartsWith("--"))
            {
                targetDir = args[i];
            }
        }

        baselinePath ??= Path.Combine(targetDir, ".gatesentry-baseline.json");
        HashSet<string>? baselineFingerprints = null;

        if (File.Exists(baselinePath))
        {
            var baseline = await BaselineFile.LoadAsync(baselinePath);
            if (baseline != null)
            {
                baselineFingerprints = baseline.SuppressedFingerprints;
                Console.WriteLine($"[INFO] Loaded baseline filter with {baselineFingerprints.Count} suppressed fingerprints.");
            }
        }

        var options = new GateSentryOptions
        {
            TargetDirectory = targetDir,
            FailOnSeverity = failOn
        };

        var engine = new ScannerEngine(options);
        Console.WriteLine($"Scanning target: {Path.GetFullPath(targetDir)} ...\n");

        var report = await engine.ScanDirectoryAsync(targetDir, baselineFingerprints);

        foreach (var finding in report.Findings)
        {
            ConsoleRenderer.PrintFinding(finding);
        }

        ConsoleRenderer.PrintSummary(report.Metrics);

        if (!string.IsNullOrEmpty(sarifPath))
        {
            var sarif = SarifFormatter.GenerateSarif(report);
            await File.WriteAllTextAsync(sarifPath, sarif);
            Console.WriteLine($"[EXPORT] SARIF report written to: {sarifPath}");
        }

        if (!string.IsNullOrEmpty(jsonPath))
        {
            var json = JsonReportFormatter.Format(report);
            await File.WriteAllTextAsync(jsonPath, json);
            Console.WriteLine($"[EXPORT] JSON report written to: {jsonPath}");
        }

        bool shouldFail = report.Findings.Any(f => f.Severity >= failOn);
        return shouldFail ? 1 : 0;
    }

    private static async Task<int> RunBaselineCommandAsync(string[] args)
    {
        string targetDir = args.Length > 0 && !args[0].StartsWith("--") ? args[0] : ".";
        string baselinePath = Path.Combine(targetDir, ".gatesentry-baseline.json");

        Console.WriteLine($"Generating baseline for: {Path.GetFullPath(targetDir)} ...");

        var engine = new ScannerEngine();
        var report = await engine.ScanDirectoryAsync(targetDir);

        var fingerprints = report.Findings.Select(f => f.Fingerprint).Distinct().ToList();
        await BaselineFile.SaveAsync(baselinePath, fingerprints);

        Console.WriteLine($"[OK] Baseline successfully saved to '{baselinePath}' with {fingerprints.Count} fingerprints suppressed.");
        return 0;
    }
}
