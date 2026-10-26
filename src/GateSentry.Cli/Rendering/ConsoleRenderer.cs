namespace GateSentry.Cli.Rendering;

public static class ConsoleRenderer
{
    private const string Cyan = "\u001b[36m";
    private const string Bold = "\u001b[1m";
    private const string Dim = "\u001b[2m";
    private const string Reset = "\u001b[0m";
    private const string Red = "\u001b[31m";
    private const string Green = "\u001b[32m";
    private const string Yellow = "\u001b[33m";
    private const string Magenta = "\u001b[35m";

    public static void PrintBanner()
    {
        Console.WriteLine($"{Cyan}{Bold}");
        Console.WriteLine(@"  ____       _       ____             _              ");
        Console.WriteLine(@" / ___| __ _| |_ ___/ ___|  ___ _ __ | |_ _ __ _   _ ");
        Console.WriteLine(@"| |  _ / _` | __/ _ \___ \ / _ \ '_ \| __| '__| | | |");
        Console.WriteLine(@"| |_| | (_| | ||  __/___) |  __/ | | | |_| |  | |_| |");
        Console.WriteLine(@" \____|\__,_|\__\___|____/ \___|_| |_|\__|_|   \__, |");
        Console.WriteLine(@"                                               |___/ ");
        Console.WriteLine($"{Reset}{Dim} DevSecOps Guardrail Engine | v1.0.0-release (.NET 10 AOT ready){Reset}\n");
    }

    public static void PrintFinding(Core.Models.Finding finding)
    {
        var (color, label) = finding.Severity switch
        {
            Core.Models.SeverityLevel.Critical => (Magenta, "[CRITICAL]"),
            Core.Models.SeverityLevel.High => (Red, "[HIGH]    "),
            Core.Models.SeverityLevel.Medium => (Yellow, "[MEDIUM]  "),
            Core.Models.SeverityLevel.Low => (Cyan, "[LOW]     "),
            _ => (Dim, "[INFO]    ")
        };

        Console.WriteLine($"{Bold}{color}{label}{Reset} {Bold}{finding.RuleName}{Reset} ({Dim}{finding.RuleId}{Reset})");
        Console.WriteLine($"  {Dim}File:{Reset} {finding.FilePath}:{finding.Location.LineNumber}:{finding.Location.ColumnStart}");
        Console.WriteLine($"  {Dim}Fingerprint:{Reset} {finding.Fingerprint}");
        Console.WriteLine($"  {Dim}Snippet:{Reset} {finding.Location.RedactedContent.Trim()}");
        if (!string.IsNullOrEmpty(finding.Remediation))
        {
            Console.WriteLine($"  {Green}Fix:{Reset} {finding.Remediation}");
        }
        Console.WriteLine();
    }

    public static void PrintSummary(Core.Models.ScanMetrics metrics)
    {
        Console.WriteLine($"{Bold}─────────────── Scan Summary ───────────────{Reset}");
        Console.WriteLine($"  Files scanned:   {metrics.TotalFilesScanned}");
        Console.WriteLine($"  Throughput:      {(metrics.TotalBytesScanned / 1024.0 / 1024.0):F2} MB in {metrics.Duration.TotalMilliseconds:F0} ms");
        Console.WriteLine($"  Findings total:  {metrics.TotalFindings}");
        Console.WriteLine($"    {Magenta}Critical:{Reset} {metrics.CriticalSeverityCount}");
        Console.WriteLine($"    {Red}High:{Reset}     {metrics.HighSeverityCount}");
        Console.WriteLine($"    {Yellow}Medium:{Reset}   {metrics.MediumSeverityCount}");
        Console.WriteLine($"    {Cyan}Low:{Reset}      {metrics.LowSeverityCount}");
        Console.WriteLine($"{Bold}────────────────────────────────────────────{Reset}");

        if (metrics.HasBlockerFindings)
        {
            Console.WriteLine($"\n{Red}{Bold}[FAIL]{Reset} GateSentry discovered policy-violating high/critical security findings!");
        }
        else
        {
            Console.WriteLine($"\n{Green}{Bold}[PASS]{Reset} Security audit cleared! No blocking policy violations found.");
        }
    }
}
