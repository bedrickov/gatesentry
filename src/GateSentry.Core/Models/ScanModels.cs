namespace GateSentry.Core.Models;

public enum SeverityLevel
{
    Info,
    Low,
    Medium,
    High,
    Critical
}

public enum RuleCategory
{
    Secret,
    CloudCredential,
    PrivateKey,
    Misconfiguration,
    InsecureDependency,
    WeakCryptography
}

public sealed record RuleDefinition(
    string Id,
    string Name,
    RuleCategory Category,
    SeverityLevel Severity,
    string Description,
    string Pattern,
    string? EntropyThreshold = null,
    string? RemediationGuide = null,
    string[]? TargetExtensions = null,
    string[]? ExcludedPaths = null
);

public sealed record CodeSnippet(
    int LineNumber,
    string LineContent,
    int ColumnStart,
    int ColumnEnd,
    string RedactedContent
);

public sealed record Finding(
    string RuleId,
    string RuleName,
    RuleCategory Category,
    SeverityLevel Severity,
    string FilePath,
    CodeSnippet Location,
    string Description,
    string? Remediation,
    string Fingerprint
);

public sealed record ScanMetrics(
    int TotalFilesScanned,
    int TotalFilesIgnored,
    long TotalBytesScanned,
    TimeSpan Duration,
    int HighSeverityCount,
    int CriticalSeverityCount,
    int MediumSeverityCount,
    int LowSeverityCount,
    int InfoSeverityCount
)
{
    public int TotalFindings => HighSeverityCount + CriticalSeverityCount + MediumSeverityCount + LowSeverityCount + InfoSeverityCount;
    public bool HasBlockerFindings => CriticalSeverityCount > 0 || HighSeverityCount > 0;
}

public sealed record ScanReport(
    string TargetPath,
    DateTimeOffset Timestamp,
    ScanMetrics Metrics,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<string> ScannedRules
);
