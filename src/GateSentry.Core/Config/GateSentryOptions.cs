using System.Text.Json;
using GateSentry.Core.Models;

namespace GateSentry.Core.Config;

public sealed record GateSentryOptions
{
    public string TargetDirectory { get; init; } = ".";
    public SeverityLevel FailOnSeverity { get; init; } = SeverityLevel.High;
    public string? BaselineFilePath { get; init; }
    public string? SarifOutputPath { get; init; }
    public string? JsonOutputPath { get; init; }
    public HashSet<string> IgnoredDirectories { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ".git", ".svn", ".hg", "node_modules", "bin", "obj", "dist", "build", "target", ".idea", ".vscode", "coverage", ".artifacts"
    };
    public HashSet<string> IgnoredExtensions { get; init; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ".dll", ".exe", ".pdb", ".bin", ".iso", ".zip", ".tar", ".gz", ".7z", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".wav", ".pdf"
    };
    public long MaxFileSizeBytes { get; init; } = 4 * 1024 * 1024; // 4MB
}

public sealed record BaselineFile(
    int Version,
    DateTimeOffset CreatedAt,
    HashSet<string> SuppressedFingerprints
)
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static async Task<BaselineFile?> LoadAsync(string path)
    {
        if (!File.Exists(path))
            return null;

        try
        {
            await using var stream = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync<BaselineFile>(stream, JsonOptions);
        }
        catch
        {
            return null;
        }
    }

    public static async Task SaveAsync(string path, IEnumerable<string> fingerprints)
    {
        var baseline = new BaselineFile(1, DateTimeOffset.UtcNow, new HashSet<string>(fingerprints));
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, baseline, JsonOptions);
    }
}
