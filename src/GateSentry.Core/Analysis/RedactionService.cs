using System.Security.Cryptography;
using System.Text;

namespace GateSentry.Core.Analysis;

public static class RedactionService
{
    /// <summary>
    /// Masks secret tokens while keeping the first and last 2 characters intact for verification.
    /// </summary>
    public static string Mask(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return "[REDACTED]";

        if (token.Length <= 6)
            return "******";

        int keep = Math.Min(3, token.Length / 4);
        string prefix = token[..keep];
        string suffix = token[^keep..];
        int maskedCount = Math.Max(4, token.Length - (keep * 2));
        return $"{prefix}{new string('*', maskedCount)}{suffix}";
    }

    /// <summary>
    /// Generates a deterministic SHA256 fingerprint for a finding to track baseline suppressions.
    /// </summary>
    public static string ComputeFingerprint(string ruleId, string filePath, int line, string rawMatch)
    {
        string normPath = filePath.Replace('\\', '/').ToLowerInvariant();
        string input = $"{ruleId}:{normPath}:{line}:{rawMatch.Trim()}";
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}
