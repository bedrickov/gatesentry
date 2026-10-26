using GateSentry.Core.Analysis;
using GateSentry.Core.Engine;
using GateSentry.Core.Models;
using Xunit;

namespace GateSentry.Tests;

public class ScannerTests
{
    [Fact]
    public void ShannonEntropy_ReturnsZero_ForEmptyOrHomogeneousString()
    {
        Assert.Equal(0.0, ShannonEntropy.Calculate(string.Empty));
        Assert.Equal(0.0, ShannonEntropy.Calculate("aaaaaaaaaa"));
    }

    [Fact]
    public void ShannonEntropy_CalculatesHighValue_ForHighRandomness()
    {
        // 40 chars base64 secret
        string secret = "4a8B+9cK1lMnOpQrStUvWxYz0123456789+AbCdE=";
        double entropy = ShannonEntropy.Calculate(secret);
        Assert.True(entropy > 4.5, $"Entropy was expected to be > 4.5, got {entropy}");
    }

    [Fact]
    public void RedactionService_MasksSecret_Correctly()
    {
        string secret = "AKIA" + "IOSFODNN7EXAMPLE"; // gatesentry:ignore
        string masked = RedactionService.Mask(secret);

        Assert.StartsWith("AKI", masked);
        Assert.EndsWith("PLE", masked);
        Assert.Contains("******", masked);
        Assert.DoesNotContain("IOSFODNN7EXAM", masked);
    }

    [Fact]
    public void RedactionService_ProducesDeterministicFingerprint()
    {
        string dummy = "AKIA" + "IOSFODNN7EXAMPLE"; // gatesentry:ignore
        string fp1 = RedactionService.ComputeFingerprint("GS-001", "src/config.json", 12, dummy);
        string fp2 = RedactionService.ComputeFingerprint("GS-001", "src/config.json", 12, dummy);
        string fpDifferent = RedactionService.ComputeFingerprint("GS-001", "src/other.json", 12, dummy);

        Assert.Equal(fp1, fp2);
        Assert.NotEqual(fp1, fpDifferent);
    }

    [Fact]
    public async Task ScannerEngine_DetectsAwsKey_AndIgnoresSafeComments()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "gatesentry_test_" + Guid.NewGuid());
        Directory.CreateDirectory(tempDir);

        try
        {
            string testFile = Path.Combine(tempDir, "deploy.env");
            await File.WriteAllLinesAsync(testFile,
            [
                "# Production AWS credentials",
                "AWS_ACCESS_KEY_ID=" + "AKIA" + "IOSFODNN7EXAMPLE",
                "SAFE_EXAMPLE_KEY=AKIA0000000000000000 // gatesentry:ignore",
                "NORMAL_VAR=hello_world"
            ]);

            var engine = new ScannerEngine();
            var report = await engine.ScanDirectoryAsync(tempDir);

            Assert.Single(report.Findings);
            var finding = report.Findings[0];
            Assert.Equal("GS-001", finding.RuleId);
            Assert.Equal(SeverityLevel.Critical, finding.Severity);
            Assert.Equal(2, finding.Location.LineNumber);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, true);
            }
        }
    }
}
