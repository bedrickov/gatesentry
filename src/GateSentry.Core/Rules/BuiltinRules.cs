using System.Text.RegularExpressions;
using GateSentry.Core.Models;

namespace GateSentry.Core.Rules;

public sealed class CompiledRule
{
    public RuleDefinition Definition { get; }
    public Regex Regex { get; }
    public double MinEntropy { get; }

    public CompiledRule(RuleDefinition definition)
    {
        Definition = definition;
        Regex = new Regex(definition.Pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(500));
        MinEntropy = double.TryParse(definition.EntropyThreshold, System.Globalization.CultureInfo.InvariantCulture, out var e) ? e : 0.0;
    }
}

public static class BuiltinRules
{
    public static readonly IReadOnlyList<RuleDefinition> All =
    [
        new(
            Id: "GS-001",
            Name: "AWS Access Key ID",
            Category: RuleCategory.CloudCredential,
            Severity: SeverityLevel.Critical,
            Description: "Detected raw AWS Access Key ID (AKIA/ABIA/ACCA/ASIA). Never commit AWS credentials into version control.",
            Pattern: @"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b",
            RemediationGuide: "Revoke key in AWS IAM console immediately, rotate secrets, and migrate to IAM Roles or AWS Secrets Manager."
        ),
        new(
            Id: "GS-002",
            Name: "AWS Secret Access Key",
            Category: RuleCategory.CloudCredential,
            Severity: SeverityLevel.Critical,
            Description: "Detected high-entropy AWS Secret Access Key assignment.",
            Pattern: @"(?i)(?:aws_secret_access_key|aws_sec_key|aws_secret)\s*[:=]\s*['""]?([A-Za-z0-9\/+=]{40})['""]?",
            EntropyThreshold: "4.0",
            RemediationGuide: "Inactivate key in AWS IAM and audit CloudTrail for unauthorized API calls."
        ),
        new(
            Id: "GS-003",
            Name: "GitHub Personal Access Token",
            Category: RuleCategory.Secret,
            Severity: SeverityLevel.Critical,
            Description: "Detected GitHub Personal Access Token (classic ghp_ or fine-grained github_pat_).",
            Pattern: @"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b",
            RemediationGuide: "Revoke token under GitHub Settings -> Developer Settings -> Personal access tokens."
        ),
        new(
            Id: "GS-004",
            Name: "Private Cryptographic Key",
            Category: RuleCategory.PrivateKey,
            Severity: SeverityLevel.Critical,
            Description: "Detected unencrypted RSA/EC/OPENSSH/PGP private key header in source tree.",
            Pattern: @"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
            RemediationGuide: "Remove private key from git history (using git-filter-repo or BFG). Store in HSM, Vault or Kubernetes Secret."
        ),
        new(
            Id: "GS-005",
            Name: "Generic High-Entropy API Key or Secret",
            Category: RuleCategory.Secret,
            Severity: SeverityLevel.High,
            Description: "Detected generic high-entropy secret assignment (api_key, secret_key, client_secret).",
            Pattern: @"(?i)(?:api_key|apikey|secret_key|client_secret|auth_token|access_token|private_key)\s*[:=]\s*['""]([A-Za-z0-9_\-\.]{24,})['""]",
            EntropyThreshold: "3.75",
            RemediationGuide: "Use environment variables, Azure Key Vault, HashiCorp Vault, or .env files excluded via .gitignore."
        ),
        new(
            Id: "GS-006",
            Name: "Slack Bot / User Token",
            Category: RuleCategory.Secret,
            Severity: SeverityLevel.High,
            Description: "Detected Slack API token (xoxb, xoxp, xapp).",
            Pattern: @"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b",
            RemediationGuide: "Revoke the token in the Slack API dashboard and install as a secure app secret."
        ),
        new(
            Id: "GS-007",
            Name: "Telegram Bot API Token",
            Category: RuleCategory.Secret,
            Severity: SeverityLevel.High,
            Description: "Detected Telegram Bot API authentication token.",
            Pattern: @"\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b",
            RemediationGuide: "Regenerate bot token via @BotFather in Telegram immediately."
        ),
        new(
            Id: "GS-008",
            Name: "Database Connection String with Credentials",
            Category: RuleCategory.Misconfiguration,
            Severity: SeverityLevel.High,
            Description: "Detected hardcoded database connection URI with embedded plaintext username and password.",
            Pattern: @"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[^\s:=]+:[^\s@]+@[^\s/]+",
            RemediationGuide: "Extract credentials to environment variables or use Managed Identity / IAM database authentication."
        ),
        new(
            Id: "GS-009",
            Name: "OpenAI / Anthropic LLM API Key",
            Category: RuleCategory.Secret,
            Severity: SeverityLevel.Critical,
            Description: "Detected OpenAI (sk-...) or Anthropic (sk-ant-...) production API secret key.",
            Pattern: @"\b(sk-(?:live-)?[a-zA-Z0-9]{32,}|sk-ant-[a-zA-Z0-9\-_]{32,})\b",
            RemediationGuide: "Revoke key in OpenAI/Anthropic developer portal to prevent unauthorized billing drain."
        ),
        new(
            Id: "GS-010",
            Name: "Insecure TLS / SSL Verification Bypass",
            Category: RuleCategory.Misconfiguration,
            Severity: SeverityLevel.Medium,
            Description: "Detected disabled TLS/SSL certificate verification (ServerCertificateCustomValidationCallback / rejectUnauthorized: false / verify=False).",
            Pattern: @"(?i)(?:ServerCertificateCustomValidationCallback\s*=\s*(?:\([^\)]*\)|[a-zA-Z0-9_]+)\s*=>\s*true|rejectUnauthorized\s*:\s*false|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*0)",
            RemediationGuide: "Ensure strict certificate validation is enabled in production environments to prevent MITM attacks."
        ),
        new(
            Id: "GS-011",
            Name: "Hardcoded JWT Secret / Signing Key",
            Category: RuleCategory.WeakCryptography,
            Severity: SeverityLevel.High,
            Description: "Detected hardcoded secret or symmetric key used for JWT token validation/generation.",
            Pattern: @"(?i)(?:jwt_secret|jwt_key|symmetric_security_key)\s*[:=]\s*['""][^'""]{8,}['""]",
            RemediationGuide: "Inject signing keys via secure configuration management or use asymmetric key pairs (RS256/ES256)."
        ),
        new(
            Id: "GS-012",
            Name: "Docker Root User Misconfiguration",
            Category: RuleCategory.Misconfiguration,
            Severity: SeverityLevel.Low,
            Description: "Container file appears to run without a non-root USER declaration.",
            Pattern: @"(?i)^USER\s+root\b",
            TargetExtensions: [".dockerfile", "dockerfile", "Dockerfile", ".containerfile"],
            RemediationGuide: "Define and switch to an unprivileged user (e.g. 'USER appuser' or 'USER 10001') before ENTRYPOINT/CMD."
        )
    ];
}
