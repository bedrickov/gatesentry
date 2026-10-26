# GateSentry

<p align="center">
  <strong>Fast, High-Precision DevSecOps Static Analysis & Secret Guardrail CLI</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet" alt=".NET 10" />
  <img src="https://img.shields.io/badge/AOT-Ready-success" alt="AOT Ready" />
  <img src="https://img.shields.io/badge/SARIF-OASIS%202.1-blue" alt="SARIF v2.1" />
  <img src="https://img.shields.io/badge/License-MIT-green" alt="MIT" />
  <img src="https://img.shields.io/badge/Zero-External%20Deps-brightgreen" alt="Zero Dependencies" />
</p>

---

## ⚡ Overview

**GateSentry** is a lightweight, zero-dependency DevSecOps static analysis tool written in modern **C# (.NET 10)**. It enforces security guardrails in your repository prior to code reaching production or public version control.

Unlike naive regex-only scanners that overwhelm developers with hundreds of false positives, **GateSentry** combines:
1. **Multi-pattern heuristic detection** (cloud secrets, private keys, LLM tokens, insecure TLS, misconfigurations).
2. **Shannon Entropy validation** to distinguish real high-randomness cryptographic secrets from dummy test strings.
3. **Safe Redaction engine** ensuring sensitive credentials are never dumped unmasked into CI logs or stdout.
4. **Deterministic Fingerprinting & Baseline suppression** allowing clean integration into mature brownfield projects without breaking builds.
5. **Native SARIF v2.1 export** directly compatible with **GitHub Code Scanning**, GitLab SAST, and Azure DevOps Security Center.

---

## ✨ Features

- **🚀 Ultra-Fast Parallel Scanning**: Utilizes lock-free streaming parallel evaluation across all CPU cores.
- **🛡️ Built-in Security Rules**:
  - AWS Access Keys & High-Entropy Secret Keys
  - GitHub PATs (classic `ghp_` and fine-grained `github_pat_`)
  - RSA, EC, OpenSSH, PGP unencrypted private keys
  - OpenAI & Anthropic API keys
  - Telegram & Slack Bot tokens
  - Embedded database connection URIs with plaintext credentials
  - Insecure TLS/SSL bypasses (`rejectUnauthorized: false`, `ServerCertificateCustomValidationCallback => true`)
  - Hardcoded symmetric JWT keys
  - Container privilege escalation (root execution)
- **🔕 Inline Exclusion**: Simply append `// gatesentry:ignore` or `# gatesentry:ignore` to safe lines.
- **📑 Baseline Suppressions**: Save known legacy issues to `.gatesentry-baseline.json` and block only new leaks.
- **📊 Standard Output Formats**: SARIF 2.1, JSON, and rich ANSI terminal reporting.

---

## 📦 Quick Start

### Installation & Building

```bash
# Clone the repository
git clone https://github.com/<your-username>/GateSentry.git
cd GateSentry

# Build solution
dotnet build -c Release

# Run tests
dotnet test
```

### CLI Usage

```bash
# Scan current repository
dotnet run --project src/GateSentry.Cli -- scan .

# Scan and export standard SARIF report for GitHub Code Scanning
dotnet run --project src/GateSentry.Cli -- scan . --sarif gatesentry-results.sarif

# Scan with custom failure threshold (Critical, High, Medium, Low)
dotnet run --project src/GateSentry.Cli -- scan . --fail-on Critical

# Generate a baseline file to suppress current legacy findings
dotnet run --project src/GateSentry.Cli -- baseline .

# Inspect entropy score of any suspect token
dotnet run --project src/GateSentry.Cli -- entropy "4a8B+9cK1lMnOpQrStUvWxYz0123456789+AbCdE="

# List all active rules and severity levels
dotnet run --project src/GateSentry.Cli -- rules
```

---

## 🔄 GitHub Actions CI/CD Integration

Embed GateSentry in `.github/workflows/security.yml`:

```yaml
name: "GateSentry Security Audit"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Run GateSentry Scan
        run: |
          dotnet run --project src/GateSentry.Cli -- scan . --sarif results.sarif --fail-on High

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 🏗️ Architecture

```
GateSentry/
├── src/
│   ├── GateSentry.Core/            # Core scanning engine (Zero third-party dependencies)
│   │   ├── Analysis/               # Shannon entropy & token masking algorithms
│   │   ├── Config/                 # Scanner options & baseline management
│   │   ├── Engine/                 # Multi-core concurrent repository scanner
│   │   ├── Formatter/              # OASIS SARIF v2.1 & JSON report builders
│   │   ├── Models/                 # Immutable records for rules, findings & metrics
│   │   └── Rules/                  # Built-in security detection catalog
│   └── GateSentry.Cli/             # High-performance CLI interface & ANSI terminal UI
└── tests/
    └── GateSentry.Tests/           # Unit & integration test suite (xUnit)
```

---

## 📄 License

MIT © 2026. Designed for modern high-reliability engineering pipelines.
