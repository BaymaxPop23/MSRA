# MSRA — Mobile Security Review Assistant

Android APK security analysis platform with pattern-based detection, AI-assisted triage, and dynamic runtime verification.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Patterns](https://img.shields.io/badge/patterns-77+-orange.svg)

## Highlights

- **Web Dashboard** — Upload APKs, browse scans, triage findings in a single-page UI
- **77+ Security Patterns** — Covering OWASP Mobile Top 10 with context-based FP reduction
- **Dynamic Verification** — Basic ADB scan (no API key needed) or AI-enhanced Claude analysis
- **AI PoC Generation** — Generate proof-of-concept Android apps for confirmed findings
- **PDF / CSV / SARIF exports** — With triage state included

## Requirements

- Python 3.8+
- `jadx` for APK decompilation ([install](https://github.com/skylot/jadx))
- `adb` for dynamic analysis (Android SDK platform-tools)

Optional for AI features:
- `ANTHROPIC_API_KEY` environment variable (for AI-enhanced scan and PoC generation)

## Installation

```bash
git clone https://github.com/BaymaxPop23/MSRA.git
cd MSRA
pip install flask weasyprint
```

### Install jadx

```bash
# macOS
brew install jadx

# Linux (Ubuntu/Debian)
sudo apt install jadx
```

### Install adb

```bash
# macOS
brew install android-platform-tools

# Linux
sudo apt install adb
```

## Quick Start

### Web Dashboard (recommended)

```bash
python server.py
# Open http://localhost:5001
```

Set your Anthropic API key for AI features:

```bash
ANTHROPIC_API_KEY=sk-ant-... python server.py
```

Upload an APK through the dashboard, then:
- Browse findings with severity chips and risk score
- Click a finding to open the drawer: vulnerable code, exploitation details, ADB commands
- Run **Basic ADB Scan** (heuristic, no API key needed) or **AI-Enhanced Scan** (Claude analysis)
- Generate PoC Android apps for confirmed findings
- Export as PDF, CSV, SARIF, or JSON

### Dynamic Analysis

The dashboard auto-detects connected ADB devices (including Genymotion at `127.0.0.1:6555`).

**Basic ADB Scan** — runs targeted ADB probes per finding category and produces a heuristic verdict without needing an API key.

**AI-Enhanced Scan** — same probes + passes all evidence to Claude for intelligent analysis and suggested actions.

## Vulnerability Categories

| Category | Description | Patterns |
|----------|-------------|----------|
| **WebView** | JavaScript interface, file access, SSL errors | 18 |
| **Intent/DeepLink** | Intent redirect, PendingIntent, broadcast hijacking | 13 |
| **Component Exposure** | Exported activities, services, receivers, providers | 11 |
| **Cryptography** | Weak algorithms, hardcoded keys, insecure random | 9 |
| **Permissions** | Dangerous permissions, signature protection | 7 |
| **Data Storage** | SharedPreferences, SQLite, external storage | 6 |
| **Network** | TLS validation, cleartext traffic, cert pinning | 4 |
| **Input Validation** | SQL injection, path traversal | 4 |
| **Logging** | Sensitive data in logs | 3 |
| **Credentials** | Hardcoded secrets, API keys | 2 |

## Project Structure

```
MSRA/
├── server.py              # Flask web server & dashboard
├── main.py                # CLI entry point
├── msra/
│   ├── scanner.py         # Pattern-based vulnerability scanner
│   ├── report.py          # HTML report generation
│   ├── db.py              # SQLite persistence (WAL mode)
│   ├── rules_api.py       # Pattern management API
│   ├── pdf_export.py      # PDF/SARIF/CSV export
│   ├── corellium.py       # Corellium cloud device client
│   ├── deep_analysis/     # WebView, Intent, Provider analyzers
│   ├── dynamic/           # ADB/Frida/mitmproxy dynamic analysis
│   └── patterns/          # Pattern loading & validation
└── data/
    └── builtin/
        └── patterns.json  # 77+ OWASP security patterns
```

## Custom Patterns

Add patterns to `data/custom/user_rules.json`:

```json
{
  "patterns": [
    {
      "id": "custom-001",
      "title": "Custom Vulnerability",
      "severity": "High",
      "category": "Custom",
      "detection": {
        "type": "regex",
        "patterns": [{"pattern": "dangerousMethod\\s*\\(", "file_types": [".java"]}]
      },
      "description": "...",
      "remediation": "...",
      "enabled": true
    }
  ]
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add patterns to `data/builtin/patterns.json`
4. Submit a pull request

## License

MIT License

## Acknowledgments

- [jadx](https://github.com/skylot/jadx) — APK decompilation
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/) — Security guidance
- [Claude](https://claude.ai) — AI-powered analysis
