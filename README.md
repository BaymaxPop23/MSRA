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

---

## Installation

### Option 1 — Shell script (macOS / Linux, recommended)

```bash
git clone https://github.com/BaymaxPop23/MSRA.git
cd MSRA

# Install dependencies
pip3 install flask weasyprint
brew install jadx android-platform-tools   # macOS
# sudo apt install jadx adb               # Linux

# Start (opens browser automatically)
./start.sh

# Stop
./stop.sh
```

To enable AI features, set your Anthropic API key before starting:

```bash
ANTHROPIC_API_KEY=sk-ant-... ./start.sh
```

Or add it to a `.env` file (copy from `.env.example`).

---

### Option 2 — Make

```bash
git clone https://github.com/BaymaxPop23/MSRA.git
cd MSRA
make install      # pip install + reminds you to install jadx/adb
make start        # start dashboard, open browser
make stop         # stop dashboard
make restart      # restart
make logs         # tail server logs
```

---

### Option 3 — Docker (no Python setup needed)

```bash
git clone https://github.com/BaymaxPop23/MSRA.git
cd MSRA

# Add your API key (optional, for AI features)
cp .env.example .env
# edit .env and set ANTHROPIC_API_KEY=sk-ant-...

docker compose up -d
# Open http://localhost:5001

docker compose down   # stop
```

Scan data and reports persist in Docker volumes across restarts.

---

## Requirements

| Dependency | Purpose | Install |
|---|---|---|
| Python 3.8+ | Runtime | [python.org](https://python.org) |
| flask, weasyprint | Web server, PDF export | `pip3 install flask weasyprint` |
| `jadx` | APK decompilation (required for scanning) | `brew install jadx` |
| `adb` | Dynamic analysis (optional) | `brew install android-platform-tools` |
| `ANTHROPIC_API_KEY` | AI-enhanced scan + PoC generation (optional) | [console.anthropic.com](https://console.anthropic.com) |

---

## Usage

Upload an APK through the dashboard, then:
- Browse findings with severity chips and risk score
- Click a finding to open the detail drawer: vulnerable code, exploitation details, ADB commands
- Run **Basic ADB Scan** (heuristic verdict, no API key needed) or **AI-Enhanced Scan** (Claude analysis)
- Generate PoC Android apps for confirmed findings
- Export as PDF, CSV, SARIF, or JSON
- Triage findings: Confirmed / False Positive / Accepted Risk / Fixed

### Dynamic Analysis

The dashboard auto-detects connected ADB devices (including Genymotion at `127.0.0.1:6555`).

**Basic ADB Scan** — runs targeted ADB probes per finding category and produces a heuristic verdict without needing an API key.

**AI-Enhanced Scan** — same probes + passes all evidence to Claude for intelligent analysis and suggested actions.

---

## Vulnerability Categories

| Category | Description | Patterns |
|---|---|---|
| **WebView** | JavaScript interface, file access, SSL errors | 18 |
| **Intent / DeepLink** | Intent redirect, PendingIntent, broadcast hijacking | 13 |
| **Component Exposure** | Exported activities, services, receivers, providers | 11 |
| **Cryptography** | Weak algorithms, hardcoded keys, insecure random | 9 |
| **Permissions** | Dangerous permissions, signature protection | 7 |
| **Data Storage** | SharedPreferences, SQLite, external storage | 6 |
| **Network** | TLS validation, cleartext traffic, cert pinning | 4 |
| **Input Validation** | SQL injection, path traversal | 4 |
| **Logging** | Sensitive data in logs | 3 |
| **Credentials** | Hardcoded secrets, API keys | 2 |

---

## Project Structure

```
MSRA/
├── start.sh               # One-command start (opens browser)
├── stop.sh                # Stop server
├── Makefile               # make start / stop / logs / docker
├── Dockerfile             # Docker image
├── docker-compose.yml     # Docker Compose with persistent volumes
├── server.py              # Flask web server & dashboard
├── main.py                # CLI entry point
├── msra/
│   ├── scanner.py         # Pattern-based vulnerability scanner
│   ├── report.py          # HTML report generation
│   ├── db.py              # SQLite persistence (WAL mode)
│   ├── rules_api.py       # Pattern management API
│   ├── pdf_export.py      # PDF / SARIF / CSV export
│   ├── corellium.py       # Corellium cloud device client
│   ├── deep_analysis/     # WebView, Intent, Provider analyzers
│   ├── dynamic/           # ADB / Frida / mitmproxy dynamic analysis
│   └── patterns/          # Pattern loading & validation
└── data/
    └── builtin/
        └── patterns.json  # 77+ OWASP security patterns
```

---

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

---

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
