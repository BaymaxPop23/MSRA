# MSRA — Mobile Security Review Assistant

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Patterns](https://img.shields.io/badge/patterns-215+-orange.svg)
![Platforms](https://img.shields.io/badge/platforms-Android%20%7C%20iOS%20%7C%20JAR%20%7C%20EXE-blueviolet.svg)

MSRA is a multi-platform security scanner and web dashboard built for penetration testers and security researchers. It automates the tedious parts of mobile app security reviews — upload an APK, IPA, JAR, or EXE and within minutes get a fully triaged vulnerability report mapped to OWASP Mobile Top 10, CWEs, and severity ratings.

It goes beyond pattern matching: MSRA decompiles Android apps with jadx and runs inter-procedural taint analysis to trace real data flows from source to sink. It then drives ADB to dynamically probe exported components with SQLi, path traversal, and intent injection payloads — confirming whether static findings are actually exploitable at runtime. Findings come with ready-to-use `adb` PoC commands so pentesters can move straight to exploitation and reporting.

**AI (powered by Claude):** The AI-Enhanced Dynamic Scan passes runtime logcat, Frida hook output, and ADB probe results to Claude, which returns a structured true positive / false positive / uncertain verdict with confidence score and reasoning — cutting manual triage time dramatically. The Intelligence Hub lets you paste any blog URL or CVE and Claude auto-generates new detection rules; it also crawls 15 security research blogs (Oversecured, Project Zero, NowSecure, etc.) to keep rules current. AI features require an `ANTHROPIC_API_KEY` — everything else runs fully offline.

## Highlights

- **Web Dashboard** — Upload files, browse scans, triage findings in a single-page UI
- **215+ Security Patterns** — Android (77), iOS (45), Java JAR (49), Windows PE (44)
- **Multi-Platform Scanning** — APK / APKM / XAPK · IPA · JAR · EXE / DLL
- **Dynamic Verification** — ADB-based probes (no API key) or AI-enhanced Claude analysis
- **AI PoC Generation** — Generate proof-of-concept code for confirmed findings
- **Intelligence Hub** — Community rules, custom pattern editor, HackerOne / OWASP feeds
- **Exports** — PDF, CSV, SARIF, JSON — all with triage state included

---

## Installation

### Option 1 — Shell script (macOS / Linux, recommended)

```bash
git clone https://github.com/BaymaxPop23/MSRA.git
cd MSRA

# Install Python dependencies
pip3 install -r requirements.txt

# macOS system tools
brew install jadx android-platform-tools

# Linux system tools
# sudo apt install jadx adb

# Start (opens browser automatically)
./start.sh
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
make install      # pip install dependencies
make start        # start dashboard, open browser
make stop         # stop dashboard
make restart      # restart
make update       # pull latest version and restart
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

## Updating

MSRA ships an `update.sh` script that pulls the latest code, updates dependencies, and restarts the server in one step.

### Quickest way

```bash
./update.sh
```

The script will:
1. Show your current version and any new commits available
2. Ask for confirmation before applying
3. `git pull` the latest code
4. `pip3 install -r requirements.txt` to pick up new dependencies
5. Restart the server automatically

### With Make

```bash
make update
```

### Manual update (Docker)

```bash
git pull origin main
docker compose down
docker compose up -d --build
```

### Manual update (no script)

```bash
cd MSRA
git pull origin main
pip3 install -r requirements.txt
./stop.sh && ./start.sh
```

> **Note:** The SQLite database (`msra.db`) and all scan reports in `reports/` are never touched by an update — your data is safe.

---

## Requirements

### Python (required)

| Package | Purpose |
|---|---|
| Python 3.8+ | Runtime — [python.org](https://python.org) |
| `flask` | Web server |
| `weasyprint` | PDF report export |
| `pefile` | Windows PE / EXE / DLL scanning |

Install all Python packages at once:
```bash
pip3 install -r requirements.txt
```

### System libraries — WeasyPrint PDF export

WeasyPrint requires native system libraries. **Without these, PDF export will not work.**

**macOS:**
```bash
brew install pango cairo gdk-pixbuf
```

**Ubuntu / Debian:**
```bash
sudo apt install libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0
```

**Fedora / RHEL:**
```bash
sudo dnf install pango cairo gdk-pixbuf2
```

> `start.sh` will print a warning at startup if WeasyPrint is not working correctly.

### External tools

| Tool | Purpose | Install |
|---|---|---|
| `jadx` | APK decompilation (required for Android scans) | `brew install jadx` / `apt install jadx` |
| `adb` | Dynamic analysis — ADB probes (optional) | `brew install android-platform-tools` |
| `frida-tools` | Runtime instrumentation hooks (optional) | `pip3 install frida-tools` |

### AI features (optional)

Set `ANTHROPIC_API_KEY` to enable:
- AI-Enhanced Dynamic Scan (Claude verdict + reasoning)
- PoC code generation
- Intelligence Hub — URL-to-rule extraction and feed analysis

```bash
export ANTHROPIC_API_KEY=sk-ant-...
# or add to .env (copy from .env.example)
```

Get a key at [console.anthropic.com](https://console.anthropic.com). All scanning and heuristic dynamic analysis works fully offline without a key.

---

## Usage

Upload a file through the dashboard, then:

- Browse findings with severity chips and risk score
- Click a finding to open the detail drawer: vulnerable code, exploitation details, commands
- Run **Basic ADB Scan** (heuristic verdict, no API key) or **AI-Enhanced Scan** (Claude analysis)
- Generate PoC code / Android apps for confirmed findings
- Export as PDF, CSV, SARIF, or JSON
- Triage findings: Confirmed / False Positive / Accepted Risk / Fixed

### Supported File Types

| File | Platform | Scanner |
|------|----------|---------|
| `.apk` `.apkm` `.xapk` | Android | jadx decompile + 77 patterns |
| `.ipa` | iOS | plist / entitlements / binary + 45 patterns |
| `.jar` | Java | manifest + class files + 49 patterns |
| `.exe` `.dll` | Windows PE | PE headers + imports + strings + 44 patterns |

### Dynamic Analysis (Android)

The dashboard auto-detects connected ADB devices (including Genymotion at `127.0.0.1:6555`).

**Basic ADB Scan** — runs targeted ADB probes per finding category and produces a heuristic verdict without an API key. Probes include:
- SQLi: 4 payload classes against ContentProvider + open query
- Path traversal: 4 encoded variants
- WebView: JS-scheme deeplink + file:// URI + intent-extras injection
- Credentials: world-readable file scan + external storage + SharedPrefs
- Network: NSC config read + cleartext HTTP detection
- Components: exported component enumeration via `dumpsys`

**AI-Enhanced Scan** — same probes + passes security-filtered evidence to Claude with category-specific guidance for intelligent verdict and suggested actions.

---

## Vulnerability Categories

### Android (77 patterns)
| Category | Patterns |
|---|---|
| WebView | 18 |
| Intent / DeepLink | 13 |
| Component Exposure | 11 |
| Network Security | 12 |
| Cryptography | 10 |
| Data Storage | 8 |
| Permissions | 7 |
| Hardcoded Secrets | 7 |
| Input Validation | 4 |
| Logging | 4 |

### iOS (45 patterns)
ATS misconfiguration, insecure data storage, weak cryptography, URL scheme hijacking, Objective-C runtime abuse, entitlement misuse, binary protections.

### Java JAR (49 patterns)
Log4Shell / Spring4Shell / Commons Collections, deserialization gadget chains, code injection, weak crypto, manifest security, known-vulnerable library versions.

### Windows PE (44 patterns)
Missing ASLR / DEP / CFG / StackCookie / High-Entropy ASLR / Authenticode, process injection triad, credential theft APIs (MiniDumpWriteDump, DPAPI, CredRead), ransomware API combos, persistence, anti-analysis, string IOCs.

---

## Project Structure

```
MSRA/
├── start.sh               # One-command start (opens browser)
├── stop.sh                # Stop server
├── update.sh              # Pull latest version and restart
├── Makefile               # make start / stop / update / logs / docker
├── Dockerfile             # Docker image
├── docker-compose.yml     # Docker Compose with persistent volumes
├── requirements.txt       # Python dependencies
├── server.py              # Flask web server & dashboard (~6500 lines)
├── main.py                # CLI entry point
├── msra/
│   ├── scanner.py         # Android pattern-based scanner
│   ├── ios_scanner.py     # iOS IPA static scanner
│   ├── jar_scanner.py     # Java JAR static scanner
│   ├── exe_scanner.py     # Windows PE static scanner
│   ├── report.py          # HTML report generation
│   ├── db.py              # SQLite persistence (WAL mode)
│   ├── rules_api.py       # Pattern management API (cached)
│   ├── pdf_export.py      # PDF / SARIF / CSV export
│   ├── corellium.py       # Corellium cloud device client
│   ├── deep_analysis/     # WebView, Intent, Provider analyzers
│   └── dynamic/           # ADB / Frida / mitmproxy dynamic analysis
└── data/
    └── builtin/
        ├── patterns.json      # 77 Android patterns
        ├── ios_patterns.json  # 45 iOS patterns
        ├── jar_patterns.json  # 49 JAR patterns
        └── exe_patterns.json  # 44 Windows PE patterns
```

---

## Custom Patterns

Create rules in the dashboard (**Intelligence Hub → Custom Rules → New Rule**) or add them directly to `data/custom/user_rules.json`:

```json
{
  "patterns": [
    {
      "id": "custom-001",
      "title": "Dangerous Method Call",
      "severity": "High",
      "category": "Custom",
      "detection": {
        "type": "regex",
        "patterns": [{"pattern": "dangerousMethod\\s*\\(", "file_types": [".java"]}]
      },
      "description": "Calls to dangerousMethod() may allow...",
      "remediation": "Replace with safeMethod().",
      "enabled": true
    }
  ]
}
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-patterns`)
3. Add patterns to the appropriate `data/builtin/*.json` file
4. Submit a pull request

## License

MIT License

## Acknowledgments

- [jadx](https://github.com/skylot/jadx) — APK decompilation
- [pefile](https://github.com/erocarrera/pefile) — Windows PE parsing
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/) — Security guidance
- [Claude](https://claude.ai) — AI-powered analysis
