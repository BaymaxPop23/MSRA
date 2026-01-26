# APK Analyzer

A comprehensive Android APK security vulnerability scanner with pattern-based detection, deep analysis, visualization, and dynamic testing capabilities.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)

## Features

### Security Scanning
- **77+ vulnerability patterns** covering OWASP Mobile Top 10
- **Deep analysis engine** - WebView, Intent, and ContentProvider security analysis
- **Exploitability validation** - Reduces false positives by validating attack paths
- **Manifest analysis** - Exported components, permissions, intent filters

### Visualization
- **Component interaction graphs** - Activities, Services, Receivers, Providers
- **Data flow analysis** - Track data from sources to sinks
- **Class hierarchy diagrams** - Inheritance relationships
- **Entry point mapping** - Attack surface visualization
- **Interactive HTML reports** with Mermaid.js diagrams

### Dynamic Analysis
- **Genymotion/Emulator integration** - Automated runtime testing
- **Frida instrumentation** - Hook and monitor app behavior
- **Network traffic capture** - SSL/TLS inspection
- **Runtime permission testing**

### Threat Intelligence
- **Auto-updating patterns** - Fetch latest vulnerability signatures
- **HackerOne crawler** - Extract patterns from disclosed reports
- **Security blog crawler** - Monitor Oversecured, NowSecure, WithSecure, etc.
- **Pattern review workflow** - Approve/reject extracted patterns

## Requirements

- Python 3.8+
- `jadx` for APK decompilation ([install](https://github.com/skylot/jadx))
- `adb` for device communication
- Optional: `wkhtmltopdf` or `weasyprint` for PDF reports
- Optional: `frida` for dynamic analysis

## Installation

```bash
git clone https://github.com/yourusername/apk-analyzer.git
cd apk-analyzer
```

## Quick Start

```bash
# Scan an APK
python main.py scan app.apk --out report

# Generate visualization
python main.py visualize app.apk --out report

# Open the reports
open report/report.html
open report/visualization.html
```

## Usage

### Scanning APKs

```bash
# Basic scan with auto threat intel update
python main.py scan app.apk --out report

# Skip threat intel update
python main.py scan app.apk --out report --no-update

# Force threat intel update
python main.py scan app.apk --out report --force-update

# Keep decompiled sources
python main.py scan app.apk --out report --keep-decompiled

# Use custom patterns directory
python main.py scan app.apk --out report --patterns-dir ./my-patterns

# Specify jadx path
python main.py scan app.apk --out report --jadx-path /path/to/jadx
```

### Visualization

```bash
# Generate all visualizations
python main.py visualize app.apk --out report

# Generates:
#   - Component Interaction Graph
#   - Call Graph
#   - Data Flow Graph
#   - Class Hierarchy
#   - Entry Points & Attack Surface
```

### Pattern Management

```bash
# List all patterns
python main.py patterns list

# List by category
python main.py patterns list --category WebView

# Show pattern details
python main.py patterns show webview-js-interface

# Show statistics
python main.py patterns stats

# Validate patterns
python main.py patterns validate

# Export patterns
python main.py patterns list --format json > patterns.json
```

### Threat Intelligence Updates

```bash
# Update threat intel (checks if update needed)
python main.py update

# Force update
python main.py update --force

# Show update status
python main.py update --stats
```

### Security Source Crawling

```bash
# Crawl HackerOne reports
export HACKERONE_USERNAME=your_username
export HACKERONE_TOKEN=your_api_token
python main.py crawl hackerone --max 50 --extract

# Crawl security blogs
python main.py crawl blogs --max 20 --extract

# Crawl specific sources
python main.py crawl blogs --sources Oversecured NowSecure --extract

# Review extracted patterns
python main.py crawl review --list
python main.py crawl review --approve h1-123456-webview
python main.py crawl review --reject blog-abc123-crypto
```

### Dynamic Analysis

```bash
# List available devices/emulators
python main.py dynamic --list-devices

# Run dynamic analysis
python main.py dynamic app.apk --out dynamic_report

# Specify device
python main.py dynamic app.apk --device emulator-5554

# Extended timeout
python main.py dynamic app.apk --timeout 600
```

## Vulnerability Categories

| Category | Description | Patterns |
|----------|-------------|----------|
| **WebView** | JavaScript interface, file access, SSL errors | 18 |
| **Intent/DeepLink** | Intent redirect, PendingIntent, broadcast hijacking | 13 |
| **Component Exposure** | Exported activities, services, receivers, providers | 11 |
| **Cryptography** | Weak algorithms, hardcoded keys, insecure random | 9 |
| **Data Storage** | SharedPreferences, SQLite, external storage | 6 |
| **Network** | TLS validation, cleartext traffic, cert pinning | 4 |
| **Permissions** | Dangerous permissions, signature protection | 7 |
| **Logging** | Sensitive data in logs | 3 |
| **Input Validation** | SQL injection, path traversal | 4 |
| **Credentials** | Hardcoded secrets, API keys | 2 |

## Report Features

### HTML Report (`report.html`)
- Summary dashboard with severity breakdown
- Filter by severity, category, or analysis type
- Expandable finding cards with:
  - Description and attack path
  - Code evidence with line numbers
  - ADB proof-of-concept commands (copy button)
  - CWE references
  - Remediation guidance
  - External references

### Visualization Report (`visualization.html`)
- Interactive Mermaid.js diagrams
- Component interaction flows
- Data flow from sources to sinks
- Class hierarchy browser
- Entry point attack surface map

## Custom Patterns

Create custom patterns in JSON format:

```json
{
  "schema_version": "1.0.0",
  "patterns": [
    {
      "id": "custom-vuln-001",
      "title": "Custom Vulnerability",
      "severity": "High",
      "category": "Custom",
      "detection": {
        "type": "regex",
        "patterns": [
          {
            "pattern": "dangerousMethod\\s*\\(",
            "flags": "i",
            "file_types": [".java", ".kt"]
          }
        ]
      },
      "description": "Description of the vulnerability",
      "attack_path": "How an attacker exploits this",
      "remediation": "How to fix it",
      "metadata": {
        "cwe": ["CWE-xxx"],
        "references": ["https://example.com"]
      },
      "enabled": true
    }
  ]
}
```

## Project Structure

```
apk_analyzer/
├── cli.py                 # Command-line interface
├── scanner.py             # Main vulnerability scanner
├── report.py              # HTML/PDF report generation
├── utils.py               # Utility functions
├── patterns/              # Pattern management
│   ├── manager.py         # PatternManager
│   ├── loader.py          # JSON pattern loading
│   ├── validator.py       # Pattern validation
│   └── models.py          # Data models
├── crawler/               # Security source crawlers
│   ├── hackerone.py       # HackerOne API
│   ├── blogs.py           # RSS/Atom feeds
│   ├── extractor.py       # Pattern extraction
│   └── cache.py           # SQLite caching
├── deep_analysis/         # Deep analysis engines
│   ├── engine.py          # Analysis orchestrator
│   ├── webview.py         # WebView analyzer
│   ├── intent.py          # Intent analyzer
│   └── provider.py        # ContentProvider analyzer
├── visualizer/            # Visualization generators
│   ├── analyzer.py        # App structure analysis
│   ├── graphs.py          # Graph builders
│   └── renderer.py        # HTML rendering
├── dynamic/               # Dynamic analysis
│   └── executor.py        # Runtime testing
└── exploitability/        # Exploitability validation
    └── validator.py       # False positive reduction

data/
├── builtin/               # 77+ built-in patterns
│   └── patterns.json
├── community/             # Community patterns
└── crawled/               # Extracted patterns
    └── pending_review/
```

## Security Checks

### Manifest Analysis
- Exported components without permissions
- Debug mode enabled
- Backup enabled
- Cleartext traffic allowed
- Custom permissions without signature protection

### Code Analysis
- SQL injection in ContentProviders
- Path traversal vulnerabilities
- Insecure WebView configurations
- Hardcoded credentials and API keys
- Weak cryptographic implementations
- Insecure random number generation
- Sensitive data logging

### Deep Analysis
- WebView JavaScript interface exposure
- Intent redirect vulnerabilities
- PendingIntent mutable flags
- ContentProvider query injection
- Broadcast receiver hijacking

## Example Output

```
[+] Decompiling APK with jadx...
[+] Scanning decompiled sources...
[+] Pattern stats: 77 patterns loaded
[+] Source files scanned: 18478
[+] Vulnerabilities found: 67
[+] HTML report: /path/to/report/report.html
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add patterns to `data/builtin/patterns.json`
4. Run `python main.py patterns validate`
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [jadx](https://github.com/skylot/jadx) - APK decompilation
- [Mermaid.js](https://mermaid.js.org/) - Diagram rendering
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/) - Security guidance
