# APKSlayer

Android APK security vulnerability scanner with pattern-based detection, deep analysis, visualization, and dynamic testing capabilities.

> *Slay vulnerabilities before they slay your users.*

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)
![Patterns](https://img.shields.io/badge/patterns-77+-orange.svg)

## Highlights

- **Interactive CLI** - Step-by-step wizard for easy usage
- **77+ Security Patterns** - Covering OWASP Mobile Top 10
- **Low False Positives** - Smart detection with context validation
- **Visual Reports** - Interactive graphs and diagrams
- **Zero Dependencies** - Pure Python, stdlib only

## Features

### Security Scanning
- **Pattern-based detection** - 77+ vulnerability patterns with regex and manifest checks
- **Deep analysis engine** - WebView, Intent, and ContentProvider security analysis
- **Exploitability validation** - Reduces false positives by validating attack paths
- **Smart credential detection** - Context-aware to avoid false positives from debug strings

### Interactive CLI
- **Guided wizard** - No need to remember command flags
- **Step-by-step prompts** - APK selection, output config, analysis options
- **Colorful output** - Clear visual feedback with progress indicators
- **Auto-open reports** - View results immediately in browser

### Visualization
- **Interactive filters** - Filter by risk level, category, or search text
- **Component interaction graphs** - Activities, Services, Receivers, Providers
- **Data flow analysis** - Track data with parameters and taint chains
- **Attack surface mapping** - Exported components with ADB test commands
- **Injection point detection** - SQL, Path, Command, XSS, Intent injections
- **Frida script generation** - Ready-to-use hooks for dynamic testing
- **Class hierarchy diagrams** - Inheritance relationships
- **Optimized rendering** - Handles large apps without overflow

### Threat Intelligence
- **Auto-updating patterns** - Fetch latest vulnerability signatures
- **HackerOne crawler** - Extract patterns from disclosed reports
- **Security blog crawler** - Monitor Oversecured, NowSecure, WithSecure, etc.
- **Pattern review workflow** - Approve/reject extracted patterns

### Dynamic Analysis
- **Genymotion/Emulator integration** - Automated runtime testing
- **Enhanced verification engine** - Real exploit verification with evidence collection
- **Device abstraction layer** - ADB fallback with uiautomator2 support
- **Frida instrumentation** - Hook and monitor app behavior (optional)
- **Traffic interception** - mitmproxy integration with leak detection (optional)
- **Graceful degradation** - Works with or without optional dependencies

## Requirements

- Python 3.8+
- `jadx` for APK decompilation ([install](https://github.com/skylot/jadx))
- `adb` for device communication (Android SDK)

## Installation

```bash
# Clone the repository
git clone https://github.com/Sai-Jagadeesh/apkslayer.git
cd apkslayer

# Option 1: Run directly (no install needed)
python main.py

# Option 2: Install as package
pip install -e .

# Then run from anywhere
apkslayer
```

### Installing jadx (required)

```bash
# macOS
brew install jadx

# Linux (Ubuntu/Debian)
sudo apt install jadx

# Or download from: https://github.com/skylot/jadx/releases
```

### Installing adb (for dynamic analysis)

```bash
# macOS
brew install android-platform-tools

# Linux (Ubuntu/Debian)
sudo apt install adb

# Or install Android SDK
```

## Quick Start

### Interactive Mode (Recommended)

Simply run without arguments to launch the interactive wizard:

```bash
python main.py
```

```
    _    ____  _  __     _                _
   / \  |  _ \| |/ /    / \   _ __   __ _| |_   _ _______ _ __
  / _ \ | |_) | ' /    / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 / ___ \|  __/| . \   / ___ \| | | | (_| | | |_| |/ /  __/ |
/_/   \_\_|   |_|\_\ /_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                                            |___/

Android Security Vulnerability Scanner
77+ patterns | Deep Analysis | Visualization

[1/6] What would you like to do?

Select operation:
  > 1. Security Scan - Find vulnerabilities in APK
    2. Visualize - Generate app structure diagrams
    3. Full Analysis - Scan + Visualize
    4. Pattern Management - List/validate patterns
    5. Update Threat Intel - Fetch latest patterns
```

The wizard guides you through:
1. **Operation selection** - Scan, visualize, or both
2. **APK file** - With path validation
3. **Output directory** - Where to save reports
4. **Threat intelligence** - Auto/force/skip updates
5. **Analysis options** - Keep sources, custom patterns
6. **Confirmation** - Review settings before starting

### Command Line Mode

```bash
# Scan an APK
python main.py scan app.apk --out report

# Generate visualization
python main.py visualize app.apk --out report

# Full analysis (scan + visualize)
python main.py scan app.apk --out report
python main.py visualize app.apk --out report
```

## Usage Examples

### Scanning APKs

```bash
# Basic scan with auto threat intel update
python main.py scan app.apk --out report

# Skip threat intel update
python main.py scan app.apk --out report --no-update

# Force threat intel update
python main.py scan app.apk --out report --force-update

# Keep decompiled sources for manual review
python main.py scan app.apk --out report --keep-decompiled

# Use custom patterns directory
python main.py scan app.apk --out report --patterns-dir ./my-patterns
```

### Visualization

```bash
# Generate visualization report
python main.py visualize app.apk --out report

# Generates visualization.html with:
#   - Filter bar (risk level, category, search)
#   - Data Flow Details (with parameters & taint chains)
#   - Attack Surface (ADB commands, deep links, Frida hooks)
#   - Injection Points (SQL, Path, Command, XSS, Intent)
#   - Frida Scripts (SSL bypass, crypto logging, etc.)
#   - Component/Call/Data Flow graphs
#   - Class Hierarchy diagram
```

### Pattern Management

```bash
# List all patterns
python main.py patterns list

# Show pattern statistics
python main.py patterns stats

# Validate patterns
python main.py patterns validate

# Export patterns as JSON
python main.py patterns list --format json > patterns.json
```

### Threat Intelligence

```bash
# Update threat intel (auto-checks if needed)
python main.py update

# Force update
python main.py update --force

# Show update status
python main.py update --stats

# Crawl HackerOne for new patterns
export HACKERONE_USERNAME=your_username
export HACKERONE_TOKEN=your_api_token
python main.py crawl hackerone --max 50 --extract

# Crawl security blogs
python main.py crawl blogs --max 20 --extract
```

### Dynamic Analysis

```bash
# List available devices/emulators
python main.py dynamic --list-devices

# Run basic dynamic analysis (legacy mode)
python main.py dynamic app.apk --out dynamic_report

# Run enhanced dynamic analysis with verification
python main.py dynamic app.apk --out dynamic_report --enhanced

# Enhanced mode with aggressive testing (SSL/root bypass)
python main.py dynamic app.apk --enhanced --mode aggressive

# Specify device and timeout
python main.py dynamic app.apk --device emulator-5554 --timeout 600

# Disable optional features
python main.py dynamic app.apk --enhanced --no-frida --no-traffic
```

#### Enhanced Dynamic Analysis Options

| Option | Description |
|--------|-------------|
| `--enhanced` | Use new verification engine with evidence collection |
| `--mode` | Analysis mode: `passive`, `active`, `aggressive` |
| `--no-frida` | Disable Frida instrumentation |
| `--no-traffic` | Disable traffic interception |
| `--no-ui-automation` | Use basic ADB only |
| `--proxy-port` | Proxy port for traffic capture (default: 8080) |
| `--explore-depth` | UI exploration depth (default: 5) |

#### Optional Dependencies for Enhanced Mode

```bash
# For UI automation (recommended)
pip install uiautomator2

# For runtime instrumentation (requires rooted device or frida-gadget)
pip install frida-tools

# For traffic interception
pip install mitmproxy
```

The enhanced mode gracefully degrades when optional dependencies aren't available.

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

## Report Features

### Security Report (`report.html`)
- Summary dashboard with severity breakdown (Critical/High/Medium/Low)
- Filter by severity, category, or analysis type
- Expandable finding cards with:
  - Vulnerability description and attack path
  - Code evidence with file path and line numbers
  - ADB proof-of-concept commands (one-click copy)
  - CWE references and external links
  - Remediation guidance

### Visualization Report (`visualization.html`)
- **Filter bar** - Filter findings by risk level, category, or search text
- **Data Flow Details** - Source-to-sink analysis with:
  - Risk levels (Critical/High/Medium/Low)
  - Parameters involved in the flow
  - Taint chain showing variable propagation
- **Attack Surface** - Exported components with:
  - Ready-to-use ADB commands (one-click copy)
  - Deep link URLs for testing
  - Frida hooks for runtime analysis
- **Injection Points** - Potential vulnerabilities:
  - SQL, Path Traversal, Command, XSS, Intent injection
  - Exploit examples for each finding
- **Frida Scripts** - Pre-built scripts for:
  - SSL pinning bypass
  - Crypto operation logging
  - Intent monitoring
  - File operation tracking
- **Interactive diagrams** - Mermaid.js graphs for components, calls, data flow
- **Optimized rendering** - Handles large applications (auto-limits nodes)

## Project Structure

```
apkslayer/
├── main.py                # Entry point
├── apk_analyzer/
│   ├── cli.py             # Interactive & command-line interface
│   ├── scanner.py         # Vulnerability scanner
│   ├── report.py          # HTML/PDF report generation
│   ├── utils.py           # Utility functions
│   ├── patterns/          # Pattern management
│   │   ├── manager.py     # PatternManager
│   │   ├── loader.py      # JSON pattern loading
│   │   ├── validator.py   # Pattern validation
│   │   └── models.py      # Data models
│   ├── crawler/           # Security source crawlers
│   │   ├── hackerone.py   # HackerOne API
│   │   ├── blogs.py       # RSS/Atom feeds
│   │   └── extractor.py   # Pattern extraction
│   ├── deep_analysis/     # Deep analysis engines
│   │   ├── webview.py     # WebView analyzer
│   │   ├── intent.py      # Intent analyzer
│   │   └── provider.py    # ContentProvider analyzer
│   ├── visualizer/        # Visualization generators
│   │   ├── analyzer.py    # App structure analysis
│   │   ├── graphs.py      # Graph builders (with size limits)
│   │   └── renderer.py    # HTML rendering
│   └── dynamic/           # Dynamic analysis
│       ├── executor.py    # Test executor (legacy + enhanced)
│       ├── genymotion.py  # Genymotion/emulator control
│       ├── monitor.py     # App monitoring
│       ├── config.py      # Configuration management
│       ├── exceptions.py  # Custom exceptions
│       ├── device/        # Device abstraction layer
│       │   ├── base.py    # DeviceInterface ABC
│       │   ├── adb_device.py      # ADB fallback
│       │   └── uiautomator_device.py  # uiautomator2
│       ├── automation/    # UI automation
│       │   ├── navigator.py       # Screen exploration
│       │   └── form_filler.py     # Form detection/filling
│       ├── instrumentation/  # Frida integration
│       │   ├── frida_manager.py   # Session management
│       │   └── hooks/     # JS hook scripts
│       ├── verification/  # Exploit verification
│       │   ├── base.py    # BaseVerifier ABC
│       │   ├── webview.py # WebView XSS verification
│       │   ├── provider.py # SQLi/traversal verification
│       │   ├── intent.py  # Intent verification
│       │   └── deeplink.py # Deep link verification
│       └── traffic/       # Traffic interception
│           ├── proxy.py   # mitmproxy management
│           └── analyzer.py # Leak detection
└── data/
    └── builtin/           # 77+ built-in patterns
        └── patterns.json
```

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

## Example Output

```
$ python main.py scan app.apk --out report

[+] Decompiling APK with jadx...
[+] Scanning decompiled sources...
[+] Pattern stats: 77 patterns loaded
[+] Source files scanned: 18478
[+] Vulnerabilities found: 67
[+] HTML report: /path/to/report/report.html
```

## Recent Updates

### v2.0 - Enhanced Dynamic Analysis
- **Enhanced Dynamic Executor** - New verification engine with real exploit confirmation
- **Device Abstraction Layer** - Unified interface for ADB, uiautomator2, Genymotion
- **UI Automation** - Screen exploration, form detection, and payload injection
- **Frida Integration** - SSL bypass, root bypass, API monitoring hooks
- **Traffic Interception** - mitmproxy integration with sensitive data leak detection
- **Exploit Verifiers** - WebView XSS, Provider SQLi, Intent hijacking, DeepLink injection
- **Graceful Degradation** - Works without optional dependencies (Frida, mitmproxy)
- **Evidence Collection** - Screenshots, hook results, traffic logs for verified vulns

### Previous Updates
- **Visualization Filters** - Filter findings by risk level, category, or search text
- **Enhanced Data Flow** - Parameters, taint chains, and risk level analysis
- **Attack Surface Mapping** - ADB commands, deep links, and Frida hooks for testing
- **Injection Detection** - SQL, Path, Command, XSS, Intent injection points
- **Frida Script Generation** - Ready-to-use hooks for dynamic analysis
- **APKM Bundle Support** - Auto-detects and extracts split APKs from APKMirror
- **Organized Reports** - Saved to `reports/<package_name>/` directory
- **Interactive CLI** - Step-by-step wizard for easy usage
- **Improved Credential Detection** - Reduced false positives from debug/log strings

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
