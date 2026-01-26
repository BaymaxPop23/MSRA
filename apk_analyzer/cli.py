"""Command-line interface for APK Analyzer."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Tuple

from .report import generate_html_report, render_pdf_from_html
from .scanner import Scanner
from .patterns import PatternManager, PatternConfig
from .utils import iter_source_files
from .dynamic import GenymotionController, DynamicTestExecutor, AppMonitor
from .crawler import ThreatIntelUpdater, UpdateConfig
from .visualizer import AppStructureAnalyzer, VisualizationRenderer, VisualizationConfig


# ============================================================================
# Interactive Mode Helpers
# ============================================================================

class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

    # Check if colors should be disabled
    _enabled = True

    @classmethod
    def disable(cls):
        """Disable all colors."""
        cls._enabled = False
        cls.HEADER = cls.BLUE = cls.CYAN = cls.GREEN = ''
        cls.YELLOW = cls.RED = cls.BOLD = cls.UNDERLINE = cls.END = ''

    @classmethod
    def enable(cls):
        """Enable colors."""
        cls._enabled = True
        cls.HEADER = '\033[95m'
        cls.BLUE = '\033[94m'
        cls.CYAN = '\033[96m'
        cls.GREEN = '\033[92m'
        cls.YELLOW = '\033[93m'
        cls.RED = '\033[91m'
        cls.BOLD = '\033[1m'
        cls.UNDERLINE = '\033[4m'
        cls.END = '\033[0m'


def print_banner():
    """Print the APK Analyzer banner."""
    banner = """
    _    ____  _  __     _                _
   / \\  |  _ \\| |/ /    / \\   _ __   __ _| |_   _ _______ _ __
  / _ \\ | |_) | ' /    / _ \\ | '_ \\ / _` | | | | |_  / _ \\ '__|
 / ___ \\|  __/| . \\   / ___ \\| | | | (_| | | |_| |/ /  __/ |
/_/   \\_\\_|   |_|\\_\\ /_/   \\_\\_| |_|\\__,_|_|\\__, /___\\___|_|
                                            |___/

Android Security Vulnerability Scanner
77+ patterns | Deep Analysis | Visualization
"""
    print(banner, flush=True)


def print_step(step: int, total: int, message: str):
    """Print a step indicator."""
    print(f"\n[{step}/{total}] {message}")


def print_success(message: str):
    """Print a success message."""
    print(f"[OK] {message}")


def print_error(message: str):
    """Print an error message."""
    print(f"[ERROR] {message}")


def print_info(message: str):
    """Print an info message."""
    print(f"[INFO] {message}")


def prompt_input(prompt: str, default: str = None) -> str:
    """Prompt for input with optional default."""
    if default:
        display = f"{prompt} [{default}]: "
    else:
        display = f"{prompt}: "

    try:
        # Print prompt and flush before reading
        sys.stdout.write(display)
        sys.stdout.flush()
        value = sys.stdin.readline().strip()
        return value if value else default
    except (KeyboardInterrupt, EOFError):
        print("\n")
        sys.exit(0)


def prompt_choice(prompt: str, choices: List[Tuple[str, str]], default: int = 1) -> str:
    """Prompt for a choice from a list."""
    print(f"\n{prompt}")
    for i, (key, description) in enumerate(choices, 1):
        marker = ">" if i == default else " "
        print(f"  {marker} {i}. {description}")

    while True:
        try:
            sys.stdout.write(f"\nEnter choice [{default}]: ")
            sys.stdout.flush()
            choice = sys.stdin.readline().strip()
            if not choice:
                return choices[default - 1][0]
            idx = int(choice)
            if 1 <= idx <= len(choices):
                return choices[idx - 1][0]
            print(f"Please enter a number between 1 and {len(choices)}")
        except ValueError:
            print("Please enter a valid number")
        except (KeyboardInterrupt, EOFError):
            print("\n")
            sys.exit(0)


def prompt_yes_no(prompt: str, default: bool = True) -> bool:
    """Prompt for yes/no with default."""
    default_str = "Y/n" if default else "y/N"
    try:
        sys.stdout.write(f"{prompt} [{default_str}]: ")
        sys.stdout.flush()
        response = sys.stdin.readline().strip().lower()
        if not response:
            return default
        return response in ('y', 'yes', 'true', '1')
    except (KeyboardInterrupt, EOFError):
        print("\n")
        sys.exit(0)


def prompt_file(prompt: str, must_exist: bool = True, extension: str = None) -> str:
    """Prompt for a file path with validation."""
    while True:
        path = prompt_input(prompt)
        if not path:
            print_error("Please enter a path")
            continue

        path = os.path.expanduser(path)
        path = os.path.abspath(path)

        if must_exist and not os.path.exists(path):
            print_error(f"File not found: {path}")
            continue

        if extension and not path.endswith(extension):
            print_error(f"File must have {extension} extension")
            continue

        return path


def interactive_mode() -> int:
    """Run interactive mode for APK analysis."""
    print_banner()

    total_steps = 6

    # Step 1: Select operation mode
    print_step(1, total_steps, "What would you like to do?")
    operation = prompt_choice("Select operation:", [
        ("scan", "Security Scan - Find vulnerabilities in APK"),
        ("visualize", "Visualize - Generate app structure diagrams"),
        ("both", "Full Analysis - Scan + Visualize"),
        ("patterns", "Pattern Management - List/validate patterns"),
        ("update", "Update Threat Intel - Fetch latest patterns"),
    ])

    if operation == "patterns":
        return cmd_patterns_interactive()

    if operation == "update":
        return cmd_update_interactive()

    # Step 2: APK file
    print_step(2, total_steps, "Select APK file")
    apk_path = prompt_file("Enter path to APK file", must_exist=True, extension=".apk")
    print_success(f"APK: {os.path.basename(apk_path)}")

    # Step 3: Output directory
    print_step(3, total_steps, "Output settings")
    default_out = os.path.join(os.path.dirname(apk_path), "analysis_output")
    out_dir = prompt_input("Output directory", default=default_out)
    out_dir = os.path.abspath(os.path.expanduser(out_dir))
    print_success(f"Output: {out_dir}")

    # Step 4: Threat intelligence
    print_step(4, total_steps, "Threat Intelligence")
    update_mode = prompt_choice("Update threat patterns before scan?", [
        ("auto", "Auto - Update if older than 24 hours (Recommended)"),
        ("force", "Force - Always fetch latest patterns"),
        ("skip", "Skip - Use existing patterns only"),
    ])

    # Step 5: Analysis options
    print_step(5, total_steps, "Analysis Options")

    keep_decompiled = prompt_yes_no("Keep decompiled sources after analysis?", default=False)

    custom_patterns = prompt_yes_no("Use custom patterns directory?", default=False)
    patterns_dir = None
    if custom_patterns:
        patterns_dir = prompt_input("Custom patterns directory path")
        if patterns_dir:
            patterns_dir = os.path.abspath(os.path.expanduser(patterns_dir))

    # Step 6: Confirmation
    print_step(6, total_steps, "Review & Confirm")
    print(f"""
Analysis Configuration:
  APK File:        {os.path.basename(apk_path)}
  Output:          {out_dir}
  Operation:       {operation.title()}
  Threat Intel:    {update_mode.title()}
  Keep Sources:    {'Yes' if keep_decompiled else 'No'}
  Custom Patterns: {patterns_dir if patterns_dir else 'None'}
""")

    if not prompt_yes_no("Proceed with analysis?", default=True):
        print_info("Analysis cancelled")
        return 0

    print(f"\n{'='*60}")
    print("Starting Analysis...")
    print(f"{'='*60}\n")

    # Build args object
    class Args:
        pass

    args = Args()
    args.apk = apk_path
    args.out = out_dir
    args.jadx_path = None
    args.adb_path = "adb"
    args.patterns_dir = patterns_dir
    args.keep_decompiled = keep_decompiled
    args.no_update = (update_mode == "skip")
    args.force_update = (update_mode == "force")
    args.quiet_update = False

    # Run scan
    if operation in ("scan", "both"):
        result = cmd_scan(args)
        if result != 0:
            return result

    # Run visualization
    if operation in ("visualize", "both"):
        args.no_components = False
        args.no_calls = False
        args.no_dataflow = False
        args.no_hierarchy = False
        result = cmd_visualize(args)
        if result != 0:
            return result

    # Final summary
    print(f"\n{'='*60}")
    print("Analysis Complete!")
    print(f"{'='*60}")
    print(f"\nOutput Files:")

    if operation in ("scan", "both"):
        print(f"  Report:        {os.path.join(out_dir, 'report.html')}")
    if operation in ("visualize", "both"):
        print(f"  Visualization: {os.path.join(out_dir, 'visualization.html')}")

    # Offer to open reports
    print()
    if prompt_yes_no("Open reports in browser?", default=True):
        if operation in ("scan", "both"):
            _open_file(os.path.join(out_dir, "report.html"))
        if operation in ("visualize", "both"):
            _open_file(os.path.join(out_dir, "visualization.html"))

    return 0


def cmd_patterns_interactive() -> int:
    """Interactive pattern management."""
    print_step(1, 1, "Pattern Management")

    action = prompt_choice("Select action:", [
        ("list", "List all patterns"),
        ("stats", "Show pattern statistics"),
        ("validate", "Validate all patterns"),
        ("search", "Search patterns"),
    ])

    manager = PatternManager()
    manager.load_all()

    if action == "list":
        print(f"\nLoaded Patterns:\n")
        print(f"{'ID':<35} {'Title':<40} {'Severity':<10}")
        print("-" * 90)
        for p in manager.get_patterns(enabled_only=True):
            title = p.title[:38] + ".." if len(p.title) > 40 else p.title
            print(f"{p.id:<35} {title:<40} {p.severity.value:<10}")

        stats = manager.stats
        print(f"\nTotal: {stats['total']} | Enabled: {stats['enabled']}")

    elif action == "stats":
        stats = manager.stats
        print(f"\nPattern Statistics")
        print("=" * 40)
        print(f"Total patterns: {stats['total']}")
        print(f"Enabled: {stats['enabled']}")
        print(f"\nBy Severity:")
        for sev, count in sorted(stats['by_severity'].items()):
            print(f"  {sev}: {count}")
        print(f"\nBy Category:")
        for cat, count in sorted(stats['by_category'].items()):
            print(f"  {cat}: {count}")

    elif action == "validate":
        issues = manager.validate_all()
        if not issues:
            print_success("All patterns are valid!")
        else:
            print_error(f"Found issues in {len(issues)} patterns:")
            for pattern_id, pattern_issues in issues.items():
                print(f"\n  {pattern_id}:")
                for issue in pattern_issues:
                    print(f"    - {issue}")

    elif action == "search":
        query = prompt_input("Search query")
        results = manager.search_patterns(query)
        if results:
            print(f"\nFound {len(results)} patterns:\n")
            for p in results:
                print(f"  {p.id}: {p.title}")
        else:
            print_info("No patterns found matching query")

    return 0


def cmd_update_interactive() -> int:
    """Interactive threat intel update."""
    print_step(1, 1, "Threat Intelligence Update")

    config = UpdateConfig()
    updater = ThreatIntelUpdater(config)

    # Show current status
    stats = updater.get_stats()
    print(f"\nCurrent Status:")
    print(f"  Last update: {stats['last_update'] or 'Never'}")
    print(f"  Patterns pending review: {stats['pending_patterns']}")

    action = prompt_choice("\nSelect action:", [
        ("update", "Update now (skip if recent)"),
        ("force", "Force update"),
        ("cancel", "Cancel"),
    ])

    if action == "cancel":
        return 0

    print(f"\nUpdating threat intelligence...\n")
    result = updater.update(force=(action == "force"))

    if result.success:
        print_success("Update completed successfully")
    else:
        print_error("Update completed with errors")
        for error in result.errors:
            print(f"  - {error}")

    return 0


def _open_file(path: str):
    """Open a file with the default application."""
    import platform
    try:
        if platform.system() == "Darwin":
            subprocess.run(["open", path], check=False)
        elif platform.system() == "Windows":
            os.startfile(path)
        else:
            subprocess.run(["xdg-open", path], check=False)
    except Exception:
        pass


def _find_jadx(jadx_path: Optional[str]) -> str:
    """Locate jadx executable."""
    if jadx_path:
        return jadx_path
    for candidate in ("jadx", "jadx-cli"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    # Common macOS Jadx GUI install path
    mac_gui = "/Applications/jadx-gui.app/Contents/Resources/jadx/bin/jadx"
    if os.path.exists(mac_gui):
        return mac_gui
    return ""


def _ensure_dir(path: str) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)


def _decompile(apk_path: str, out_dir: str, jadx_path: str) -> None:
    """Decompile APK using jadx."""
    cmd = [jadx_path, "-d", out_dir, apk_path]
    subprocess.run(cmd, check=False)


def _update_threat_intel(force: bool = False, quiet: bool = False) -> None:
    """Update threat intelligence feeds by crawling security sources."""
    config = UpdateConfig()
    updater = ThreatIntelUpdater(config)
    updater.update(force=force, quiet=quiet)


def cmd_scan(args) -> int:
    """Scan APK for vulnerabilities."""
    apk_path = os.path.abspath(args.apk)
    if not os.path.exists(apk_path):
        print(f"APK not found: {apk_path}", file=sys.stderr)
        return 2

    jadx_path = _find_jadx(args.jadx_path)
    if not jadx_path:
        print("jadx not found. Install jadx-cli or pass --jadx-path.", file=sys.stderr)
        return 2

    # Update threat intelligence before scanning
    if not args.no_update:
        _update_threat_intel(force=args.force_update, quiet=args.quiet_update)

    out_dir = os.path.abspath(args.out)
    _ensure_dir(out_dir)

    decompiled_dir = os.path.join(out_dir, "decompiled")
    _ensure_dir(decompiled_dir)

    print("[+] Decompiling APK with jadx...")
    _decompile(apk_path, decompiled_dir, jadx_path)

    manifest_guess = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    sources_guess = os.path.join(decompiled_dir, "sources")
    if not os.path.exists(manifest_guess) and not os.path.exists(sources_guess):
        print("[!] Decompiled output appears empty. Jadx may have failed.", file=sys.stderr)

    # Configure pattern loading
    pattern_config = PatternConfig()
    if args.patterns_dir:
        pattern_config.custom_patterns_dir = Path(args.patterns_dir)

    print("[+] Scanning decompiled sources...")
    scanner = Scanner(decompiled_dir, adb_path=args.adb_path, pattern_config=pattern_config)
    findings = scanner.scan()
    source_file_count = sum(1 for _ in iter_source_files(decompiled_dir))

    print(f"[+] Pattern stats: {scanner.pattern_stats.get('total', 0)} patterns loaded")
    print(f"[+] Source files scanned: {source_file_count}")
    print(f"[+] Vulnerabilities found: {len(findings)}")

    # Generate reports
    html_path = os.path.join(out_dir, "report.html")
    metadata = {
        "title": "APK Analyzer Security Report",
        "package": scanner.package_name or "unknown",
        "apk": os.path.basename(apk_path),
        "scan_time": datetime.now().isoformat(),
        "patterns_loaded": scanner.pattern_stats.get('total', 0),
    }
    generate_html_report(findings, html_path, metadata)
    print(f"[+] HTML report: {html_path}")

    pdf_path = os.path.join(out_dir, "report.pdf")
    pdf_rendered = render_pdf_from_html(html_path, pdf_path)
    if pdf_rendered:
        print(f"[+] PDF report: {pdf_path}")
    else:
        print("[!] PDF renderer not available. Install wkhtmltopdf or weasyprint.")

    # Cleanup
    if not findings and not args.keep_decompiled:
        print("[!] No findings detected; keeping decompiled output for inspection.")
    elif not args.keep_decompiled:
        shutil.rmtree(decompiled_dir, ignore_errors=True)
        print("[+] Cleaned decompiled output.")

    return 0


def cmd_patterns_list(args) -> int:
    """List loaded patterns."""
    manager = PatternManager()
    manager.load_all()

    if args.format == "json":
        patterns = []
        for p in manager.get_patterns(enabled_only=not args.all):
            patterns.append({
                "id": p.id,
                "title": p.title,
                "severity": p.severity.value,
                "category": p.category.value,
                "enabled": p.enabled,
            })
        print(json.dumps(patterns, indent=2))
    else:
        print(f"\n{'ID':<35} {'Title':<40} {'Severity':<10} {'Category':<25}")
        print("-" * 115)
        for p in manager.get_patterns(enabled_only=not args.all):
            title = p.title[:38] + ".." if len(p.title) > 40 else p.title
            print(f"{p.id:<35} {title:<40} {p.severity.value:<10} {p.category.value:<25}")

    stats = manager.stats
    print(f"\nTotal: {stats['total']} | Enabled: {stats['enabled']}")
    print(f"By severity: {stats['by_severity']}")

    return 0


def cmd_patterns_show(args) -> int:
    """Show pattern details."""
    manager = PatternManager()
    manager.load_all()

    pattern = manager.get_pattern(args.pattern_id)
    if not pattern:
        print(f"Pattern not found: {args.pattern_id}", file=sys.stderr)
        return 1

    print(f"\nPattern: {pattern.id}")
    print(f"Title: {pattern.title}")
    print(f"Severity: {pattern.severity.value}")
    print(f"Category: {pattern.category.value}")
    print(f"Enabled: {pattern.enabled}")
    print(f"\nDescription:\n{pattern.description}")
    print(f"\nAttack Path:\n{pattern.attack_path}")
    if pattern.remediation:
        print(f"\nRemediation:\n{pattern.remediation}")
    if pattern.metadata.cwe:
        print(f"\nCWE: {', '.join(pattern.metadata.cwe)}")
    if pattern.metadata.cve:
        print(f"CVE: {', '.join(pattern.metadata.cve)}")
    if pattern.metadata.references:
        print(f"\nReferences:")
        for ref in pattern.metadata.references:
            print(f"  - {ref}")

    return 0


def cmd_patterns_validate(args) -> int:
    """Validate all patterns."""
    manager = PatternManager()
    manager.load_all()

    issues = manager.validate_all()
    if not issues:
        print("All patterns valid.")
        return 0

    print(f"Found issues in {len(issues)} patterns:\n")
    for pattern_id, pattern_issues in issues.items():
        print(f"{pattern_id}:")
        for issue in pattern_issues:
            print(f"  - {issue}")

    return 1


def cmd_patterns_stats(args) -> int:
    """Show pattern statistics."""
    manager = PatternManager()
    manager.load_all()

    stats = manager.stats
    print("\nPattern Statistics")
    print("=" * 40)
    print(f"Total patterns: {stats['total']}")
    print(f"Enabled: {stats['enabled']}")
    print(f"\nBy severity:")
    for sev, count in sorted(stats['by_severity'].items()):
        print(f"  {sev}: {count}")
    print(f"\nBy category:")
    for cat, count in sorted(stats['by_category'].items()):
        print(f"  {cat}: {count}")
    print(f"\nSources loaded: {stats['sources_loaded']}")

    return 0


def cmd_crawl_hackerone(args) -> int:
    """Crawl HackerOne for Android vulnerability reports."""
    from .crawler import HackerOneCrawler, HackerOneConfig, PatternExtractor

    config = HackerOneConfig(
        api_username=os.environ.get("HACKERONE_USERNAME"),
        api_token=os.environ.get("HACKERONE_TOKEN"),
        min_severity=args.min_severity,
    )

    crawler = HackerOneCrawler(config)

    since = None
    if args.since:
        since = datetime.fromisoformat(args.since)

    print(f"[+] Fetching HackerOne disclosed reports (max: {args.max})...")
    reports = list(crawler.fetch_reports(since=since, max_reports=args.max))
    print(f"[+] Found {len(reports)} Android-related reports")

    if args.extract:
        extractor = PatternExtractor()
        extracted_count = 0

        for report in reports:
            result = extractor.extract_from_hackerone(report)
            if result.success:
                for pattern in result.patterns:
                    extractor.save_pattern(pattern, pending_review=True)
                    extracted_count += 1
                print(f"  Extracted {len(result.patterns)} patterns from: {report.title[:50]}")

        print(f"\n[+] Total patterns extracted: {extracted_count}")
        print(f"[+] Patterns saved to pending_review folder for approval")
    else:
        for report in reports[:10]:  # Show first 10
            print(f"  [{report.severity.upper()}] {report.title[:60]}")
            print(f"    URL: {report.report_url}")

    return 0


def cmd_crawl_blogs(args) -> int:
    """Crawl security blogs for Android vulnerability writeups."""
    from .crawler import BlogCrawler, PatternExtractor

    crawler = BlogCrawler()

    if args.sources:
        print(f"[+] Crawling specified sources: {args.sources}")
    else:
        print(f"[+] Crawling all configured sources: {crawler.list_sources()}")

    articles = []
    if args.sources:
        for source in args.sources:
            articles.extend(crawler.crawl_source(source, max_articles=args.max))
    else:
        articles = list(crawler.crawl_all_sources(max_articles_per_source=args.max))

    print(f"[+] Found {len(articles)} Android-related articles")

    if args.extract:
        extractor = PatternExtractor()
        extracted_count = 0

        for article in articles:
            result = extractor.extract_from_blog(article)
            if result.success:
                for pattern in result.patterns:
                    extractor.save_pattern(pattern, pending_review=True)
                    extracted_count += 1
                print(f"  Extracted {len(result.patterns)} patterns from: {article.title[:50]}")

        print(f"\n[+] Total patterns extracted: {extracted_count}")
        print(f"[+] Patterns saved to pending_review folder for approval")
    else:
        for article in articles[:10]:
            print(f"  {article.title[:60]}")
            print(f"    Source: {article.source} | URL: {article.url}")

    return 0


def cmd_crawl_review(args) -> int:
    """Review and approve/reject extracted patterns."""
    from .crawler import PatternExtractor

    extractor = PatternExtractor()

    if args.list:
        pending = extractor.list_pending()
        if not pending:
            print("No patterns pending review.")
            return 0

        print(f"\nPatterns pending review ({len(pending)}):\n")
        print(f"{'ID':<40} {'Severity':<10} {'Title':<40}")
        print("-" * 95)
        for p in pending:
            title = p['title'][:38] + ".." if len(p['title']) > 40 else p['title']
            print(f"{p['id']:<40} {p['severity']:<10} {title:<40}")
        return 0

    if args.approve:
        for pattern_id in args.approve:
            if extractor.approve_pattern(pattern_id):
                print(f"Approved: {pattern_id}")
            else:
                print(f"Failed to approve: {pattern_id}", file=sys.stderr)

    if args.reject:
        for pattern_id in args.reject:
            if extractor.reject_pattern(pattern_id):
                print(f"Rejected: {pattern_id}")
            else:
                print(f"Failed to reject: {pattern_id}", file=sys.stderr)

    return 0


def cmd_dynamic(args) -> int:
    """Run dynamic analysis on APK using Genymotion/emulator."""
    # Initialize controller
    controller = GenymotionController(adb_path=args.adb_path)

    # Handle list-devices first (doesn't need APK)
    if args.list_devices:
        devices = controller.list_devices()
        if not devices:
            print("No devices found. Start Genymotion or connect a device.")
            return 1
        print(f"\nAvailable devices ({len(devices)}):\n")
        print(f"{'Serial':<25} {'Model':<20} {'State':<10} {'Type':<15} {'API':<5}")
        print("-" * 80)
        for d in devices:
            dtype = "Genymotion" if d.is_genymotion else ("Emulator" if d.is_emulator else "Physical")
            api = str(d.api_level) if d.api_level else "?"
            print(f"{d.serial:<25} {d.model:<20} {d.state:<10} {dtype:<15} {api:<5}")
        return 0

    # APK is required for actual analysis
    if not args.apk:
        print("APK path is required for dynamic analysis.", file=sys.stderr)
        print("Use --list-devices to see available devices.", file=sys.stderr)
        return 2

    apk_path = os.path.abspath(args.apk)
    if not os.path.exists(apk_path):
        print(f"APK not found: {apk_path}", file=sys.stderr)
        return 2

    out_dir = os.path.abspath(args.out)
    _ensure_dir(out_dir)

    # Connect to device
    print("[+] Connecting to device/emulator...")
    if not controller.connect(serial=args.device):
        return 1

    # Run static scan first if not skipped
    findings = []
    if not args.skip_static:
        jadx_path = _find_jadx(args.jadx_path)
        if not jadx_path:
            print("[!] jadx not found. Skipping static analysis.")
        else:
            print("\n[+] Running static analysis first...")
            decompiled_dir = os.path.join(out_dir, "decompiled")
            _ensure_dir(decompiled_dir)

            print("[+] Decompiling APK with jadx...")
            _decompile(apk_path, decompiled_dir, jadx_path)

            pattern_config = PatternConfig()
            scanner = Scanner(decompiled_dir, adb_path=args.adb_path, pattern_config=pattern_config)
            findings = scanner.scan()
            print(f"[+] Static analysis found {len(findings)} vulnerabilities")

            # Filter to testable findings
            testable_categories = ['webview', 'intent', 'provider', 'component', 'network']
            testable_findings = [
                f for f in findings
                if any(cat in f.get('category', '').lower() for cat in testable_categories)
                or f.get('severity') in ['critical', 'high']
            ]
            print(f"[+] {len(testable_findings)} findings are testable dynamically")
            findings = testable_findings

    # Extract package name from APK
    print("\n[+] Extracting package name from APK...")
    try:
        import zipfile
        from xml.etree import ElementTree as ET

        with zipfile.ZipFile(apk_path, 'r') as apk:
            # Try to read AndroidManifest.xml (binary format)
            # Use aapt if available for accurate parsing
            result = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                if line.startswith("package:"):
                    # Parse: package: name='com.example' versionCode='1' ...
                    for part in line.split():
                        if part.startswith("name='"):
                            package_name = part.split("'")[1]
                            break
                    break
            else:
                print("[!] Could not extract package name. Specify with --package.")
                return 1
    except Exception as e:
        if args.package:
            package_name = args.package
        else:
            print(f"[!] Could not extract package name: {e}")
            print("[!] Specify with --package.")
            return 1

    print(f"[+] Package: {package_name}")

    # Initialize dynamic test executor
    executor = DynamicTestExecutor(
        controller=controller,
        package_name=package_name,
        apk_path=apk_path,
        findings=findings,
        output_dir=out_dir
    )

    # Setup (install app, start monitoring)
    print("\n[+] Setting up dynamic analysis...")
    if not executor.setup():
        print("[!] Setup failed")
        return 1

    # Run tests
    print("\n[+] Running dynamic tests...")
    print("-" * 60)
    results = executor.run_tests(timeout=args.timeout)

    # Print results summary
    print("\n" + "=" * 60)
    print("DYNAMIC ANALYSIS RESULTS")
    print("=" * 60)

    confirmed = [r for r in results if r.test_status == 'confirmed']
    likely = [r for r in results if r.test_status == 'likely_vulnerable']
    inconclusive = [r for r in results if r.test_status == 'inconclusive']
    not_vuln = [r for r in results if r.test_status == 'not_vulnerable']

    print(f"\nConfirmed vulnerabilities: {len(confirmed)}")
    for r in confirmed:
        print(f"  [{r.severity.upper()}] {r.finding_title}")
        if r.evidence:
            print(f"    Evidence: {r.evidence[:100]}...")

    print(f"\nLikely vulnerable: {len(likely)}")
    for r in likely:
        print(f"  [{r.severity.upper()}] {r.finding_title}")

    print(f"\nInconclusive: {len(inconclusive)}")
    print(f"Not vulnerable: {len(not_vuln)}")

    # Check for crashes/sensitive data leaks
    report = executor.get_report()
    if report.crashes_detected:
        print(f"\n[!] CRASHES DETECTED: {report.crashes_detected}")
    if report.sensitive_data_leaks:
        print(f"\n[!] SENSITIVE DATA LEAKS: {report.sensitive_data_leaks}")

    # Export report
    report_path = os.path.join(out_dir, "dynamic_report.json")
    executor.export_report(report_path)
    print(f"\n[+] Dynamic report saved: {report_path}")

    # Cleanup
    executor.cleanup()

    # Generate combined HTML report if we have static findings
    if findings:
        html_path = os.path.join(out_dir, "combined_report.html")
        metadata = {
            "title": "APK Analyzer - Combined Security Report",
            "package": package_name,
            "apk": os.path.basename(apk_path),
            "scan_time": datetime.now().isoformat(),
            "dynamic_results": {
                "confirmed": len(confirmed),
                "likely": len(likely),
                "inconclusive": len(inconclusive),
                "not_vulnerable": len(not_vuln),
                "crashes": report.crashes_detected,
                "leaks": report.sensitive_data_leaks,
            }
        }
        generate_html_report(findings, html_path, metadata)
        print(f"[+] Combined HTML report: {html_path}")

    return 0


def cmd_dynamic_list_devices(args) -> int:
    """List available devices/emulators."""
    controller = GenymotionController(adb_path=args.adb_path)
    devices = controller.list_devices()

    if not devices:
        print("No devices found. Start Genymotion or connect a device.")
        return 1

    print(f"\nAvailable devices ({len(devices)}):\n")
    print(f"{'Serial':<25} {'Model':<20} {'State':<10} {'Type':<15} {'API':<5}")
    print("-" * 80)
    for d in devices:
        dtype = "Genymotion" if d.is_genymotion else ("Emulator" if d.is_emulator else "Physical")
        api = str(d.api_level) if d.api_level else "?"
        print(f"{d.serial:<25} {d.model:<20} {d.state:<10} {dtype:<15} {api:<5}")

    return 0


def cmd_update(args) -> int:
    """Update threat intelligence feeds by crawling security sources."""
    config = UpdateConfig(
        max_hackerone_reports=args.max_reports,
        max_blog_articles_per_source=args.max_articles,
        enable_hackerone=not args.no_hackerone,
        enable_blogs=not args.no_blogs,
    )

    updater = ThreatIntelUpdater(config)

    if args.stats:
        stats = updater.get_stats()
        print("\nThreat Intelligence Status")
        print("=" * 40)
        print(f"Last update: {stats['last_update'] or 'Never'}")
        print(f"Total updates: {stats['update_count']}")
        print(f"Patterns pending review: {stats['pending_patterns']}")
        return 0

    result = updater.update(force=args.force)

    if result.errors:
        print(f"\n[!] Errors encountered: {len(result.errors)}")
        for error in result.errors:
            print(f"    - {error}")

    return 0 if result.success else 1


def cmd_visualize(args) -> int:
    """Visualize application structure and functionality."""
    apk_path = os.path.abspath(args.apk)
    if not os.path.exists(apk_path):
        print(f"APK not found: {apk_path}", file=sys.stderr)
        return 2

    jadx_path = _find_jadx(args.jadx_path)
    if not jadx_path:
        print("jadx not found. Install jadx-cli or pass --jadx-path.", file=sys.stderr)
        return 2

    out_dir = os.path.abspath(args.out)
    _ensure_dir(out_dir)

    decompiled_dir = os.path.join(out_dir, "decompiled")
    _ensure_dir(decompiled_dir)

    # Decompile if needed
    manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        print("[+] Decompiling APK with jadx...")
        _decompile(apk_path, decompiled_dir, jadx_path)

    if not os.path.exists(manifest_path):
        print("[!] Decompilation failed - manifest not found", file=sys.stderr)
        return 1

    # Analyze application structure
    print("[+] Analyzing application structure...")
    analyzer = AppStructureAnalyzer(decompiled_dir)
    structure = analyzer.analyze()

    print(f"[+] Found {len(structure.classes)} classes")
    print(f"[+] Found {len(structure.components)} components")
    print(f"[+] Found {len(structure.entry_points)} entry points")

    # Configure visualization
    viz_config = VisualizationConfig(
        include_component_graph=not args.no_components,
        include_call_graph=not args.no_calls,
        include_data_flow=not args.no_dataflow,
        include_class_hierarchy=not args.no_hierarchy,
        include_entry_points=True,
        include_statistics=True,
    )

    # Render visualization
    print("[+] Generating visualization...")
    renderer = VisualizationRenderer(structure, viz_config)

    html_path = os.path.join(out_dir, "visualization.html")
    renderer.render_html(html_path)

    print(f"[+] Visualization saved: {html_path}")

    # Print summary
    print("\n" + "=" * 50)
    print("APPLICATION STRUCTURE SUMMARY")
    print("=" * 50)
    print(f"Package: {structure.package_name}")
    print(f"Classes: {len(structure.classes)}")
    print(f"  - Activities: {sum(1 for c in structure.classes.values() if c.is_activity)}")
    print(f"  - Services: {sum(1 for c in structure.classes.values() if c.is_service)}")
    print(f"  - Receivers: {sum(1 for c in structure.classes.values() if c.is_receiver)}")
    print(f"  - Providers: {sum(1 for c in structure.classes.values() if c.is_provider)}")
    print(f"  - Fragments: {sum(1 for c in structure.classes.values() if c.is_fragment)}")
    print(f"Components (manifest): {len(structure.components)}")
    print(f"  - Exported: {sum(1 for c in structure.components.values() if c.exported)}")
    print(f"Entry Points: {len(structure.entry_points)}")
    print(f"Permissions: {len(structure.permissions)}")
    print(f"Data Flows: {len(structure.data_flows)}")

    # List entry points
    if structure.entry_points:
        print("\nEntry Points:")
        for entry in structure.entry_points[:10]:
            print(f"  - {entry}")
        if len(structure.entry_points) > 10:
            print(f"  ... and {len(structure.entry_points) - 10} more")

    # Cleanup if requested
    if not args.keep_decompiled:
        import shutil
        shutil.rmtree(decompiled_dir, ignore_errors=True)
        print("\n[+] Cleaned decompiled output")

    return 0


def main() -> int:
    """Main CLI entry point."""
    # Check for --no-color flag
    if '--no-color' in sys.argv:
        Colors.disable()
        sys.argv.remove('--no-color')

    # If no arguments, run interactive mode
    if len(sys.argv) == 1:
        return interactive_mode()

    # Check for explicit interactive flag
    if len(sys.argv) == 2 and sys.argv[1] in ('-i', '--interactive'):
        return interactive_mode()

    parser = argparse.ArgumentParser(
        description="APK Security Analyzer - Vulnerability Scanner with Dynamic Patterns",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode (recommended for first-time users):
    apk-analyzer                          # Launch interactive wizard
    apk-analyzer --interactive            # Same as above

  Scan an APK (auto-updates threat intel):
    apk-analyzer scan app.apk --out report
    apk-analyzer scan app.apk --no-update      # Skip update
    apk-analyzer scan app.apk --force-update   # Force fresh update

  Visualize application structure:
    apk-analyzer visualize app.apk             # Generate visualization
    apk-analyzer visualize app.apk --out viz   # Custom output dir

  Update threat intelligence:
    apk-analyzer update                        # Update if needed
    apk-analyzer update --force                # Force update
    apk-analyzer update --stats                # Show update status

  List patterns:
    apk-analyzer patterns list

  Dynamic analysis:
    apk-analyzer dynamic --list-devices
    apk-analyzer dynamic app.apk --out dynamic_report
    apk-analyzer dynamic app.apk --device emulator-5554 --timeout 600

  Crawl HackerOne:
    apk-analyzer crawl hackerone --max 50 --extract

  Review extracted patterns:
    apk-analyzer crawl review --list
    apk-analyzer crawl review --approve h1-123-webview
        """
    )

    # Add interactive flag
    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Launch interactive wizard')

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan APK for vulnerabilities")
    scan_parser.add_argument("apk", help="Path to APK file")
    scan_parser.add_argument("--out", default="report", help="Output directory")
    scan_parser.add_argument("--jadx-path", default=None, help="Path to jadx")
    scan_parser.add_argument("--adb-path", default="adb", help="Path to adb")
    scan_parser.add_argument("--patterns-dir", help="Custom patterns directory")
    scan_parser.add_argument("--keep-decompiled", action="store_true", help="Keep decompiled output")
    scan_parser.add_argument("--no-update", action="store_true", help="Skip threat intel update")
    scan_parser.add_argument("--force-update", action="store_true", help="Force threat intel update even if recent")
    scan_parser.add_argument("--quiet-update", action="store_true", help="Suppress threat intel update output")
    scan_parser.set_defaults(func=cmd_scan)

    # Patterns commands
    patterns_parser = subparsers.add_parser("patterns", help="Pattern management")
    patterns_sub = patterns_parser.add_subparsers(dest="patterns_cmd")

    list_parser = patterns_sub.add_parser("list", help="List patterns")
    list_parser.add_argument("--format", choices=["table", "json"], default="table")
    list_parser.add_argument("--all", action="store_true", help="Include disabled patterns")
    list_parser.set_defaults(func=cmd_patterns_list)

    show_parser = patterns_sub.add_parser("show", help="Show pattern details")
    show_parser.add_argument("pattern_id", help="Pattern ID")
    show_parser.set_defaults(func=cmd_patterns_show)

    validate_parser = patterns_sub.add_parser("validate", help="Validate patterns")
    validate_parser.set_defaults(func=cmd_patterns_validate)

    stats_parser = patterns_sub.add_parser("stats", help="Show pattern statistics")
    stats_parser.set_defaults(func=cmd_patterns_stats)

    # Crawl commands
    crawl_parser = subparsers.add_parser("crawl", help="Crawl security sources")
    crawl_sub = crawl_parser.add_subparsers(dest="crawl_cmd")

    h1_parser = crawl_sub.add_parser("hackerone", help="Crawl HackerOne")
    h1_parser.add_argument("--since", help="Fetch reports since date (YYYY-MM-DD)")
    h1_parser.add_argument("--max", type=int, default=50, help="Max reports")
    h1_parser.add_argument("--min-severity", default="low", choices=["none", "low", "medium", "high", "critical"])
    h1_parser.add_argument("--extract", action="store_true", help="Extract patterns")
    h1_parser.set_defaults(func=cmd_crawl_hackerone)

    blog_parser = crawl_sub.add_parser("blogs", help="Crawl security blogs")
    blog_parser.add_argument("--sources", nargs="+", help="Specific sources")
    blog_parser.add_argument("--max", type=int, default=20, help="Max articles per source")
    blog_parser.add_argument("--extract", action="store_true", help="Extract patterns")
    blog_parser.set_defaults(func=cmd_crawl_blogs)

    review_parser = crawl_sub.add_parser("review", help="Review extracted patterns")
    review_parser.add_argument("--list", action="store_true", help="List pending")
    review_parser.add_argument("--approve", nargs="+", help="Approve pattern IDs")
    review_parser.add_argument("--reject", nargs="+", help="Reject pattern IDs")
    review_parser.set_defaults(func=cmd_crawl_review)

    # Dynamic analysis command
    dynamic_parser = subparsers.add_parser("dynamic", help="Dynamic analysis with Genymotion/emulator")
    dynamic_parser.add_argument("apk", nargs="?", help="Path to APK file")
    dynamic_parser.add_argument("--out", default="dynamic_report", help="Output directory")
    dynamic_parser.add_argument("--device", help="Device serial (auto-selects if not specified)")
    dynamic_parser.add_argument("--adb-path", default="adb", help="Path to adb")
    dynamic_parser.add_argument("--jadx-path", default=None, help="Path to jadx")
    dynamic_parser.add_argument("--package", help="Package name (auto-detected from APK)")
    dynamic_parser.add_argument("--skip-static", action="store_true", help="Skip static analysis")
    dynamic_parser.add_argument("--timeout", type=int, default=300, help="Test timeout in seconds")
    dynamic_parser.add_argument("--list-devices", action="store_true", help="List available devices")
    dynamic_parser.set_defaults(func=cmd_dynamic)

    # Update command
    update_parser = subparsers.add_parser("update", help="Update threat intelligence feeds")
    update_parser.add_argument("--force", action="store_true", help="Force update even if recently updated")
    update_parser.add_argument("--stats", action="store_true", help="Show update statistics")
    update_parser.add_argument("--max-reports", type=int, default=30, help="Max HackerOne reports to fetch")
    update_parser.add_argument("--max-articles", type=int, default=10, help="Max blog articles per source")
    update_parser.add_argument("--no-hackerone", action="store_true", help="Skip HackerOne feed")
    update_parser.add_argument("--no-blogs", action="store_true", help="Skip security blog feeds")
    update_parser.set_defaults(func=cmd_update)

    # Visualize command
    viz_parser = subparsers.add_parser("visualize", help="Visualize application structure")
    viz_parser.add_argument("apk", help="Path to APK file")
    viz_parser.add_argument("--out", default="visualization", help="Output directory")
    viz_parser.add_argument("--jadx-path", default=None, help="Path to jadx")
    viz_parser.add_argument("--keep-decompiled", action="store_true", help="Keep decompiled output")
    viz_parser.add_argument("--no-components", action="store_true", help="Skip component graph")
    viz_parser.add_argument("--no-calls", action="store_true", help="Skip call graph")
    viz_parser.add_argument("--no-dataflow", action="store_true", help="Skip data flow graph")
    viz_parser.add_argument("--no-hierarchy", action="store_true", help="Skip class hierarchy")
    viz_parser.set_defaults(func=cmd_visualize)

    args = parser.parse_args()

    # Handle interactive flag
    if hasattr(args, 'interactive') and args.interactive:
        return interactive_mode()

    # Handle legacy usage (no subcommand, just APK path)
    if args.command is None:
        if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
            # Legacy mode: treat first arg as APK path
            args.apk = sys.argv[1]
            args.out = "report"
            args.jadx_path = None
            args.adb_path = "adb"
            args.patterns_dir = None
            args.keep_decompiled = False
            args.no_update = False
            args.force_update = False
            args.quiet_update = False
            return cmd_scan(args)
        parser.print_help()
        return 1

    if hasattr(args, 'func'):
        return args.func(args)

    # Handle subcommand without action
    if args.command == "patterns" and not args.patterns_cmd:
        patterns_parser.print_help()
        return 1
    if args.command == "crawl" and not args.crawl_cmd:
        crawl_parser.print_help()
        return 1
    if args.command == "dynamic" and not args.apk and not args.list_devices:
        dynamic_parser.print_help()
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
