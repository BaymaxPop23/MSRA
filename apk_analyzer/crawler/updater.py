"""Threat Intelligence Updater - Automatic pattern updates from security feeds."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from .hackerone import HackerOneCrawler, HackerOneConfig
from .blogs import BlogCrawler, BLOG_SOURCES
from .extractor import PatternExtractor
from .cache import CrawlerCache

logger = logging.getLogger(__name__)


@dataclass
class UpdateConfig:
    """Configuration for threat intelligence updates."""
    # Update frequency
    min_update_interval: timedelta = field(default_factory=lambda: timedelta(hours=24))

    # Sources to fetch from
    enable_hackerone: bool = True
    enable_blogs: bool = True

    # Fetch limits
    max_hackerone_reports: int = 30
    max_blog_articles_per_source: int = 10

    # HackerOne settings (web crawling)
    hackerone_min_severity: str = "low"

    # Auto-approval
    auto_approve_threshold: float = 0.7  # Confidence threshold for auto-approval
    auto_approve_enabled: bool = False   # Disabled by default for safety

    # Paths
    data_dir: Optional[Path] = None


@dataclass
class UpdateResult:
    """Result of a threat intelligence update."""
    success: bool
    patterns_found: int = 0
    patterns_added: int = 0
    patterns_pending: int = 0
    sources_checked: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    skipped_reason: Optional[str] = None


class ThreatIntelUpdater:
    """
    Coordinates threat intelligence updates from multiple sources.
    Fetches security writeups, extracts patterns, and updates the pattern database.
    """

    def __init__(self, config: Optional[UpdateConfig] = None):
        self.config = config or UpdateConfig()

        # Set up paths
        self.data_dir = self.config.data_dir or Path.home() / ".apkanalyzer"
        self.state_file = self.data_dir / "update_state.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.extractor = PatternExtractor(self.data_dir / "data" / "crawled")

        # Load state
        self._state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """Load update state from disk."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load state: {e}")
        return {"last_update": None, "update_count": 0}

    def _save_state(self) -> None:
        """Save update state to disk."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self._state, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    def should_update(self) -> bool:
        """Check if an update is needed based on last update time."""
        last_update = self._state.get("last_update")
        if not last_update:
            return True

        try:
            last_dt = datetime.fromisoformat(last_update)
            elapsed = datetime.now() - last_dt
            return elapsed >= self.config.min_update_interval
        except Exception:
            return True

    def update(self, force: bool = False, quiet: bool = False) -> UpdateResult:
        """
        Run a threat intelligence update.

        Args:
            force: Force update even if recently updated
            quiet: Suppress output messages

        Returns:
            UpdateResult with details of the update
        """
        start_time = datetime.now()
        result = UpdateResult(success=True)

        # Check if update is needed
        if not force and not self.should_update():
            result.success = True
            result.skipped_reason = "Recently updated"
            if not quiet:
                last = self._state.get("last_update", "never")
                print(f"[*] Threat intel is up to date (last update: {last})")
            return result

        if not quiet:
            print("[*] Updating threat intelligence feeds...")

        # Fetch from HackerOne
        if self.config.enable_hackerone:
            try:
                h1_result = self._fetch_hackerone(quiet)
                result.patterns_found += h1_result["found"]
                result.patterns_added += h1_result["added"]
                result.patterns_pending += h1_result["pending"]
                result.sources_checked.append("HackerOne")
            except Exception as e:
                error_msg = f"HackerOne fetch failed: {e}"
                result.errors.append(error_msg)
                if not quiet:
                    print(f"[!] {error_msg}")

        # Fetch from security blogs
        if self.config.enable_blogs:
            try:
                blog_result = self._fetch_blogs(quiet)
                result.patterns_found += blog_result["found"]
                result.patterns_added += blog_result["added"]
                result.patterns_pending += blog_result["pending"]
                result.sources_checked.extend(blog_result["sources"])
            except Exception as e:
                error_msg = f"Blog fetch failed: {e}"
                result.errors.append(error_msg)
                if not quiet:
                    print(f"[!] {error_msg}")

        # Update state
        self._state["last_update"] = datetime.now().isoformat()
        self._state["update_count"] = self._state.get("update_count", 0) + 1
        self._save_state()

        # Calculate duration
        result.duration_seconds = (datetime.now() - start_time).total_seconds()

        if not quiet:
            print(f"[+] Threat intel update complete:")
            print(f"    Sources checked: {', '.join(result.sources_checked)}")
            print(f"    Patterns found: {result.patterns_found}")
            print(f"    Patterns added: {result.patterns_added}")
            print(f"    Pending review: {result.patterns_pending}")

        return result

    def _fetch_hackerone(self, quiet: bool) -> Dict[str, int]:
        """Fetch patterns from HackerOne by crawling the website."""
        result = {"found": 0, "added": 0, "pending": 0}

        # Configure HackerOne crawler (web crawling, no API needed)
        h1_config = HackerOneConfig(
            min_severity=self.config.hackerone_min_severity,
        )

        crawler = HackerOneCrawler(h1_config)

        # Fetch since last update
        since = None
        if self._state.get("last_update"):
            try:
                since = datetime.fromisoformat(self._state["last_update"])
            except Exception:
                pass

        if not quiet:
            print(f"  [*] Fetching HackerOne reports (max: {self.config.max_hackerone_reports})...")

        reports = list(crawler.fetch_reports(
            since=since,
            max_reports=self.config.max_hackerone_reports,
            use_cache=True
        ))

        if not quiet:
            print(f"  [+] Found {len(reports)} Android-related reports")

        # Extract patterns from reports
        for report in reports:
            extraction = self.extractor.extract_from_hackerone(report)
            if extraction.success:
                result["found"] += len(extraction.patterns)

                for pattern in extraction.patterns:
                    # Check if pattern should be auto-approved
                    if (self.config.auto_approve_enabled and
                        extraction.confidence >= self.config.auto_approve_threshold):
                        self.extractor.save_pattern(pattern, pending_review=False)
                        result["added"] += 1
                    else:
                        self.extractor.save_pattern(pattern, pending_review=True)
                        result["pending"] += 1

        return result

    def _fetch_blogs(self, quiet: bool) -> Dict[str, Any]:
        """Fetch patterns from security blogs."""
        result = {"found": 0, "added": 0, "pending": 0, "sources": []}

        crawler = BlogCrawler()

        if not quiet:
            print(f"  [*] Fetching security blog articles...")

        for source in BLOG_SOURCES:
            try:
                articles = list(crawler.crawl_source(
                    source.name,
                    max_articles=self.config.max_blog_articles_per_source,
                    use_cache=True
                ))

                result["sources"].append(source.name)

                for article in articles:
                    extraction = self.extractor.extract_from_blog(article)
                    if extraction.success:
                        result["found"] += len(extraction.patterns)

                        for pattern in extraction.patterns:
                            if (self.config.auto_approve_enabled and
                                extraction.confidence >= self.config.auto_approve_threshold):
                                self.extractor.save_pattern(pattern, pending_review=False)
                                result["added"] += 1
                            else:
                                self.extractor.save_pattern(pattern, pending_review=True)
                                result["pending"] += 1

            except Exception as e:
                if not quiet:
                    print(f"  [!] Failed to fetch from {source.name}: {e}")

        if not quiet:
            print(f"  [+] Checked {len(result['sources'])} blog sources")

        return result

    def get_pending_count(self) -> int:
        """Get the number of patterns pending review."""
        return len(self.extractor.list_pending())

    def get_last_update(self) -> Optional[str]:
        """Get the timestamp of the last update."""
        return self._state.get("last_update")

    def get_stats(self) -> Dict[str, Any]:
        """Get update statistics."""
        return {
            "last_update": self._state.get("last_update"),
            "update_count": self._state.get("update_count", 0),
            "pending_patterns": self.get_pending_count(),
        }
