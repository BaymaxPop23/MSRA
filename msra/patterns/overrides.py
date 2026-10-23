"""Analyst rule overrides (data/custom/overrides.json) applied during scans.

The Intelligence Hub writes {"disabled": [...], "enabled": [...]}. Until now only
the Hub's own listing read that file, so toggling a rule off (or creating a custom
rule) never affected a scan. Every scanner now filters through this module.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _data_dir(data_dir: Optional[Path] = None) -> Path:
    if data_dir:
        return Path(data_dir)
    from .manager import get_default_data_dir
    return get_default_data_dir()


def overrides_path(data_dir: Optional[Path] = None) -> Path:
    env = os.environ.get("MSRA_OVERRIDES_FILE")
    return Path(env) if env else _data_dir(data_dir) / "custom" / "overrides.json"


def load_overrides(data_dir: Optional[Path] = None) -> Dict[str, List[str]]:
    try:
        raw = json.loads(overrides_path(data_dir).read_text())
    except (OSError, ValueError):
        return {"disabled": [], "enabled": []}
    if not isinstance(raw, dict):
        return {"disabled": [], "enabled": []}
    return {"disabled": [x for x in raw.get("disabled", []) if isinstance(x, str)],
            "enabled": [x for x in raw.get("enabled", []) if isinstance(x, str)]}


def is_enabled(pattern_id: str, default: bool, overrides: Dict[str, List[str]]) -> bool:
    if pattern_id in overrides["disabled"]:
        return False
    if pattern_id in overrides["enabled"]:
        return True
    return default


def filter_enabled(patterns: Iterable[Dict[str, Any]],
                   data_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Keep patterns that are enabled after applying analyst overrides."""
    ov = load_overrides(data_dir)
    return [p for p in patterns if is_enabled(p.get("id", ""), p.get("enabled", True), ov)]
