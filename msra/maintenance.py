"""Housekeeping that keeps disk use bounded on long-running servers (all opt-in)."""
from __future__ import annotations

import logging
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Callable, Iterable

log = logging.getLogger(__name__)

ACTIVE = ("queued", "decompiling", "scanning", "reporting")


def _env_float(name: str, default: float = 0.0) -> float:
    try:
        return max(0.0, float(os.environ.get(name, default)))
    except ValueError:
        return default


def prune_uploads(upload_dir: Path, ttl_s: float, active_ids: Iterable[str], now: float = None) -> int:
    """Delete leftover upload files (named '<scan_id>_<name>') older than ttl_s.

    Files that belong to a scan that is still active are never touched."""
    if ttl_s <= 0 or not upload_dir.is_dir():
        return 0
    now = now or time.time()
    active = set(active_ids)
    removed = 0
    for p in upload_dir.iterdir():
        try:
            if not p.is_file() or p.is_symlink() or now - p.stat().st_mtime < ttl_s:
                continue
            if p.name.split("_", 1)[0] in active:
                continue
            p.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def prune_decompiled(reports_dir: Path, ttl_s: float, active_ids: Iterable[str], now: float = None) -> int:
    """Remove '<report>/decompiled' trees older than ttl_s. Reports and findings stay;
    only the (large, regenerable) jadx output goes. Scans that are active are skipped."""
    if ttl_s <= 0 or not reports_dir.is_dir():
        return 0
    now = now or time.time()
    active = set(active_ids)
    removed = 0
    for d in reports_dir.iterdir():
        dec = d / "decompiled"
        try:
            if d.is_symlink() or not dec.is_dir() or dec.is_symlink() or d.name in active:
                continue
            if now - dec.stat().st_mtime < ttl_s:
                continue
            shutil.rmtree(dec, ignore_errors=True)
            removed += 1
        except OSError:
            continue
    return removed


def start_janitor(upload_dir: Path, reports_dir: Path, active_ids: Callable[[], Iterable[str]],
                  interval_s: float = 3600) -> bool:
    """Start the background pruner when MSRA_UPLOAD_TTL_HOURS / MSRA_DECOMPILED_TTL_DAYS is set."""
    up = _env_float("MSRA_UPLOAD_TTL_HOURS") * 3600
    dec = _env_float("MSRA_DECOMPILED_TTL_DAYS") * 86400
    if not (up or dec):
        return False

    def loop():
        while True:
            try:
                ids = list(active_ids())
                n1, n2 = prune_uploads(upload_dir, up, ids), prune_decompiled(reports_dir, dec, ids)
                if n1 or n2:
                    log.info("janitor removed %d upload(s), %d decompiled tree(s)", n1, n2)
            except Exception as exc:                       # never die
                log.warning("janitor error: %s", exc)
            time.sleep(interval_s)

    threading.Thread(target=loop, name="janitor", daemon=True).start()
    return True
