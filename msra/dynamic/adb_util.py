"""Single ADB subprocess runner plus a per-job deadline.

Replaces the hand-rolled runners that used to live in server.py,
verification/component_prober.py and traffic/mitm_capture.py.

The deadline is thread-local: a dynamic job sets it once, and every
``run_adb`` call made from that thread afterwards raises ``JobDeadline`` once
time is up. ``JobDeadline`` derives from BaseException on purpose so the many
``except Exception: pass`` blocks in probe code cannot swallow it - the job
unwinds to the worker, which reports a timeout.
"""
from __future__ import annotations

import logging
import subprocess
import threading
import time
from contextlib import contextmanager
from typing import Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

_ctx = threading.local()


class JobDeadline(BaseException):
    """Raised when the current dynamic job has exceeded its time budget."""


def set_deadline(seconds: Optional[float]) -> None:
    _ctx.deadline = (time.monotonic() + seconds) if seconds else None


def clear_deadline() -> None:
    _ctx.deadline = None


@contextmanager
def deadline(seconds: Optional[float]):
    set_deadline(seconds)
    try:
        yield
    finally:
        clear_deadline()


def check_deadline() -> None:
    dl = getattr(_ctx, "deadline", None)
    if dl is not None and time.monotonic() > dl:
        raise JobDeadline("dynamic job exceeded its time limit")


def sleep(seconds: float) -> None:
    """time.sleep that never sleeps past the job deadline."""
    check_deadline()
    dl = getattr(_ctx, "deadline", None)
    if dl is not None:
        seconds = max(0.0, min(seconds, dl - time.monotonic()))
    time.sleep(seconds)
    check_deadline()


def run_adb(args: Sequence[str], timeout: float = 15,
            serial: Optional[str] = None) -> Tuple[int, str, str]:
    """Run ``adb [-s serial] <args>``; returns (returncode, stdout, stderr).

    Never raises for adb failures (rc=-1 with a message); raises JobDeadline
    when the calling job is out of time. The per-call timeout is clamped to the
    time left on the deadline.
    """
    check_deadline()
    dl = getattr(_ctx, "deadline", None)
    if dl is not None:
        timeout = max(1.0, min(timeout, dl - time.monotonic()))
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        logger.error("'adb' not found on PATH")
        return -1, "", "adb not found in PATH"
    except subprocess.TimeoutExpired:
        logger.debug("ADB command timed out: %s", cmd)
        return -1, "", "adb command timed out"
    except Exception as exc:  # noqa: BLE001 - report as a failed command
        logger.debug("ADB command failed: %s - %s", cmd, exc)
        return -1, "", str(exc)
