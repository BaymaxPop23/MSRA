"""Every builtin regex must stay near-linear on crafted input (attacker-supplied
APKs/JARs/EXEs are scanned with these)."""
import json
import re
import time
from pathlib import Path

import pytest

DATA = Path(__file__).resolve().parent.parent / "data" / "builtin"
LIMIT_S = 1.5
N = 12000


def _collect(node, out):
    if isinstance(node, dict):
        for k, v in node.items():
            if k in ("pattern", "regex") and isinstance(v, str):
                out.append(v)
            else:
                _collect(v, out)
    elif isinstance(node, list):
        for v in node:
            _collect(v, out)


def _all_patterns():
    pats = []
    for f in sorted(DATA.glob("*.json")):
        found = []
        _collect(json.loads(f.read_text()), found)
        pats += [(f.name, p) for p in found]
    return pats


def _inputs():
    return {
        "call-args": "rawQuery(" + "a + " * 16000,     # ~64k chars: where quadratic cost shows
        "open-paren": "foo(" * (N // 4),
        "generic": "A<" * (N // 2),
        "word-run": "password" * (N // 8),
        "newlines": "x = y;\n" * (N // 7),
        "spaces": "x" + " " * N + "y",
    }


def test_builtin_patterns_exist():
    assert len(_all_patterns()) > 100


def test_no_builtin_pattern_is_superlinear():
    inputs = _inputs()
    slow = []
    for fname, pat in _all_patterns():
        try:
            rx = re.compile(pat, re.I | re.S)
        except re.error:
            continue
        for name, text in inputs.items():
            t0 = time.perf_counter()
            for _ in rx.finditer(text):
                pass
            dt = time.perf_counter() - t0
            if dt > LIMIT_S:
                slow.append((fname, name, round(dt, 2), pat[:80]))
    assert not slow, slow
