"""Cross-platform framework payloads (React Native, Flutter, Xamarin, Unity).

jadx only decompiles the Java/Kotlin layer. For hybrid apps the interesting code lives in
a JS bundle, a Dart AOT snapshot or managed assemblies, so the Java scan sees almost
nothing. This module detects those frameworks and runs the secrets scanner over the
payloads (extracting printable strings from binaries) so hardcoded keys are not missed.
"""
from __future__ import annotations

import os
import re
from typing import Dict, List

from ..utils import Evidence, Finding
from .secrets import scan_text

_MAX_PAYLOAD = 40_000_000      # bytes read per file
_MIN_STR = 8
_STR_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STR)
_HERMES_MAGIC = bytes.fromhex("c61fbc03c103191f")

_FRAMEWORKS = {
    "react-native": ("index.android.bundle", "libreactnativejni.so", "libhermes.so"),
    "flutter": ("libflutter.so", "libapp.so", "flutter_assets"),
    "xamarin": ("libmonodroid.so", "Xamarin.Android.Support", "assemblies"),
    "unity": ("libunity.so", "global-metadata.dat"),
}


def _walk(roots: List[str]):
    for root in roots:
        if not os.path.isdir(root):
            continue
        for base, dirs, files in os.walk(root):
            for d in dirs:
                yield os.path.join(base, d), d
            for n in files:
                yield os.path.join(base, n), n


def detect(decompiled_dir: str) -> Dict[str, List[str]]:
    roots = [os.path.join(decompiled_dir, "resources"), decompiled_dir]
    seen_roots = set()
    found: Dict[str, List[str]] = {}
    for root in roots:
        real = os.path.realpath(root)
        if real in seen_roots:
            continue
        seen_roots.add(real)
        for path, name in _walk([root]):
            for fw, markers in _FRAMEWORKS.items():
                if name in markers and path not in found.get(fw, []):
                    found.setdefault(fw, []).append(path)
    return found


def _read_strings(path: str) -> str:
    with open(path, "rb") as fh:
        data = fh.read(_MAX_PAYLOAD)
    return "\n".join(m.group(0).decode("ascii", "ignore") for m in _STR_RE.finditer(data))


def _rechunk(text: str) -> str:
    """Minified JS is one giant line; break it so per-line rules stay fast and snippets readable."""
    return re.sub(r"([;,{}])", r"\1\n", text) if "\n" not in text[:5000] else text


def _payload_text(fw: str, path: str) -> str:
    name = os.path.basename(path)
    if fw == "react-native" and name.endswith(".bundle"):
        with open(path, "rb") as fh:
            head = fh.read(8)
        if head == _HERMES_MAGIC:
            return _read_strings(path)             # compiled Hermes bytecode: strings only
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return _rechunk(fh.read(_MAX_PAYLOAD))
    if name in ("libapp.so", "global-metadata.dat") or (fw == "xamarin" and name.endswith(".dll")):
        return _read_strings(path)
    return ""


def scan_hybrid(decompiled_dir: str) -> List[Finding]:
    findings: List[Finding] = []
    frameworks = detect(decompiled_dir)
    for fw, paths in sorted(frameworks.items()):
        findings.append(Finding(
            fid=f"hybrid-framework-{fw}",
            title=f"Cross-platform framework detected: {fw}",
            severity="Info",
            description=("The app ships a {0} payload. Java/Kotlin analysis covers only the native shell; "
                         "business logic, API endpoints and keys usually live in the framework payload "
                         "({1}). Hardcoded secrets in those payloads were scanned separately.").format(
                             fw, ", ".join(sorted({os.path.basename(p) for p in paths})[:5])),
            attack_path="", adb_commands=[], evidence=None,
            references=["https://mas.owasp.org/MASTG/"],
            extra={"category": "Platform Security", "framework": fw}))
        for p in paths:
            if not os.path.isfile(p):
                continue
            try:
                text = _payload_text(fw, p)
            except OSError:
                continue
            if not text:
                continue
            for f in scan_text(p, text):
                f.extra["framework"] = fw
                f.description += f" (found in the {fw} payload {os.path.basename(p)})"
                findings.append(f)
    return findings
