"""Deterministic vetting of findings before they are surfaced.

Rules fire on patterns; this stage asks, per finding, "does the surrounding code actually
support the claim?" and records the answer. It never deletes anything:

  * a finding that is *disproved* by strong, rule-specific evidence is marked `likely_fp`, its
    confidence is set to low and its severity is capped to Low (the original is kept in
    `extra["vetting"]["original_severity"]`), so it stops crowding out real risks but stays visible
    with the reason;
  * a finding whose claim is *demonstrated* (argument-mapped taint chain) is marked `verified`;
  * everything else is `needs_review` (or `likely` when it is application code with a verified
    local source->sink), with the reasons we could and could not establish.

Every decision carries human-readable reasons (also appended to `false_positive_check`, which the
report already renders). Set MSRA_VETTING=0 to disable. The AI researcher can later promote or
demote a finding on top of this (see msra/ai/research.py).
"""
from __future__ import annotations

import logging
import os
import re
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .code_filter import classify_path

logger = logging.getLogger(__name__)

STATUSES = ("verified", "likely", "needs_review", "likely_fp")
_SEV_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

# categories where the "path" is not source code (manifest, SBOM, secrets in resources...)
_PATHLESS = ("AndroidManifest", "sbom", "SBOM")

_METHOD_RE = re.compile(
    r"^\s*(?:@\w+\s+)*(?:(?:public|protected|private|static|final|synchronized|abstract)\s+)*"
    r"[\w<>\[\],.? ]+?\s+(\w+)\s*\([^;{}]*\)\s*(?:throws\s+[\w., ]+)?\{?\s*$")
_SCHEMA_METHODS = {"onCreate", "onUpgrade", "onDowngrade", "onOpen", "onConfigure"}
_PROVIDER_INPUT = re.compile(
    r"\b(selection|selectionArgs|getLastPathSegment|getPathSegments|getQueryParameter|"
    r"projection|sortOrder|uri\b|Uri\b|contentValues|values)\b")
_DDL = re.compile(r"""execSQL\(\s*["'](?:\s*)(CREATE|DROP|ALTER|PRAGMA|VACUUM|ANALYZE|REINDEX)\b""", re.I)


def enabled() -> bool:
    return os.environ.get("MSRA_VETTING", "1").strip().lower() not in ("0", "false", "no", "off")


def _sev(f) -> str:
    return str(getattr(f.severity, "value", f.severity))


def _evidence(f):
    return getattr(f, "evidence", None)


def matched_line(f) -> str:
    """The snippet line whose number equals the evidence line ('' if unknown)."""
    ev = _evidence(f)
    if not ev or not getattr(ev, "snippet", None):
        return ""
    ln = getattr(ev, "line_number", None)
    for raw in str(ev.snippet).splitlines():
        m = re.match(r"\s*(\d+):\s?(.*)$", raw)
        if m and ln is not None and int(m.group(1)) == int(ln):
            return m.group(2)
    return ""


def _source_lines(path: str, ctx: dict) -> List[str]:
    cache = ctx.setdefault("lines", {})
    if path not in cache:
        try:
            cache[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[path] = []
    return cache[path]


def enclosing_method(path: str, line: int, ctx: dict) -> str:
    lines = _source_lines(path, ctx)
    for i in range(min(line, len(lines)) - 1, max(-1, line - 60), -1):
        m = _METHOD_RE.match(lines[i])
        if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "synchronized", "return", "new"):
            return m.group(1)
    return ""


def _rel(path: str) -> str:
    p = (path or "").replace("\\", "/")
    return p.split("sources/", 1)[1] if "sources/" in p else p


# Each disprover returns a reason string when the finding is DISPROVED, else None.
Disprover = Callable[[object, str, dict], Optional[str]]


def _not_code(f, line: str, cache) -> Optional[str]:
    s = line.strip()
    if not s:
        return None
    if re.match(r"(import|package)\s", s):
        return "the evidence line is an import/package statement, not code that uses the API"
    if s.startswith(("//", "/*", "*")):
        return "the evidence line is a comment"
    return None


def _local_broadcast(f, line: str, cache) -> Optional[str]:
    t = (f.title or "").lower()
    if "implicit intent" not in t:
        return None
    ev = _evidence(f)
    window = line + " " + str(getattr(ev, "snippet", "") or "")
    if "LocalBroadcastManager" in line:
        return "LocalBroadcastManager delivers only inside this app's process; other apps cannot receive it"
    if re.search(r"\.setPackage\(|\.setComponent\(|\.setClass(Name)?\(|new Intent\([^)]*,\s*[\w.]+\.class\)", line):
        return "the intent is made explicit (setPackage/setComponent/class), so it is not implicit"
    if re.search(r"sendBroadcast\([^,()]+,\s*[^)]+\)", line) and "permission" in window.lower():
        return "the broadcast is protected by a receiver permission"
    return None


def _schema_sql(f, line: str, cache) -> Optional[str]:
    t = (f.title or "").lower()
    if "sql injection" not in t:
        return None
    ev = _evidence(f)
    if not ev:
        return None
    stmt = line or ""
    if _PROVIDER_INPUT.search(stmt):
        return None                                           # provider input is in play: keep
    method = enclosing_method(ev.file_path, int(ev.line_number or 0), cache)
    if _DDL.search(stmt):
        return ("schema-setup DDL (" + (stmt.strip()[:50]) + "...) built from internal values, "
                "no ContentProvider input reaches it")
    if method in _SCHEMA_METHODS:
        return f"statement is inside {method}() (database setup) and uses no provider input"
    return None


def _webview_param_evidence(f, line: str, cache) -> Optional[str]:
    t = (f.title or "").lower()
    if "webview url" not in t:
        return None
    s = line.strip()
    ev = _evidence(f)
    window = str(getattr(ev, "snippet", "") or "")
    if re.match(r"(public|final|abstract|class)\b.*\bclass\b", s) and not re.search(
            r"loadUrl|getStringExtra|getData\(|getQueryParameter|Uri\.parse", window):
        return "the evidence is a class declaration; no loadUrl or intent-extra use is shown"
    return None


def _library(f, line: str, cache) -> Optional[str]:
    ev = _evidence(f)
    if not ev or not ev.file_path or any(k in (f.extra or {}).get("category", "") for k in _PATHLESS):
        return None
    path = ev.file_path
    if "sources/" not in path.replace("\\", "/"):
        return None
    kind = classify_path(path, cache.get("package") or None)
    if kind in ("library", "framework"):
        return f"the code is third-party/{kind} code ({_rel(path)[:60]}), owned by its maintainers, not this app"
    return None


_STRING_RE = re.compile(r'<string\s+name="([^"]+)"[^>]*>(.*?)</string>', re.S)
_PLACEHOLDER = re.compile(r"%\d*\$?[sd]|\{[A-Za-z0-9_]+\}")


def _looks_like_ui_text(value: str) -> bool:
    """Human-readable label/sentence rather than a secret: prose, placeholders, or one plain word."""
    v = value.strip()
    if not v:
        return False
    if re.search(r"\s", v) or _PLACEHOLDER.search(v):
        return True
    if any(ord(c) > 127 and c.isalpha() for c in v):
        return True                                   # translated text (accents, CJK, Arabic ...)
    if re.fullmatch(r"[A-Za-z]{2,30}", v) and v[0].isupper():
        return True                                   # "Password", "Gold"
    return bool(re.fullmatch(r"[A-Z][a-z]{1,15}(?:[/\-][A-Za-z][a-z]{1,15}){1,3}", v))   # "Platinum/Gold"


def _ui_string_credential(f, line: str, cache) -> Optional[str]:
    t = (f.title or "").lower()
    fid = (f.fid or "").lower()
    if not ("hardcoded credential" in t or "credential-like" in t or "storage-hardcoded-credentials" in fid
            or "secret-high-entropy" in fid):
        return None
    ev = _evidence(f)
    path = (ev.file_path or "").replace("\\", "/") if ev else ""
    if not re.search(r"/res/values[^/]*/[^/]*\.xml$", path):
        return None
    # prefer the real file (the snippet may carry a masked value); fall back to the snippet line
    src = _source_lines(path, cache)
    text = src[int(ev.line_number) - 1] if src and 0 < int(ev.line_number) <= len(src) else line
    m = _STRING_RE.search(text or "")
    if not m:
        return None
    name, value = m.group(1), m.group(2)
    if _looks_like_ui_text(value):
        return f'the value of string "{name}" is user-facing text (a label/sentence), not a credential'
    return None


def _cookie_claim_without_cookies(f, line: str, cache) -> Optional[str]:
    t, fid = (f.title or "").lower(), (f.fid or "").lower()
    if "exposes session cookies" not in t and "sso-cookie" not in fid:
        return None
    ev = _evidence(f)
    window = str(getattr(ev, "snippet", "") or "")
    if ev and "cookie" not in window.lower():
        return "the claim is about cookie exposure but the evidence contains no cookie handling (matched on a class/name only)"
    return None


_NON_PROVIDER_BASES = re.compile(
    r"\bclass\s+\w+\s+extends\s+(?:\w+\.)*(BroadcastReceiver|Service|IntentService|JobService|"
    r"Activity|AppCompatActivity|FragmentActivity|Fragment|Application)\b")


def _not_a_provider(f, line: str, cache) -> Optional[str]:
    t = (f.title or "").lower()
    if "contentprovider" not in t:
        return None
    ev = _evidence(f)
    if not ev or not ev.file_path:
        return None
    text = "\n".join(_source_lines(ev.file_path, cache))
    m = _NON_PROVIDER_BASES.search(text)
    if m and "ContentProvider" not in text:
        return f"the flagged class extends {m.group(1)}, not ContentProvider, so provider-only attack paths do not apply"
    return None


DISPROVERS: List[Disprover] = [_not_code, _local_broadcast, _schema_sql, _webview_param_evidence,
                               _ui_string_credential, _not_a_provider, _cookie_claim_without_cookies, _library]


def _positive_signals(f) -> Tuple[str, List[str]]:
    """(status hint, reasons) for claims that are demonstrated rather than merely pattern-matched."""
    extra = f.extra or {}
    flow = extra.get("data_flow") or extra.get("flow_type")
    if flow == "call-chain-verified":
        return "verified", ["tainted argument traced through each call to the sink (parameter-mapped)"]
    if flow in ("intra-method", "intra_method"):
        return "likely", ["source and sink are in the same method with data flowing between them"]
    if extra.get("icc_chain"):
        return "likely", ["exported component forwards the extra to an internal component's sink"]
    return "needs_review", []


def vet_finding(f, cache: Optional[dict] = None) -> dict:
    cache = cache if cache is not None else {}
    line = matched_line(f)
    reasons: List[str] = []
    for d in DISPROVERS:
        try:
            why = d(f, line, cache)
        except Exception as exc:                      # a broken heuristic must never break a scan
            logger.debug("disprover %s failed: %s", d.__name__, exc)
            why = None
        if why:
            reasons.append(why)
            break
    if reasons:
        status = "likely_fp"
    else:
        status, reasons = _positive_signals(f)
    return {"status": status, "reasons": reasons}


def vet_findings(findings: list, package: str = "") -> Tuple[list, Dict[str, int]]:
    """Annotate findings in place (never removes). Returns (findings, status counts)."""
    if not enabled():
        return findings, {}
    cache: dict = {"package": package}
    counts: Counter = Counter()
    for f in findings:
        try:
            v = vet_finding(f, cache)
        except Exception as exc:
            logger.debug("vetting failed for %s: %s", getattr(f, "fid", "?"), exc)
            continue
        if f.extra is None:
            f.extra = {}
        extra = f.extra
        info = {"status": v["status"], "reasons": v["reasons"]}
        if v["status"] == "likely_fp":
            sev = _sev(f)
            if _SEV_RANK.get(sev, 0) > _SEV_RANK["Low"]:
                info["original_severity"] = sev
                f.severity = "Low"
            extra["confidence"] = "low"
            fp = list(extra.get("false_positive_check") or [])
            fp.insert(0, "Vetting: likely false positive - " + v["reasons"][0])
            extra["false_positive_check"] = fp
        elif v["status"] == "verified":
            extra["confidence"] = "high"
        elif v["status"] == "likely":
            extra["confidence"] = extra.get("confidence") if extra.get("confidence") == "high" else "medium"
        extra["vetting"] = info
        counts[v["status"]] += 1
    return findings, dict(counts)
