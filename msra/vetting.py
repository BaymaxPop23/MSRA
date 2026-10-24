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


def cap_severity() -> bool:
    """Demoted findings are capped to Low unless MSRA_VETTING_CAP=0 (then only labelled)."""
    return os.environ.get("MSRA_VETTING_CAP", "1").strip().lower() not in ("0", "false", "no", "off")


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



_CLASS_DECL = re.compile(
    r"\b(?:class|interface|enum)\s+(\w+)(?:\s*<[^>{]*>)?(?:\s+extends\s+([\w.$<>, ]+?))?"
    r"(?:\s+implements\s+[\w.$<>, ]+)?\s*\{")


def _strip_noise(raw: str, in_block: bool) -> Tuple[str, bool]:
    """Remove string/char literals and comments so braces and keywords inside them are ignored."""
    out, i, n = [], 0, len(raw)
    while i < n:
        c = raw[i]
        if in_block:
            j = raw.find("*/", i)
            if j == -1:
                return "".join(out), True
            i, in_block = j + 2, False
        elif raw.startswith("/*", i):
            in_block = True
            i += 2
        elif raw.startswith("//", i):
            break
        elif c in "\"'":
            q, i = c, i + 1
            while i < n and raw[i] != q:
                i += 2 if raw[i] == "\\" else 1
            i += 1
            out.append(" ")
        else:
            out.append(c)
            i += 1
    return "".join(out), in_block


def enclosing_class(lines: List[str], line_no: int) -> Optional[Tuple[str, str]]:
    """(name, base class) of the innermost class still OPEN at line_no, tracked by brace depth.
    Returns None when it cannot be established (fail closed)."""
    depth, in_block = 0, False
    stack: List[Tuple[str, str, int]] = []
    for raw in lines[:max(0, line_no)]:
        code, in_block = _strip_noise(raw, in_block)
        opens = {m.end() - 1: (m.group(1), (m.group(2) or "").split("<")[0].strip().split(".")[-1])
                 for m in _CLASS_DECL.finditer(code)}
        for idx, ch in enumerate(code):
            if ch == "{":
                depth += 1
                if idx in opens:
                    stack.append((opens[idx][0], opens[idx][1], depth))
            elif ch == "}":
                if stack and stack[-1][2] == depth:
                    stack.pop()
                depth -= 1
                if depth < 0:
                    return None
    return (stack[-1][0], stack[-1][1]) if stack else None


def split_statements(line: str) -> List[str]:
    """Split on ';' that are outside string/char literals."""
    out, cur, q, i = [], [], "", 0
    while i < len(line):
        c = line[i]
        if q:
            cur.append(c)
            if c == "\\" and i + 1 < len(line):
                cur.append(line[i + 1])
                i += 1
            elif c == q:
                q = ""
        elif c in "\"'":
            q = c
            cur.append(c)
        elif c == ";":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        out.append("".join(cur))
    return [x for x in out if x.strip()]


def method_span_text(path: str, line: int, ctx: dict) -> str:
    """Source from the enclosing method's signature down to the flagged line."""
    lines = _source_lines(path, ctx)
    start = max(0, line - 1)
    for i in range(min(line, len(lines)) - 1, max(-1, line - 60), -1):
        m = _METHOD_RE.match(lines[i])
        if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "synchronized", "return", "new"):
            start = i
            break
    return "\n".join(lines[start:line])


# Each disprover returns a reason string when the finding is DISPROVED, else None.
Disprover = Callable[[object, str, dict], Optional[str]]


def _not_code(f, line: str, cache) -> Optional[str]:
    s = line.strip()
    if not s:
        return None
    if re.match(r"(import|package)\s", s):
        return "the evidence line is an import/package statement, not code that uses the API"
    if s.startswith(("//", "/*")):
        return "the evidence line is a comment"
    return None


_LOCAL_SEND = re.compile(r"LocalBroadcastManager\s*\.\s*getInstance\([^;]*?\)\s*\.\s*sendBroadcast\(")
_EXPLICIT_INTENT = re.compile(
    r"new\s+Intent\([^;]*?\)\s*\.\s*(?:setPackage|setComponent|setClassName|setClass)\(|"
    r"new\s+Intent\(\s*[\w.()]+\s*,\s*[\w.$]+\.class\s*\)")


_SENDISH = re.compile(r"\b(?:sendBroadcast|sendOrderedBroadcast|sendStickyBroadcast|sendBroadcastAsUser|"
                      r"startActivity|startActivityForResult|startService|startForegroundService)\s*\(")


def _local_broadcast(f, line: str, cache) -> Optional[str]:
    t = (f.title or "").lower()
    if "implicit intent" not in t:
        return None
    # Judge every statement on the line that sends or builds an intent; ONE non-local/non-explicit
    # statement keeps the finding (the flagged call could be any of them).
    relevant = [x for x in split_statements(line) if _SENDISH.search(x) or re.search(r"new\s+Intent\(", x)]
    if not relevant:
        return None
    if all(_LOCAL_SEND.search(x) for x in relevant):
        return "sent through LocalBroadcastManager.getInstance(...).sendBroadcast, which delivers only inside this app's process"
    if all(_EXPLICIT_INTENT.search(x) or _LOCAL_SEND.search(x) for x in relevant):
        return "the intent is constructed explicitly (setPackage/setComponent/class target), so it is not implicit"
    return None


def _schema_sql(f, line: str, cache) -> Optional[str]:
    t = (f.title or "").lower()
    if "sql injection" not in t:
        return None
    ev = _evidence(f)
    if not ev or not ev.file_path:
        return None
    ln = int(ev.line_number or 0)
    if _PROVIDER_INPUT.search(line or ""):
        return None                                           # provider input is in play: keep
    lines = _source_lines(ev.file_path, cache)
    if "ContentProvider" in "\n".join(lines):
        return None
    cls = enclosing_class(lines, ln)                          # the class that really contains the line
    if not cls or cls[1] != "SQLiteOpenHelper":
        return None
    # provider input held in a variable earlier in the method (or its parameters) keeps the finding
    if _PROVIDER_INPUT.search(method_span_text(ev.file_path, ln, cache)):
        return None
    method = enclosing_method(ev.file_path, ln, cache)
    if _DDL.search(line or ""):
        return (f"schema-setup DDL ({(line or '').strip()[:40]}...) in SQLiteOpenHelper {cls[0]}; "
                "no ContentProvider input reaches it")
    if method in _SCHEMA_METHODS:
        return (f"statement is inside {method}() of SQLiteOpenHelper {cls[0]} (database setup) and no "
                "ContentProvider input reaches it")
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


def _library_note(f, cache) -> Optional[str]:
    """Namespace-only signal. Package names are chosen by the app's author, so this never demotes a
    finding by itself (an attacker can call their code com/google/...); it only lowers confidence."""
    ev = _evidence(f)
    if not ev or not ev.file_path or any(k in (f.extra or {}).get("category", "") for k in _PATHLESS):
        return None
    if "sources/" not in ev.file_path.replace("\\", "/"):
        return None
    kind = classify_path(ev.file_path, cache.get("package") or None)
    if kind in ("library", "framework"):
        return (f"the file is under a third-party namespace ({_rel(ev.file_path)[:60]}); likely the library "
                "maintainers' code, but a package name is not proof")
    return None


_STRING_RE = re.compile(r'<string\s+name="([^"]+)"[^>]*>(.*?)</string>', re.S)
_PLACEHOLDER = re.compile(r"%\d*\$?[sd]|\{[A-Za-z0-9_]+\}")


_SECRETISH_NAME = re.compile(r"(?i)pass|pwd|secret|key|token|cred|auth")


def _looks_like_ui_text(value: str, name: str = "") -> bool:
    """Prose or placeholders: never a credential. A single plain word only counts when the string
    name is NOT itself credential-like (a hardcoded 'Administrator' under 'admin_password' is a
    finding, not a label); those cases are handled by _translated_elsewhere instead."""
    v = value.strip()
    if not v:
        return False
    if re.search(r"\s", v) or _PLACEHOLDER.search(v):
        return True
    if any(ord(c) > 127 and c.isalpha() for c in v):
        return True                                   # translated text (accents, CJK, Arabic ...)
    if _SECRETISH_NAME.search(name):
        return False
    if re.fullmatch(r"[A-Za-z]{2,30}", v) and v[0].isupper():
        return True                                   # "Gold"
    return bool(re.fullmatch(r"[A-Z][a-z]{1,15}(?:[/\-][A-Za-z][a-z]{1,15}){1,3}", v))   # "Platinum/Gold"


_LABEL_SHAPE = re.compile(r"[A-Za-z]{2,30}|[A-Z][a-z]{1,15}(?:[/\-][A-Za-z][a-z]{1,15}){1,3}")
_LANG_DIR = re.compile(r"values-[a-z]{2,3}(?:-r[A-Z]{2})?$")


def _translated_elsewhere(path: str, name: str, value: str, cache: dict) -> bool:
    """Same string name defined with a DIFFERENT value in another LANGUAGE folder: a UI label.
    Only consulted for label-shaped values (never for token/key-like strings), and only
    values-xx / values-xx-rYY folders count, because the scanned app controls what its other
    resource folders contain."""
    if not _LABEL_SHAPE.fullmatch(value.strip()):
        return False
    key = ("loc", path, name)
    if key in cache:
        return cache[key]
    found = False
    try:
        res = Path(path).parent.parent
        pat = re.compile(r'<string\s+name="' + re.escape(name) + r'"[^>]*>(.*?)</string>', re.S)
        for sib in res.glob("values-*/strings.xml"):
            if not _LANG_DIR.fullmatch(sib.parent.name) or sib.resolve() == Path(path).resolve():
                continue
            m = pat.search(sib.read_text(encoding="utf-8", errors="replace"))
            if m and m.group(1).strip() != value.strip():
                found = True
                break
    except OSError:
        pass
    cache[key] = found
    return found


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
    if _looks_like_ui_text(value, name) or _translated_elsewhere(path, name, value, cache):
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


_NON_PROVIDER_BASE_NAMES = {"BroadcastReceiver", "Service", "IntentService", "JobService", "Activity",
                            "AppCompatActivity", "FragmentActivity", "Fragment", "Application"}
def _not_a_provider(f, line: str, cache) -> Optional[str]:
    t = (f.title or "").lower()
    if "contentprovider" not in t:
        return None
    ev = _evidence(f)
    if not ev or not ev.file_path:
        return None
    lines = _source_lines(ev.file_path, cache)
    if "ContentProvider" in "\n".join(lines):
        return None
    cls = enclosing_class(lines, int(ev.line_number or 0))
    if cls and cls[1] in _NON_PROVIDER_BASE_NAMES:
        return (f"the class containing the flagged line ({cls[0]}) extends {cls[1]}, not ContentProvider, "
                "so provider-only attack paths do not apply")
    return None


DISPROVERS: List[Disprover] = [_not_code, _local_broadcast, _schema_sql, _webview_param_evidence,
                               _ui_string_credential, _not_a_provider, _cookie_claim_without_cookies]


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
        try:
            note = _library_note(f, cache)
        except Exception:
            note = None
        if note and status != "verified":
            reasons = reasons + [note]
            return {"status": status, "reasons": reasons, "low_confidence": True}
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
        if v.get("low_confidence"):
            extra["confidence"] = "low"
        if v["status"] == "likely_fp":
            sev = _sev(f)
            if _SEV_RANK.get(sev, 0) > _SEV_RANK["Low"]:
                info["original_severity"] = sev
                if cap_severity():
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
