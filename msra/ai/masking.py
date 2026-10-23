"""Redact credentials/PII from text before it is sent to a model or logged."""
from __future__ import annotations

import re

_HEADER_RE = re.compile(r"(?im)^(Authorization|Cookie|Set-Cookie|Proxy-Authorization):[ \t]*(\S.*)$")
_PARAM_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"session[_-]?id|jwt|bearer|csrf|xsrf|client[_-]?secret|private[_-]?key)\b"
    r"([\"']?[ \t]{0,4}[=:][ \t]{0,4})"
    r"(?:\"((?:\\.|[^\"\n]){0,500})\"|'((?:\\.|[^'\n]){0,500})'|([^&\s\"'<>,}]{1,500}))")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_BEARER_RE = re.compile(r"(?i)\bBearer[ \t]+[A-Za-z0-9\-_.+/=]{8,}")
_PEM_RE = re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----[\s\S]{0,8000}?(?:-----END [A-Z ]{0,30}PRIVATE KEY-----|$)")
_KNOWN_KEY_RE = re.compile(
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bAIza[0-9A-Za-z_\-]{35}\b|\bsk-ant-[A-Za-z0-9_\-]{20,}|"
    r"\bsk-[A-Za-z0-9_\-]{32,}|\bgh[pousr]_[A-Za-z0-9]{36,}|\bxox[abprs]-[A-Za-z0-9\-]{10,}|"
    r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}")
_HIGH_ENTROPY_RE = re.compile(
    r"\b(?=[A-Za-z0-9+/_=-]{32,128}\b)(?=[A-Za-z0-9+/_=-]*[0-9])(?=[A-Za-z0-9+/_=-]*[a-z])"
    r"(?=[A-Za-z0-9+/_=-]*[A-Z])[A-Za-z0-9+/_=-]{32,128}\b")

MASK = "***MASKED***"


def mask(text: str) -> str:
    """Return a redacted copy of *text* (idempotent, side-effect free)."""
    if not text:
        return text
    out = _PEM_RE.sub(MASK, text)
    out = _HEADER_RE.sub(lambda m: f"{m.group(1)}: {MASK}", out)

    def _param(m: "re.Match") -> str:
        q = '"' if m.group(3) is not None else ("'" if m.group(4) is not None else "")
        return f"{m.group(1)}{m.group(2)}{q}{MASK}{q}"

    out = _PARAM_RE.sub(_param, out)
    out = _JWT_RE.sub(MASK, out)
    out = _BEARER_RE.sub(f"Bearer {MASK}", out)
    out = _KNOWN_KEY_RE.sub(MASK, out)
    out = _HIGH_ENTROPY_RE.sub(MASK, out)
    return out
