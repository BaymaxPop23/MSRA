"""Policy shared by every path that can introduce a rule (Hub, feeds, crawler, loader).

Rules can originate from untrusted web content. Two controls apply everywhere:
  * regex safety - reject over-long patterns and the classic catastrophic-
    backtracking shape (a repeated group containing an unbounded quantifier);
  * review gating - rules tagged as machine/crawler-derived stay disabled until
    an analyst explicitly enables them.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

ALLOWED_CUSTOM_TYPES = ("regex", "regex-multiline", "combined", "manifest")
UNREVIEWED_TAGS = frozenset({"crawled", "ai-extracted", "needs-review"})
MAX_PATTERNS = 50
MAX_PATTERN_LEN = 2000

# A group containing an unbounded quantifier that is itself repeated: (a+)+ , (.*)* , (a+){2,}
_NESTED_QUANT_RE = re.compile(
    r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*]|\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\{\d+,\}")


def regex_problem(pattern: str) -> Optional[str]:
    """Return a human-readable problem with *pattern*, or None if it is acceptable."""
    if not isinstance(pattern, str):
        return "pattern must be a string"
    if len(pattern) > MAX_PATTERN_LEN:
        return f"regex too long (max {MAX_PATTERN_LEN} chars)"
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"invalid regex: {exc}"
    if _NESTED_QUANT_RE.search(pattern):
        return "nested unbounded quantifier (catastrophic backtracking / ReDoS risk)"
    return None


def is_unreviewed(tags: Optional[Iterable[str]]) -> bool:
    return bool(set(tags or ()) & UNREVIEWED_TAGS)


def default_enabled(tags: Optional[Iterable[str]], declared: bool = True) -> bool:
    """Rules derived from crawled/AI content default to OFF until reviewed."""
    return False if is_unreviewed(tags) else bool(declared)
