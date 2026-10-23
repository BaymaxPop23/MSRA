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

# --- structural ReDoS analysis -------------------------------------------------
# A text/regex heuristic cannot reliably spot catastrophic backtracking (nested
# groups, overlapping alternations, ...), so analyse the *parsed* pattern instead.
try:                                    # Python 3.11+
    import re._parser as _sre_parse
    import re._constants as _sre_const
except ImportError:                     # Python 3.9 - 3.10
    import sre_parse as _sre_parse      # type: ignore
    import sre_constants as _sre_const  # type: ignore

_MAXREPEAT = _sre_const.MAXREPEAT
_REPEATS = {getattr(_sre_const, n) for n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT")
            if hasattr(_sre_const, n)}
_SUBPATTERN = _sre_const.SUBPATTERN
_BRANCH = _sre_const.BRANCH
_LITERAL = _sre_const.LITERAL
_IN = _sre_const.IN
_MAX_NESTED_OUTER_REPEAT = 3        # (\d+\.){3} is fine; (\w+,){10} is not


def _children(op, av):
    """Yield sub-patterns of a parsed node (None for leaf nodes)."""
    if op in _REPEATS:
        yield av[2]
    elif op == _SUBPATTERN:
        yield av[-1]
    elif op == _BRANCH:
        for alt in av[1]:
            yield alt
    elif op in (_sre_const.ASSERT, _sre_const.ASSERT_NOT):
        yield av[1]
    elif op == getattr(_sre_const, "ATOMIC_GROUP", None):
        yield av
    elif op == _sre_const.GROUPREF_EXISTS:
        yield av[1]
        if av[2] is not None:
            yield av[2]


def _has_repeat(sp) -> bool:
    for op, av in sp:
        if op in _REPEATS and av[1] > 1:
            return True
        if any(_has_repeat(c) for c in _children(op, av)):
            return True
    return False


def _first_chars(sp):
    """Set of code points a sub-pattern can start with, or None if not determinable."""
    for op, av in sp:
        if op == _LITERAL:
            return {av}
        if op == _IN:
            out = set()
            for kind, val in av:
                if kind == _LITERAL:
                    out.add(val)
                elif kind == _sre_const.RANGE:
                    if val[1] - val[0] > 255:
                        return None
                    out.update(range(val[0], val[1] + 1))
                else:
                    return None                      # NEGATE / CATEGORY: broad
            return out
        if op == _SUBPATTERN:
            return _first_chars(av[-1])
        if op in _REPEATS and av[0] >= 1:
            return _first_chars(av[2])
        return None
    return None                                     # empty branch


def _overlapping_alternation(av) -> bool:
    sets = [_first_chars(alt) for alt in av[1]]
    if any(st is None for st in sets):
        return True                                 # cannot prove the branches are disjoint
    seen: set = set()
    for st in sets:
        if seen & st:
            return True
        seen |= st
    return False


def _walk(sp, under_unbounded: bool) -> Optional[str]:
    for op, av in sp:
        if op in _REPEATS:
            lo, hi, body = av
            unbounded = hi == _MAXREPEAT
            if hi > 1 and _has_repeat(body) and (unbounded or hi > _MAX_NESTED_OUTER_REPEAT):
                return "nested quantifier (catastrophic backtracking / ReDoS risk)"
            for c in _children(op, av):
                r = _walk(c, under_unbounded or (hi > 1 and unbounded))
                if r:
                    return r
        elif op == _BRANCH:
            if under_unbounded and _overlapping_alternation(av):
                return "repeated alternation whose branches can overlap (ReDoS risk)"
            for c in _children(op, av):
                r = _walk(c, under_unbounded)
                if r:
                    return r
        else:
            for c in _children(op, av):
                r = _walk(c, under_unbounded)
                if r:
                    return r
    return None


def regex_problem(pattern: str) -> Optional[str]:
    """Return a human-readable problem with *pattern*, or None if it is acceptable."""
    if not isinstance(pattern, str):
        return "pattern must be a string"
    if len(pattern) > MAX_PATTERN_LEN:
        return f"regex too long (max {MAX_PATTERN_LEN} chars)"
    try:
        re.compile(pattern)
        parsed = _sre_parse.parse(pattern)
    except (re.error, RecursionError, OverflowError) as exc:
        return f"invalid regex: {exc}"
    try:
        return _walk(parsed, False)
    except RecursionError:
        return "regex too deeply nested"


def is_unreviewed(tags: Optional[Iterable[str]]) -> bool:
    return bool(set(tags or ()) & UNREVIEWED_TAGS)


def default_enabled(tags: Optional[Iterable[str]], declared: bool = True) -> bool:
    """Rules derived from crawled/AI content default to OFF until reviewed."""
    return False if is_unreviewed(tags) else bool(declared)
