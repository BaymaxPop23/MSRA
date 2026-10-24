import os
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional


@dataclass
class Evidence:
    file_path: str
    line_number: int
    snippet: str
    matched_text: str = ""

    # Alias for backwards compatibility
    @property
    def line(self) -> int:
        return self.line_number


@dataclass
class Finding:
    fid: str
    title: str
    severity: str
    description: str
    attack_path: str
    adb_commands: List[str]
    evidence: Optional[Evidence] = None
    references: Optional[List[str]] = None
    extra: Optional[dict] = None


def read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def iter_source_files(root: str) -> Iterable[str]:
    for base, _, files in os.walk(root):
        for name in files:
            if name.endswith((".java", ".kt", ".xml")):
                yield os.path.join(base, name)


class LineIndex:
    """Line offsets for one text, built once. `str.splitlines()` also splits on \f, \v, \x85 and
    \u2028, which shifts every later line number, so lines are split on '\n' only."""

    __slots__ = ("lines", "starts")

    def __init__(self, text: str):
        self.lines = text.split("\n")
        self.starts = []
        pos = 0
        for line in self.lines:
            self.starts.append(pos)
            pos += len(line) + 1

    def line_of(self, pos: int) -> int:
        """0-based line index containing character offset *pos*."""
        import bisect
        return max(0, bisect.bisect_right(self.starts, pos) - 1)


_INDEX_SLOT: list = [None, None]          # [text, LineIndex] - the file currently being scanned


def index_for(text: str) -> LineIndex:
    """Cached LineIndex for the text being scanned (a scan asks about the same file thousands of times)."""
    if _INDEX_SLOT[0] is not text:
        _INDEX_SLOT[0], _INDEX_SLOT[1] = text, LineIndex(text)
    return _INDEX_SLOT[1]


def find_line_snippet(text: str, match_start: int, context: int = 2) -> Evidence:
    ix = index_for(text)
    lines = ix.lines
    if not text:
        return Evidence(file_path="", line_number=1, snippet="")
    idx = ix.line_of(match_start) + 1
    start = max(1, idx - context)
    end = min(len(lines), idx + context)
    snippet = "\n".join(f"{i:04d}: {lines[i-1]}" for i in range(start, end + 1))
    return Evidence(file_path="", line_number=idx, snippet=snippet)


def regex_finditer(pattern: str, text: str, flags: int = 0):
    return re.finditer(pattern, text, flags)
