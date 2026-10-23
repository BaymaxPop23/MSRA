"""Learn from analyst triage: which rules are noisy, which hold up.

Every time an analyst marks a finding False Positive / Confirmed / Fixed the
decision is stored per finding. Aggregated per *rule*, that history lets MSRA
(a) flag chronically noisy rules in the Intelligence Hub, (b) show a rule's
track record next to each finding, and (c) hand the AI verifier real feedback
as context - so the tool measurably gets less noisy the more it is used.
"""
from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional

FP_STATUSES = {"False Positive"}
TP_STATUSES = {"Confirmed", "Fixed", "In Progress", "Accepted Risk"}   # real issue, whatever the decision


def rule_key(fid: Optional[str], title: Optional[str] = None) -> str:
    """Stable per-rule key from a finding's fid (components/paths stripped)."""
    if fid:
        base = str(fid).split(":", 1)[0]
        if base.startswith("manifest-exported-"):
            return "-".join(base.split("-")[:3])          # manifest-exported-activity
        if base.startswith("TAINT_"):
            return "_".join(base.split("_")[:2])          # TAINT_SQL
        return base
    return (title or "unknown").strip()


def rule_feedback(triage_rows: Iterable[dict],
                  load_findings: Callable[[str], Optional[dict]]) -> Dict[str, dict]:
    """{rule_key: {rule, title, fp, tp, total, fp_rate}} from analyst decisions."""
    cache: Dict[str, Dict[int, dict]] = {}
    stats: Dict[str, dict] = {}

    def findings_of(scan_id: str) -> Dict[int, dict]:
        if scan_id not in cache:
            data = None
            try:
                data = load_findings(scan_id)
            except Exception:
                data = None
            by_id: Dict[int, dict] = {}
            for idx, f in enumerate((data or {}).get("findings", []), start=1):
                by_id[int(f.get("id") or idx)] = f
            cache[scan_id] = by_id
        return cache[scan_id]

    for row in triage_rows:
        status = row.get("status")
        if status in FP_STATUSES:
            kind = "fp"
        elif status in TP_STATUSES:
            kind = "tp"
        else:
            continue
        f = findings_of(row["scan_id"]).get(int(row["finding_id"]))
        if not f:
            continue
        key = rule_key(f.get("fid"), f.get("title"))
        s = stats.setdefault(key, {"rule": key, "title": f.get("title", key),
                                   "fp": 0, "tp": 0, "total": 0, "fp_rate": 0.0})
        s[kind] += 1
        s["total"] += 1
    for s in stats.values():
        s["fp_rate"] = round(s["fp"] / s["total"], 3) if s["total"] else 0.0
    return stats


def noisy_rules(stats: Dict[str, dict], min_decisions: int = 5, min_fp_rate: float = 0.7) -> List[dict]:
    """Rules analysts keep rejecting - candidates to tune or disable."""
    out = [s for s in stats.values()
           if s["total"] >= min_decisions and s["fp_rate"] >= min_fp_rate]
    return sorted(out, key=lambda s: (-s["fp_rate"], -s["total"]))


def feedback_sentence(stats: Dict[str, dict], key: str, min_decisions: int = 3) -> str:
    """One line of analyst history for the AI verifier ('' when not enough data)."""
    s = stats.get(key)
    if not s or s["total"] < min_decisions:
        return ""
    return (f"Analyst history for this rule: {s['fp']} of {s['total']} reviewed findings "
            f"were marked false positive ({int(s['fp_rate'] * 100)}%).")
