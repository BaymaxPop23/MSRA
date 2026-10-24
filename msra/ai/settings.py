"""Persistent AI settings (model per feature, triage, budget) and usage ledger.

Secrets never live here: provider URL/tokens come from the environment only
(ANTHROPIC_API_KEY, or MSRA_LLM_BASE_URL + MSRA_LLM_TOKEN for a gateway). This
file only stores *choices*, so it is safe to show in the UI and back up.
"""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .models import valid_model_id

# feature -> (label, default model alias)
FEATURES: Dict[str, Dict[str, str]] = {
    "triage":          {"label": "Finding triage (verifier votes)", "default": "sonnet"},
    "research":        {"label": "Researcher (deep investigation)", "default": "sonnet"},
    "dynamic_verdict": {"label": "Dynamic scan verdicts",           "default": "sonnet"},
    "poc":             {"label": "PoC generation",                  "default": "sonnet"},
    "rule_extraction": {"label": "Intel rule extraction",           "default": "sonnet"},
    "quick":           {"label": "Quick checks / connection test",  "default": "haiku"},
}

DEFAULTS: Dict[str, Any] = {
    "models": {k: v["default"] for k, v in FEATURES.items()},
    "triage": {"votes": 2, "min_severity": "Medium", "max_findings": 25},
    "research": {"max_steps": 6, "max_usd": 0.5},
    "budget": {"usd_cap": None},
    "pricing": {},
}
SEVERITIES = ("Info", "Low", "Medium", "High", "Critical")

_lock = threading.RLock()


def config_path() -> Path:
    env = os.environ.get("MSRA_AI_CONFIG")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "data" / "custom" / "ai_config.json"


def _merge(base: dict, over: dict) -> dict:
    out = json.loads(json.dumps(base))
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


def load() -> Dict[str, Any]:
    p = config_path()
    stored: dict = {}
    if p.exists():
        try:
            stored = json.loads(p.read_text())
        except (OSError, ValueError):
            stored = {}
    cfg = _merge(DEFAULTS, stored if isinstance(stored, dict) else {})
    # Operator env overrides apply only where the user has not chosen a model.
    legacy = os.environ.get("MSRA_CLAUDE_MODEL")
    fast = os.environ.get("MSRA_CLAUDE_FAST_MODEL")
    chosen = (stored.get("models") or {}) if isinstance(stored, dict) else {}
    for feat in FEATURES:
        if feat not in chosen:
            if feat == "quick" and fast:
                cfg["models"][feat] = fast
            elif feat != "quick" and legacy:
                cfg["models"][feat] = legacy
    return cfg


def validate(update: dict) -> Dict[str, Any]:
    """Validate a partial settings update; returns a cleaned dict or raises ValueError."""
    if not isinstance(update, dict):
        raise ValueError("settings must be an object")
    clean: Dict[str, Any] = {}
    if "models" in update:
        models = update["models"]
        if not isinstance(models, dict):
            raise ValueError("models must be an object")
        clean["models"] = {}
        for feat, model in models.items():
            if feat not in FEATURES:
                raise ValueError(f"unknown feature '{feat}'")
            if not isinstance(model, str) or not valid_model_id(model.strip()):
                raise ValueError(f"invalid model id for '{feat}'")
            clean["models"][feat] = model.strip()
    if "triage" in update:
        t = update["triage"]
        if not isinstance(t, dict):
            raise ValueError("triage must be an object")
        ct: Dict[str, Any] = {}
        if "votes" in t:
            v = int(t["votes"])
            if not 1 <= v <= 5:
                raise ValueError("triage.votes must be 1-5")
            ct["votes"] = v
        if "min_severity" in t:
            if t["min_severity"] not in SEVERITIES:
                raise ValueError(f"triage.min_severity must be one of {SEVERITIES}")
            ct["min_severity"] = t["min_severity"]
        if "max_findings" in t:
            m = int(t["max_findings"])
            if not 1 <= m <= 200:
                raise ValueError("triage.max_findings must be 1-200")
            ct["max_findings"] = m
        clean["triage"] = ct
    if "research" in update:
        r = update["research"]
        if not isinstance(r, dict):
            raise ValueError("research must be an object")
        cr: Dict[str, Any] = {}
        if "max_steps" in r:
            n = int(r["max_steps"])
            if not 2 <= n <= 12:
                raise ValueError("research.max_steps must be 2-12")
            cr["max_steps"] = n
        if "max_usd" in r:
            u = float(r["max_usd"])
            if not 0.05 <= u <= 20:
                raise ValueError("research.max_usd must be between 0.05 and 20")
            cr["max_usd"] = u
        clean["research"] = cr
    if "budget" in update:
        b = update["budget"]
        if not isinstance(b, dict):
            raise ValueError("budget must be an object")
        cap = b.get("usd_cap")
        if cap in (None, ""):
            clean["budget"] = {"usd_cap": None}
        else:
            cap = float(cap)
            if cap < 0 or cap > 100000:
                raise ValueError("budget.usd_cap must be between 0 and 100000")
            clean["budget"] = {"usd_cap": cap}
    return clean


def save(update: dict) -> Dict[str, Any]:
    clean = validate(update)
    with _lock:
        p = config_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            stored = json.loads(p.read_text()) if p.exists() else {}
        except (OSError, ValueError):
            stored = {}
        stored = _merge(stored if isinstance(stored, dict) else {}, clean)
        tmp = p.with_suffix(p.suffix + f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(stored, indent=2))
        os.replace(tmp, p)
    return load()


def model_for(feature: str) -> str:
    return load()["models"].get(feature) or FEATURES[feature]["default"]


# ── Usage ledger ──────────────────────────────────────────────────────────

class BudgetExceeded(RuntimeError):
    pass


class UsageLedger:
    """In-memory (per server process) token and cost accounting."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "_lock", threading.Lock()):
            self.since = time.time()
            self.calls = 0
            self.input_tokens = 0
            self.output_tokens = 0
            self.usd = 0.0
            self.by_feature: Dict[str, Dict[str, float]] = {}
            self.by_model: Dict[str, Dict[str, float]] = {}

    def record(self, feature: str, model: str, usage: dict, usd: float) -> None:
        with self._lock:
            self.calls += 1
            i, o = int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0)
            self.input_tokens += i
            self.output_tokens += o
            self.usd = round(self.usd + usd, 6)
            for bucket, key in ((self.by_feature, feature or "other"), (self.by_model, model)):
                row = bucket.setdefault(key, {"calls": 0, "input_tokens": 0, "output_tokens": 0, "usd": 0.0})
                row["calls"] += 1
                row["input_tokens"] += i
                row["output_tokens"] += o
                row["usd"] = round(row["usd"] + usd, 6)

    def check(self, cap: Optional[float]) -> None:
        if cap is not None and self.usd >= cap:
            raise BudgetExceeded(
                f"AI budget cap reached (${self.usd:.4f} of ${cap:.2f}). "
                "Raise it in AI Settings or reset usage.")

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            return {"since": self.since, "calls": self.calls,
                    "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                    "usd": self.usd, "by_feature": self.by_feature, "by_model": self.by_model}


LEDGER = UsageLedger()
