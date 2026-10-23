"""Model catalog helpers: aliases, routing, context windows and pricing.

Design notes (learned from running a multi-vendor Bedrock-style gateway):
  * Bare tier aliases ("sonnet") are NOT reliably understood by gateways - some
    silently substitute a default model. Always resolve to an exact id first and
    verify the model echoed back in the response.
  * Only Anthropic-family ids speak the Messages API; every other vendor on a
    multi-vendor gateway answers on the OpenAI-style chat-completions endpoint.
  * Unknown models get the smallest common context window and a mid-tier price
    so cost tracking and prompt sizing fail safe, never to zero/unbounded.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

# Direct-to-Anthropic catalog (current model family).
DIRECT_MODELS: List[Dict[str, str]] = [
    {"id": "claude-fable-5-1", "family": "fable", "label": "Claude Fable 5.1 - most capable"},
    {"id": "claude-opus-5-5",  "family": "opus",  "label": "Claude Opus 5.5 - deep reasoning"},
    {"id": "claude-sonnet-5-5", "family": "sonnet", "label": "Claude Sonnet 5.5 - balanced"},
    {"id": "claude-haiku-5-5", "family": "haiku", "label": "Claude Haiku 5.5 - fast and cheap"},
]
FAMILIES = tuple(m["family"] for m in DIRECT_MODELS)
ALIASES: Dict[str, str] = {m["family"]: m["id"] for m in DIRECT_MODELS}

ANTHROPIC_MARKERS = ("anthropic.", "claude", "fable", "opus", "sonnet", "haiku")
NON_CHAT_MARKERS = ("embed", "rerank", "image", "moderation", "whisper", "tts", "speech")

MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-]{0,119}$")


def valid_model_id(model: str) -> bool:
    return bool(model) and bool(MODEL_ID_RE.match(model))


def is_chat_model(model_id: str) -> bool:
    m = (model_id or "").lower()
    return bool(m) and not any(x in m for x in NON_CHAT_MARKERS)


def is_anthropic_family(model: str) -> bool:
    m = (model or "").strip().lower()
    return any(x in m for x in ANTHROPIC_MARKERS)


def uses_chat_completions(model: str) -> bool:
    """True when the model must be called via OpenAI-style /chat/completions.

    Blank/unknown defaults to False so a catalog-listing client built with an
    empty model never mis-routes."""
    m = (model or "").strip().lower()
    return bool(m) and not is_anthropic_family(m)


def family_of(model: str) -> Optional[str]:
    m = (model or "").lower()
    for fam in FAMILIES:
        if fam in m:
            return fam
    return None


def resolve_alias(name: str, catalog_ids: Optional[List[str]] = None) -> str:
    """Resolve a bare tier alias to an exact model id.

    With a live *catalog_ids* list (gateway mode) pick the newest catalog entry
    of that family; otherwise use the direct catalog. Exact ids pass through."""
    if not name:
        return name
    key = name.strip().lower()
    if key not in ALIASES:
        return name.strip()
    if catalog_ids:
        matches = sorted((c for c in catalog_ids if key in c.lower() and is_anthropic_family(c)),
                         key=_version_key, reverse=True)
        if matches:
            return matches[0]
    return ALIASES[key]


def _version_key(model_id: str):
    return [int(n) for n in re.findall(r"\d+", model_id)] or [0]


# Approximate context windows by family substring. Floors, not exact values.
_CONTEXT = {
    "fable": 1_000_000, "opus": 1_000_000, "sonnet": 1_000_000, "haiku": 200_000,
    "claude": 200_000, "deepseek": 163_840, "qwen": 131_072, "grok": 131_072,
    "llama": 128_000, "mistral": 131_072, "nova": 300_000, "nemotron": 128_000,
    "gpt-oss": 131_072, "glm": 128_000, "kimi": 128_000,
}
DEFAULT_CONTEXT = 128_000


def context_window_for(model: str) -> int:
    m = (model or "").lower()
    for fam, window in _CONTEXT.items():
        if fam in m:
            return window
    return DEFAULT_CONTEXT


# USD per 1M tokens (input, output). ESTIMATES - override via settings.pricing
# and verify against your provider's billing before trusting a hard budget cap.
PRICING_NOTE = "Prices are estimates (public list prices by model family); verify with your provider."
_PRICING: Dict[str, Dict[str, float]] = {
    "fable": {"input": 15.0, "output": 75.0},
    "opus": {"input": 15.0, "output": 75.0},
    "sonnet": {"input": 3.0, "output": 15.0},
    "haiku": {"input": 0.80, "output": 4.0},
    "deepseek": {"input": 0.28, "output": 0.42},
    "qwen": {"input": 0.40, "output": 1.20},
    "grok": {"input": 3.0, "output": 15.0},
    "llama": {"input": 0.20, "output": 0.60},
    "mistral": {"input": 0.40, "output": 2.0},
    "nova": {"input": 0.35, "output": 1.40},
    "nemotron": {"input": 0.20, "output": 0.60},
    "gpt-oss": {"input": 0.50, "output": 2.0},
}
_FAMILY_ORDER = tuple(_PRICING)


def price_for(model: str, overrides: Optional[dict] = None) -> Dict[str, float]:
    table = {**_PRICING, **(overrides or {})}
    m = (model or "").lower()
    for fam in _FAMILY_ORDER:
        if fam in m:
            return table[fam]
    return table.get("sonnet", _PRICING["sonnet"])      # unknown: mid-tier, never $0


def usd_for_usage(model: str, usage: dict, overrides: Optional[dict] = None) -> float:
    p = price_for(model, overrides)
    inp = (usage.get("input_tokens") or 0)
    out = (usage.get("output_tokens") or 0)
    cr = (usage.get("cache_read_input_tokens") or 0)
    cw = (usage.get("cache_creation_input_tokens") or 0)
    usd = (inp * p["input"] + out * p["output"]
           + cr * p["input"] * 0.10 + cw * p["input"] * 1.25) / 1_000_000
    return round(usd, 6)


def model_info(model: str, overrides: Optional[dict] = None, provider_kind: str = "") -> Dict[str, object]:
    """Routing/size/price facts the UI shows next to a model choice."""
    price = price_for(model, overrides)
    api = "converse" if provider_kind == "bedrock" else (
        "chat-completions" if uses_chat_completions(model) else "messages")
    return {"api": api,
            "context": context_window_for(model),
            "price_in": price["input"], "price_out": price["output"]}
