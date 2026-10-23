"""Provider-agnostic LLM client (stdlib only).

Providers (chosen from the environment - tokens are never stored in files):
  * anthropic (default): api.anthropic.com Messages API, key from ANTHROPIC_API_KEY
  * gateway: any Bedrock-style multi-vendor gateway. Set MSRA_LLM_BASE_URL and
    MSRA_LLM_TOKEN (plus optionally MSRA_LLM_AUTH_HEADER, MSRA_LLM_API_PATH,
    MSRA_LLM_CHAT_PATH, MSRA_LLM_MODELS_PATH). Claude ids use the Messages API;
    other vendors (deepseek, qwen, llama, nova, ...) use chat-completions.

Everything callers see is normalised to LLMResult.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import settings as _settings
from .masking import mask
from .models import (DIRECT_MODELS, family_of, is_chat_model, resolve_alias,
                     usd_for_usage, uses_chat_completions)

logger = logging.getLogger(__name__)

_MAX_RETRY_AFTER_S = 60.0
_MODELS_TTL_S = 300


class LLMError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


@dataclass
class ProviderConfig:
    kind: str                     # "anthropic" | "gateway"
    base_url: str
    api_path: str = "/v1/messages"
    chat_path: str = "/v1/chat/completions"
    models_path: str = "/v1/models"
    token: str = field(default="", repr=False)
    auth_header: str = "Authorization"

    @classmethod
    def from_env(cls) -> "ProviderConfig":
        base = os.environ.get("MSRA_LLM_BASE_URL", "").strip()
        if base:
            return cls(
                kind="gateway", base_url=base.rstrip("/"),
                api_path=os.environ.get("MSRA_LLM_API_PATH", "/v1/messages"),
                chat_path=os.environ.get("MSRA_LLM_CHAT_PATH", "/v1/chat/completions"),
                models_path=os.environ.get("MSRA_LLM_MODELS_PATH", "/v1/models"),
                token=os.environ.get("MSRA_LLM_TOKEN", ""),
                auth_header=os.environ.get("MSRA_LLM_AUTH_HEADER", "Authorization"))
        return cls(kind="anthropic", base_url="https://api.anthropic.com",
                   token=os.environ.get("ANTHROPIC_API_KEY", ""))

    @property
    def configured(self) -> bool:
        return bool(self.token)

    def public(self) -> Dict[str, Any]:
        """Safe to show in the UI: never includes the token."""
        host = re.sub(r"^https?://", "", self.base_url).split("/")[0]
        return {"kind": self.kind, "host": host, "configured": self.configured,
                "auth_header": self.auth_header if self.kind == "gateway" else "x-api-key"}


@dataclass
class LLMResult:
    text: str
    model: str                    # exact id that was requested
    model_returned: str = ""
    usage: Dict[str, int] = field(default_factory=dict)
    usd: float = 0.0
    stop_reason: str = ""
    coerced: bool = False         # provider answered with a different model family


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: that would forward the auth header elsewhere."""
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _parse_retry_after(value: str) -> Optional[float]:
    try:
        return max(0.1, min(float(value), _MAX_RETRY_AFTER_S))
    except (TypeError, ValueError):
        return None


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(p["text"] if isinstance(p, dict) and p.get("type") == "text"
                       and isinstance(p.get("text"), str) else (p if isinstance(p, str) else "")
                       for p in content)
    return str(content)


_CONTROL_MARKERS = ("<｜DSML｜", "<|DSML|>", "<｜tool▁calls▁begin｜>", "<|tool_calls_begin|>")


def _strip_control_markers(text: str) -> str:
    cut = len(text)
    for m in _CONTROL_MARKERS:
        i = text.find(m)
        if i != -1:
            cut = min(cut, i)
    return text[:cut].rstrip()


class LLMClient:
    def __init__(self, provider: Optional[ProviderConfig] = None, ledger=None):
        self.provider = provider or ProviderConfig.from_env()
        self.ledger = ledger or _settings.LEDGER
        self._models_cache: Dict[str, Any] = {"ts": 0.0, "data": None}
        self._cache_lock = threading.Lock()

    # ── helpers ──────────────────────────────────────────────────────────
    def _headers(self, token: str) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
        if self.provider.kind == "anthropic":
            h["x-api-key"] = token
        elif self.provider.auth_header.lower() == "authorization":
            h["Authorization"] = f"Bearer {token}"
        else:
            h[self.provider.auth_header] = token
        return h

    def _post(self, path: str, body: dict, token: str, timeout: float, retries: int = 3) -> dict:
        url = self.provider.base_url + path
        data = json.dumps(body).encode()
        last: Optional[Exception] = None
        for attempt in range(1, retries + 1):
            req = urllib.request.Request(url, data=data, headers=self._headers(token), method="POST")
            wait = 2.0 * (2 ** (attempt - 1))
            try:
                with _OPENER.open(req, timeout=timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8", "replace"))
                if not isinstance(payload, dict):
                    raise LLMError("provider returned a non-object JSON response")
                return payload
            except urllib.error.HTTPError as e:
                text = mask(e.read().decode("utf-8", "replace")[:500]) if e.fp else ""
                last = LLMError(f"HTTP {e.code}: {text}", e.code)
                if e.code == 429:
                    ra = _parse_retry_after(e.headers.get("Retry-After", "")) if e.headers else None
                    wait = ra if ra is not None else wait
                elif e.code < 500 and e.code != 529:
                    raise last                       # 4xx: retrying cannot help
            except (urllib.error.URLError, TimeoutError, ConnectionError, ValueError) as e:
                last = LLMError(f"request failed: {mask(str(e))[:200]}")
            if attempt < retries:
                time.sleep(wait)
        raise last or LLMError("request failed")

    def _get(self, path: str, token: str, timeout: float = 15) -> Any:
        req = urllib.request.Request(self.provider.base_url + path, headers=self._headers(token))
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            raise LLMError(f"HTTP {e.code}: {mask(e.read().decode('utf-8', 'replace')[:300])}", e.code)
        except (urllib.error.URLError, TimeoutError, ValueError) as e:
            raise LLMError(f"request failed: {mask(str(e))[:200]}")

    # ── model catalog ────────────────────────────────────────────────────
    def list_models(self, force: bool = False, token: Optional[str] = None) -> List[Dict[str, str]]:
        with self._cache_lock:
            c = self._models_cache
            if not force and c["data"] is not None and time.monotonic() - c["ts"] < _MODELS_TTL_S:
                return c["data"]
        tok = token or self.provider.token
        models = [dict(m, source="builtin") for m in DIRECT_MODELS] if self.provider.kind == "anthropic" else []
        if tok:
            try:
                raw = self._get(self.provider.models_path, tok)
                items = raw.get("data", raw) if isinstance(raw, dict) else raw
                seen = {m["id"] for m in models}
                for it in items if isinstance(items, list) else []:
                    mid = it.get("id") if isinstance(it, dict) else None
                    if not mid or mid in seen or not is_chat_model(mid):
                        continue
                    if self.provider.kind == "anthropic" and not mid.startswith("claude"):
                        continue
                    models.append({"id": mid, "family": family_of(mid) or "", "label": mid, "source": "live"})
                    seen.add(mid)
            except LLMError as e:
                logger.info("model catalog fetch failed: %s", e)
        models.sort(key=lambda m: (m.get("source") != "builtin", m["id"]))
        with self._cache_lock:
            self._models_cache.update(ts=time.monotonic(), data=models)
        return models

    def catalog_ids(self) -> List[str]:
        return [m["id"] for m in (self._models_cache.get("data") or [])]

    def resolve(self, model: str) -> str:
        return resolve_alias(model, self.catalog_ids() if self.provider.kind == "gateway" else None)

    # ── completion ───────────────────────────────────────────────────────
    def complete(self, *, system: str = "", prompt: str, model: str, max_tokens: int = 1024,
                 feature: str = "", temperature: Optional[float] = None, timeout: float = 90,
                 api_key: Optional[str] = None, mask_input: bool = True) -> LLMResult:
        token = api_key or self.provider.token
        if not token:
            raise LLMError("No API credentials configured (set ANTHROPIC_API_KEY, or "
                           "MSRA_LLM_BASE_URL + MSRA_LLM_TOKEN for a gateway).", 401)
        cfg = _settings.load()
        self.ledger.check(cfg["budget"].get("usd_cap"))

        exact = self.resolve(model)
        if mask_input:
            system, prompt = mask(system), mask(prompt)

        chat = uses_chat_completions(exact)
        if chat and self.provider.kind != "gateway":
            raise LLMError(f"'{exact}' is not a Claude model; non-Claude models need a gateway "
                           "(set MSRA_LLM_BASE_URL).", 400)

        if chat:
            msgs = ([{"role": "system", "content": system}] if system else []) + \
                   [{"role": "user", "content": prompt}]
            body: Dict[str, Any] = {"model": exact, "max_tokens": max_tokens, "messages": msgs}
            if temperature is not None:
                body["temperature"] = temperature
            data = self._post(self.provider.chat_path, body, token, timeout)
            text, usage, returned, stop = self._parse_chat(data, exact)
        else:
            body = {"model": exact, "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}]}
            if system:
                body["system"] = system
            if temperature is not None:
                body["temperature"] = temperature
            data = self._post(self.provider.api_path, body, token, timeout)
            text, usage, returned, stop = self._parse_messages(data, exact)

        usd = usd_for_usage(exact, usage, cfg.get("pricing"))
        self.ledger.record(feature, exact, usage, usd)

        fam = family_of(exact)
        coerced = bool(fam and returned and fam not in returned.lower())
        if coerced:
            logger.warning("provider answered '%s' for requested '%s' (alias substitution?)", returned, exact)
        return LLMResult(text=text, model=exact, model_returned=returned, usage=usage,
                         usd=usd, stop_reason=stop, coerced=coerced)

    @staticmethod
    def _parse_messages(data: dict, requested: str):
        if data.get("type") == "error" or ("error" in data and "content" not in data):
            raise LLMError(f"provider error: {mask(json.dumps(data.get('error', data))[:300])}")
        text = "".join(b.get("text", "") for b in data.get("content") or []
                       if isinstance(b, dict) and b.get("type") == "text")
        u = data.get("usage") or {}
        usage = {k: int(u.get(k) or 0) for k in
                 ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")}
        return text, usage, data.get("model") or requested, data.get("stop_reason") or ""

    @staticmethod
    def _parse_chat(data: dict, requested: str):
        if data.get("error") and not data.get("choices"):
            raise LLMError(f"provider error: {mask(json.dumps(data['error'])[:300])}")
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise LLMError("provider response had no choices")
        msg = choices[0].get("message") or {}
        text = _strip_control_markers(_content_to_text(msg.get("content")))
        if choices[0].get("finish_reason") == "content_filter" and not text:
            raise LLMError("the model refused the request (content filter)")
        u = data.get("usage") or {}
        usage = {"input_tokens": int(u.get("prompt_tokens") or 0),
                 "output_tokens": int(u.get("completion_tokens") or 0)}
        stop = {"length": "max_tokens", "stop": "end_turn"}.get(choices[0].get("finish_reason") or "", "")
        return text, usage, data.get("model") or requested, stop


# ── JSON helpers shared by features ──────────────────────────────────────

def parse_json_block(text: str) -> Any:
    """Extract the first JSON object/array from model output (fences tolerated)."""
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip(), flags=re.M)
    for opener, closer in (("{", "}"), ("[", "]")):
        s, e = t.find(opener), t.rfind(closer)
        if s != -1 and e > s:
            try:
                return json.loads(t[s:e + 1])
            except ValueError:
                continue
    raise ValueError("no JSON found in model output")


def parse_json_array(text: str) -> list:
    """Extract the first JSON array from model output; [] when there is none."""
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", (text or "").strip(), flags=re.M)
    s, e = t.find("["), t.rfind("]")
    if s != -1 and e > s:
        try:
            val = json.loads(t[s:e + 1])
            return val if isinstance(val, list) else []
        except ValueError:
            pass
    return []


_client_lock = threading.Lock()
_client: Optional[LLMClient] = None


def get_client() -> LLMClient:
    """Process-wide client (so the model-catalog cache is shared)."""
    global _client
    with _client_lock:
        if _client is None:
            _client = LLMClient()
        return _client
