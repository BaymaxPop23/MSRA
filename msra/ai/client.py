"""Provider-agnostic LLM client (stdlib only).

Providers (chosen from the environment - tokens are never stored in files):
  * anthropic (default): api.anthropic.com Messages API, key from ANTHROPIC_API_KEY
  * bedrock: native AWS Bedrock via boto3's Converse API (one request shape for every
    vendor). Set MSRA_LLM_PROVIDER=bedrock and a region (MSRA_BEDROCK_REGION / AWS_REGION).
    Credentials come from the standard AWS chain (env, AWS_PROFILE, SSO, instance role) -
    MSRA never reads or stores them. Needs `pip install boto3` (optional dependency).
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
from .models import (ALIASES, DIRECT_MODELS, family_of, is_chat_model, resolve_alias,
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
    kind: str                     # "anthropic" | "gateway" | "bedrock"
    base_url: str
    api_path: str = "/v1/messages"
    chat_path: str = "/v1/chat/completions"
    models_path: str = "/v1/models"
    token: str = field(default="", repr=False)
    auth_header: str = "Authorization"
    region: str = ""                       # bedrock only
    client_factory: Any = field(default=None, repr=False)   # bedrock only; tests inject a fake

    @classmethod
    def from_env(cls) -> "ProviderConfig":
        if os.environ.get("MSRA_LLM_MOCK", "").strip().lower() in ("1", "true", "yes"):
            return cls(kind="mock", base_url="")
        if os.environ.get("MSRA_LLM_PROVIDER", "").strip().lower() == "bedrock":
            region = (os.environ.get("MSRA_BEDROCK_REGION") or os.environ.get("AWS_REGION")
                      or os.environ.get("AWS_DEFAULT_REGION") or "").strip()
            return cls(kind="bedrock", base_url="", region=region)
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
        if self.kind == "mock":
            return True
        if self.kind == "bedrock":
            return bool(self.region) and (self.client_factory is not None or _boto3_available())
        return bool(self.token)

    def public(self) -> Dict[str, Any]:
        """Safe to show in the UI: never includes the token."""
        if self.kind == "mock":
            return {"kind": "mock", "host": "(no network)", "configured": True, "auth_header": "none"}
        if self.kind == "bedrock":
            return {"kind": "bedrock", "host": f"bedrock-runtime.{self.region or '?'}.amazonaws.com",
                    "configured": self.configured, "auth_header": "AWS credential chain",
                    "region": self.region, "boto3": _boto3_available() or self.client_factory is not None}
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


def _boto3_available() -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec("boto3") is not None
    except (ImportError, ValueError):
        return False


_BEDROCK_THROTTLE = {"ThrottlingException", "TooManyRequestsException", "ServiceQuotaExceededException"}
_BEDROCK_RETRY = _BEDROCK_THROTTLE | {"ModelTimeoutException", "ServiceUnavailableException",
                                      "InternalServerException", "ModelNotReadyException"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: that would forward the auth header elsewhere."""
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _parse_retry_after(value: str) -> Optional[float]:
    """Seconds form or HTTP-date form, capped; never 0 (would busy-loop)."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.1, min(float(value), _MAX_RETRY_AFTER_S))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        from datetime import datetime, timezone
        dt = parsedate_to_datetime(value)
        return max(0.1, min((dt - datetime.now(timezone.utc)).total_seconds(), _MAX_RETRY_AFTER_S))
    except (ValueError, TypeError, OverflowError):
        return None


def _prompt_cache_enabled() -> bool:
    return os.environ.get("MSRA_LLM_PROMPT_CACHE", "1").strip().lower() not in ("0", "false", "no", "off")


def _looks_like_cache_rejection(text: str) -> bool:
    """A 4xx naming the block-form system / cache_control shape (not an ordinary content bug)."""
    t = (text or "").lower()
    return any(s in t for s in ("cache_control", "cache control", "ephemeral", "unknown field",
                                "unknown key", "unexpected key", "additional propert", "not allowed"))


def _looks_like_context_error(text: str) -> bool:
    t = (text or "").lower()
    return any(s in t for s in ("maximum context length", "context length", "context window", "too long",
                                "reduce the length", "context_length_exceeded", "prompt is too long"))


def _shrink_prompt(prompt: str, keep: int = 24000) -> str:
    """Keep the head and tail of an over-long prompt (the middle is the least informative)."""
    if len(prompt) <= keep:
        return prompt
    half = keep // 2
    return prompt[:half] + "\n...[truncated to fit the model context]...\n" + prompt[-half:]


def _debug_log(entry: dict) -> None:
    """Opt-in raw request/response log (MSRA_LLM_DEBUG_LOG). Masked before it touches disk."""
    path = os.environ.get("MSRA_LLM_DEBUG_LOG", "").strip()
    if not path:
        return
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(mask(json.dumps(entry, default=str)) + "\n")
    except OSError:
        pass


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
        # Safe-degrade latches: once a gateway rejects a request shape, stop sending it.
        self._cache_disabled = False
        self._max_tokens_key = "max_tokens"
        self.mock_responses: List[str] = []       # tests / offline demos; cycles, last one repeats

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

    def _post(self, path: str, body: dict, token: str, timeout: float, retries: int = 3,
              adapt=None) -> dict:
        """POST with retry. `adapt(status, text, body)` may return a corrected body for a 4xx
        (safe-degrade: cache shape, max_completion_tokens, over-long prompt); it is tried once per
        distinct correction and the request is repeated without consuming a retry."""
        url = self.provider.base_url + path
        last: Optional[Exception] = None
        attempt = 0
        adapted = 0
        while attempt < retries:
            attempt += 1
            data = json.dumps(body).encode()
            req = urllib.request.Request(url, data=data, headers=self._headers(token), method="POST")
            wait = 2.0 * (2 ** (attempt - 1))
            try:
                with _OPENER.open(req, timeout=timeout) as resp:
                    payload = json.loads(resp.read().decode("utf-8", "replace"))
                if not isinstance(payload, dict):
                    raise LLMError("provider returned a non-object JSON response")
                _debug_log({"url": path, "request": body, "response": payload})
                return payload
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")[:2000] if e.fp else ""
                last = LLMError(f"HTTP {e.code}: {mask(text[:500])}", e.code)
                if e.code == 429:
                    ra = _parse_retry_after(e.headers.get("Retry-After", "")) if e.headers else None
                    wait = ra if ra is not None else wait
                elif e.code < 500 and e.code != 529:
                    if adapt is not None and adapted < 3:
                        fixed = adapt(e.code, text, body)
                        if fixed is not None:
                            adapted += 1
                            body = fixed
                            attempt -= 1
                            continue
                    _debug_log({"url": path, "request": body, "error_status": e.code, "error_body": text})
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

    # ── bedrock (native, boto3 Converse) ──────────────────────────────────
    def _bedrock(self, service: str):
        """Cached boto3 client. Raises LLMError (never ImportError) when unavailable."""
        with self._cache_lock:
            cache = self.__dict__.setdefault("_bedrock_clients", {})
            if service in cache:
                return cache[service]
        if not self.provider.region:
            raise LLMError("Bedrock needs a region: set MSRA_BEDROCK_REGION or AWS_REGION.", 400)
        if self.provider.client_factory is not None:
            cli = self.provider.client_factory(service, self.provider.region)
        else:
            try:
                import boto3
                from botocore.config import Config
            except ImportError:
                raise LLMError("Native Bedrock needs boto3: pip install boto3", 400)
            # MSRA does its own retry loop so the budget/deadline logic stays in one place.
            cli = boto3.client(service, region_name=self.provider.region,
                               config=Config(retries={"max_attempts": 1, "mode": "standard"},
                                             read_timeout=120, connect_timeout=10))
        with self._cache_lock:
            self.__dict__.setdefault("_bedrock_clients", {})[service] = cli
        return cli

    @staticmethod
    def _bedrock_error(exc: Exception) -> "LLMError":
        resp = getattr(exc, "response", None) or {}
        err = resp.get("Error") or {}
        code = err.get("Code") or type(exc).__name__
        status = (resp.get("ResponseMetadata") or {}).get("HTTPStatusCode")
        if code in _BEDROCK_THROTTLE:
            status = 429
        msg = mask(str(err.get("Message") or exc))[:300]
        if code in ("ExpiredTokenException", "UnrecognizedClientException", "AccessDeniedException"):
            msg += " (check your AWS credentials / model access for this region)"
        e = LLMError(f"Bedrock {code}: {msg}", status)
        e.retryable = code in _BEDROCK_RETRY or (isinstance(status, int) and status >= 500)
        return e

    def _converse(self, model: str, system: str, prompt: str, max_tokens: int,
                  temperature: Optional[float], retries: int = 3) -> dict:
        cli = self._bedrock("bedrock-runtime")
        kwargs: Dict[str, Any] = {
            "modelId": model,
            "messages": [{"role": "user", "content": [{"text": prompt}]}],
            "inferenceConfig": {"maxTokens": max_tokens},
        }
        if system:
            kwargs["system"] = [{"text": system}]
        if temperature is not None:
            kwargs["inferenceConfig"]["temperature"] = temperature
        last: Optional[LLMError] = None
        for attempt in range(1, retries + 1):
            try:
                out = cli.converse(**kwargs)
                if not isinstance(out, dict):
                    raise LLMError("Bedrock returned a non-object response")
                return out
            except LLMError:
                raise
            except Exception as exc:                      # botocore ClientError / EndpointConnectionError ...
                last = self._bedrock_error(exc)
                if not getattr(last, "retryable", False) and type(exc).__name__ != "EndpointConnectionError":
                    raise last
            if attempt < retries:
                time.sleep(2.0 * (2 ** (attempt - 1)))
        raise last or LLMError("Bedrock request failed")

    @staticmethod
    def _parse_converse(data: dict, requested: str):
        blocks = (((data.get("output") or {}).get("message") or {}).get("content")) or []
        text = "".join(b["text"] for b in blocks if isinstance(b, dict) and isinstance(b.get("text"), str))
        stop = data.get("stopReason") or ""
        if stop == "guardrail_intervened" and not text:
            raise LLMError("the model refused the request (guardrail)")
        u = data.get("usage") or {}
        usage = {"input_tokens": int(u.get("inputTokens") or 0),
                 "output_tokens": int(u.get("outputTokens") or 0),
                 "cache_read_input_tokens": int(u.get("cacheReadInputTokens") or 0),
                 "cache_creation_input_tokens": int(u.get("cacheWriteInputTokens") or 0)}
        # Converse does not echo the serving model; trust the id we asked for.
        return _strip_control_markers(text), usage, requested, {"end_turn": "end_turn", "max_tokens": "max_tokens"}.get(stop, stop)

    def _bedrock_models(self) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        seen = set()
        try:
            cli = self._bedrock("bedrock")
            # Inference profiles (us./eu./global.) are what newer models require; list them first.
            for prof in (cli.list_inference_profiles().get("inferenceProfileSummaries") or []):
                mid = prof.get("inferenceProfileId")
                if mid and mid not in seen and is_chat_model(mid):
                    out.append({"id": mid, "family": family_of(mid) or "", "label": prof.get("inferenceProfileName") or mid,
                                "source": "live"})
                    seen.add(mid)
            for m in (cli.list_foundation_models(byOutputModality="TEXT").get("modelSummaries") or []):
                mid = m.get("modelId")
                if mid and mid not in seen and is_chat_model(mid) and "ON_DEMAND" in (m.get("inferenceTypesSupported") or ["ON_DEMAND"]):
                    out.append({"id": mid, "family": family_of(mid) or "", "label": m.get("modelName") or mid,
                                "source": "live"})
                    seen.add(mid)
        except LLMError:
            raise
        except Exception as exc:
            raise self._bedrock_error(exc)
        return out

    # ── model catalog ────────────────────────────────────────────────────
    def list_models(self, force: bool = False, token: Optional[str] = None) -> List[Dict[str, str]]:
        with self._cache_lock:
            c = self._models_cache
            if not force and c["data"] is not None and time.monotonic() - c["ts"] < _MODELS_TTL_S:
                return c["data"]
        if self.provider.kind == "bedrock":
            models: List[Dict[str, str]] = []
            if self.provider.configured:
                try:
                    models = self._bedrock_models()
                except LLMError as e:
                    logger.info("bedrock model catalog fetch failed: %s", e)
            models.sort(key=lambda m: m["id"])
            with self._cache_lock:
                self._models_cache.update(ts=time.monotonic(), data=models)
            return models
        tok = token or self.provider.token
        models = [dict(m, source="builtin") for m in DIRECT_MODELS] if self.provider.kind in ("anthropic", "mock") else []
        if tok and self.provider.kind != "mock":
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
        return resolve_alias(model, self.catalog_ids() if self.provider.kind in ("gateway", "bedrock") else None)

    # ── completion ───────────────────────────────────────────────────────
    def complete(self, *, system: str = "", prompt: str, model: str, max_tokens: int = 1024,
                 feature: str = "", temperature: Optional[float] = None, timeout: float = 90,
                 api_key: Optional[str] = None, mask_input: bool = True) -> LLMResult:
        token = api_key or self.provider.token
        bedrock = self.provider.kind == "bedrock"
        if self.provider.kind == "mock":
            return self._mock_complete(model, prompt, max_tokens, feature)
        if bedrock:
            if not self.provider.configured:
                raise LLMError("Bedrock is not usable: set a region (MSRA_BEDROCK_REGION / AWS_REGION) "
                               "and install boto3.", 401)
        elif not token:
            raise LLMError("No API credentials configured (set ANTHROPIC_API_KEY, or "
                           "MSRA_LLM_BASE_URL + MSRA_LLM_TOKEN for a gateway, or "
                           "MSRA_LLM_PROVIDER=bedrock).", 401)
        cfg = _settings.load()
        self.ledger.check(cfg["budget"].get("usd_cap"))

        if bedrock and (model or "").strip().lower() in ALIASES and not self._models_cache.get("data"):
            self.list_models()                    # bare tier names need the live Bedrock catalog
        exact = self.resolve(model)
        if mask_input:
            system, prompt = mask(system), mask(prompt)

        chat = uses_chat_completions(exact)
        if chat and self.provider.kind == "anthropic":
            raise LLMError(f"'{exact}' is not a Claude model; non-Claude models need a gateway "
                           "(set MSRA_LLM_BASE_URL).", 400)

        if bedrock:
            data = self._converse(exact, system, prompt, max_tokens, temperature)
            text, usage, returned, stop = self._parse_converse(data, exact)
        elif chat:
            msgs = ([{"role": "system", "content": system}] if system else []) + \
                   [{"role": "user", "content": prompt}]
            body: Dict[str, Any] = {"model": exact, self._max_tokens_key: max_tokens, "messages": msgs}
            if temperature is not None:
                body["temperature"] = temperature
            data = self._post(self.provider.chat_path, body, token, timeout, adapt=self._adapt_chat)
            text, usage, returned, stop = self._parse_chat(data, exact)
        else:
            body = {"model": exact, "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}]}
            if system:
                # Cache the (stable) system prompt: N-vote triage and batch runs repeat it verbatim.
                body["system"] = ([{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
                                  if _prompt_cache_enabled() and not self._cache_disabled else system)
            if temperature is not None:
                body["temperature"] = temperature
            data = self._post(self.provider.api_path, body, token, timeout, adapt=self._adapt_messages)
            text, usage, returned, stop = self._parse_messages(data, exact)

        usd = usd_for_usage(exact, usage, cfg.get("pricing"))
        self.ledger.record(feature, exact, usage, usd)

        fam = family_of(exact)
        coerced = bool(fam and returned and fam not in returned.lower())
        if coerced:
            logger.warning("provider answered '%s' for requested '%s' (alias substitution?)", returned, exact)
        return LLMResult(text=text, model=exact, model_returned=returned, usage=usage,
                         usd=usd, stop_reason=stop, coerced=coerced)

    def _adapt_messages(self, status: int, text: str, body: dict) -> Optional[dict]:
        if isinstance(body.get("system"), list) and _looks_like_cache_rejection(text):
            self._cache_disabled = True
            logger.info("provider rejected cache_control; prompt caching disabled for this process")
            return dict(body, system=body["system"][0]["text"])
        return self._shrink_on_context_error(text, body)

    def _adapt_chat(self, status: int, text: str, body: dict) -> Optional[dict]:
        if "max_tokens" in body and "max_completion_tokens" in text:
            self._max_tokens_key = "max_completion_tokens"
            fixed = dict(body)
            fixed["max_completion_tokens"] = fixed.pop("max_tokens")
            return fixed
        return self._shrink_on_context_error(text, body)

    @staticmethod
    def _shrink_on_context_error(text: str, body: dict) -> Optional[dict]:
        if not _looks_like_context_error(text):
            return None
        msgs = body.get("messages") or []
        if not msgs or not isinstance(msgs[-1].get("content"), str):
            return None
        last = msgs[-1]["content"]
        shrunk = _shrink_prompt(last)
        if shrunk == last:
            return None
        return dict(body, messages=msgs[:-1] + [dict(msgs[-1], content=shrunk)])

    def _mock_complete(self, model: str, prompt: str, max_tokens: int, feature: str) -> "LLMResult":
        """No-network provider (MSRA_LLM_MOCK=1) so the AI features can be exercised end to end."""
        i = getattr(self, "_mock_i", 0)
        self._mock_i = i + 1
        if self.mock_responses:
            text = self.mock_responses[min(i, len(self.mock_responses) - 1)]
        else:
            text = '{"verdict": "uncertain", "confidence": 0.5, "reason": "mock provider"}'
        usage = {"input_tokens": max(1, len(prompt) // 4), "output_tokens": max(1, len(text) // 4),
                 "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
        self.ledger.record(feature, model or "mock", usage, 0.0)
        return LLMResult(text=text, model=model or "mock", model_returned=model or "mock",
                         usage=usage, usd=0.0, stop_reason="end_turn")

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
