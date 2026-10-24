"""Gateway behaviours carried over from the pentest harness: prompt-cache safe-degrade,
max_completion_tokens latch, context-length recovery, Retry-After dates, debug log, mock mode."""
import json
import time
from email.utils import formatdate

import pytest

from fake_llm import FakeLLM
from msra.ai import settings as S
from msra.ai.client import LLMClient, ProviderConfig, _parse_retry_after


@pytest.fixture()
def fake(tmp_path, monkeypatch):
    monkeypatch.setenv("MSRA_AI_CONFIG", str(tmp_path / "ai.json"))
    f = FakeLLM()
    yield f
    f.close()


def gw(fake):
    return LLMClient(ProviderConfig(kind="gateway", base_url=fake.url, token="t"), ledger=S.UsageLedger())


def bodies(fake, path):
    return [b for p, _, b in fake.requests if p == path and b]


def test_system_prompt_is_cached_by_default(fake):
    gw(fake).complete(system="SYS", prompt="p", model="claude-sonnet-5-5")
    sys_ = bodies(fake, "/v1/messages")[0]["system"]
    assert sys_[0]["cache_control"] == {"type": "ephemeral"} and sys_[0]["text"] == "SYS"


def test_cache_can_be_disabled(fake, monkeypatch):
    monkeypatch.setenv("MSRA_LLM_PROMPT_CACHE", "0")
    gw(fake).complete(system="SYS", prompt="p", model="claude-sonnet-5-5")
    assert bodies(fake, "/v1/messages")[0]["system"] == "SYS"


def test_cache_rejection_degrades_once_and_latches(fake):
    fake.reject = lambda path, b: "system: Input should be a valid string; cache_control not allowed" \
        if isinstance(b.get("system"), list) else None
    c = gw(fake)
    r = c.complete(system="SYS", prompt="p", model="claude-sonnet-5-5")
    assert r.text == "OK"
    assert c._cache_disabled
    c.complete(system="SYS", prompt="p2", model="claude-sonnet-5-5")
    assert bodies(fake, "/v1/messages")[-1]["system"] == "SYS"      # latched: no more block form


def test_max_completion_tokens_latch(fake):
    fake.reject = lambda path, b: "Unsupported parameter: max_tokens; use max_completion_tokens" \
        if "max_tokens" in b else None
    c = gw(fake)
    assert c.complete(prompt="p", model="deepseek.v3.2").text == "OK"
    last = bodies(fake, "/v1/chat/completions")[-1]
    assert "max_completion_tokens" in last and "max_tokens" not in last
    c.complete(prompt="p", model="deepseek.v3.2")
    assert "max_tokens" not in bodies(fake, "/v1/chat/completions")[-1]


def test_context_length_error_retries_with_shrunk_prompt(fake):
    fake.reject = lambda path, b: "prompt is too long: maximum context length exceeded" \
        if len(b["messages"][-1]["content"]) > 30000 else None
    r = gw(fake).complete(prompt="A" * 20000 + "MIDDLE" + "Z" * 40000, model="claude-sonnet-5-5")
    assert r.text == "OK"
    sent = bodies(fake, "/v1/messages")[-1]["messages"][-1]["content"]
    assert len(sent) < 30000 and sent.startswith("AAA") and sent.endswith("ZZZ") and "truncated" in sent


def test_unrelated_400_is_not_swallowed(fake):
    fake.reject = lambda path, b: "model not found"
    with pytest.raises(Exception) as e:
        gw(fake).complete(prompt="p", model="claude-sonnet-5-5")
    assert "model not found" in str(e.value)
    assert len(bodies(fake, "/v1/messages")) == 1                    # no pointless retries


def test_retry_after_http_date():
    assert _parse_retry_after("2") == 2.0
    assert _parse_retry_after("0") == 0.1
    got = _parse_retry_after(formatdate(time.time() + 5, usegmt=True))
    assert 1.0 <= got <= 6.0
    assert _parse_retry_after("999999") == 60.0
    assert _parse_retry_after("garbage") is None and _parse_retry_after("") is None


def test_debug_log_is_masked(fake, tmp_path, monkeypatch):
    log = tmp_path / "raw.log"
    monkeypatch.setenv("MSRA_LLM_DEBUG_LOG", str(log))
    gw(fake).complete(prompt="key AKIAIOSFODNN7EXAMPLE end", model="claude-sonnet-5-5", mask_input=False)
    text = log.read_text()
    assert "claude-sonnet-5-5" in text and "AKIAIOSFODNN7EXAMPLE" not in text


def test_mock_provider_needs_no_network(monkeypatch, tmp_path):
    monkeypatch.setenv("MSRA_AI_CONFIG", str(tmp_path / "ai.json"))
    monkeypatch.setenv("MSRA_LLM_MOCK", "1")
    c = LLMClient(ledger=S.UsageLedger())
    assert c.provider.kind == "mock" and c.provider.configured
    c.mock_responses = ["first", "second"]
    assert [c.complete(prompt="x", model="sonnet").text for _ in range(3)] == ["first", "second", "second"]
    assert c.provider.public()["configured"] is True


def test_debug_log_masks_multiline_secret_before_serialising(fake, tmp_path, monkeypatch):
    log = tmp_path / "raw2.log"
    monkeypatch.setenv("MSRA_LLM_DEBUG_LOG", str(log))
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAabcdefghijklmnop\n-----END RSA PRIVATE KEY-----"
    gw(fake).complete(prompt=pem, model="claude-sonnet-5-5", mask_input=False)
    assert "MIIEowIBAAKCAQEA" not in log.read_text()
