import json
import os

import pytest

from fake_llm import FakeLLM
from msra.ai import settings as S
from msra.ai.client import LLMClient, LLMError, ProviderConfig, parse_json_block
from msra.ai.models import (resolve_alias, uses_chat_completions, context_window_for,
                            usd_for_usage, valid_model_id, price_for)


@pytest.fixture()
def fake(tmp_path, monkeypatch):
    monkeypatch.setenv("MSRA_AI_CONFIG", str(tmp_path / "ai.json"))
    f = FakeLLM()
    yield f
    f.close()


def client(fake, kind="gateway"):
    cfg = ProviderConfig(kind=kind, base_url=fake.url, token="tok-123",
                         auth_header="Authorization" if kind == "gateway" else "x-api-key")
    return LLMClient(cfg, ledger=S.UsageLedger())


# ── pure helpers ─────────────────────────────────────────────────────────
def test_routing_and_aliases():
    assert not uses_chat_completions("anthropic.claude-opus-5-5")
    assert not uses_chat_completions("claude-haiku-5-5")
    assert uses_chat_completions("deepseek.v3.2")
    assert uses_chat_completions("meta.llama4-70b")
    assert not uses_chat_completions("")                      # blank never mis-routes
    assert resolve_alias("sonnet") == "claude-sonnet-5-5"
    assert resolve_alias("claude-opus-5-5") == "claude-opus-5-5"
    assert resolve_alias("sonnet", ["anthropic.claude-sonnet-5-5", "anthropic.claude-sonnet-4-6"]) \
        == "anthropic.claude-sonnet-5-5"


def test_pricing_and_context_fail_safe():
    assert context_window_for("totally-unknown") == 128_000
    assert price_for("totally-unknown")["input"] == price_for("sonnet")["input"] > 0
    assert usd_for_usage("claude-haiku-5-5", {"input_tokens": 1_000_000, "output_tokens": 0}) == 0.8


def test_model_id_validation():
    assert valid_model_id("anthropic.claude-sonnet-5-5") and valid_model_id("deepseek.v3.2")
    for bad in ("", "a b", "x;rm -rf", "<script>", "a" * 200):
        assert not valid_model_id(bad)


def test_parse_json_block():
    assert parse_json_block('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_block('Sure! {"v": "x"} done') == {"v": "x"}
    with pytest.raises(ValueError):
        parse_json_block("no json here")


# ── transport ────────────────────────────────────────────────────────────
def test_claude_uses_messages_api_with_bearer(fake):
    r = client(fake).complete(prompt="hi", model="anthropic.claude-sonnet-5-5", feature="t")
    path, headers, body = fake.requests[-1]
    assert path == "/v1/messages" and headers["Authorization"] == "Bearer tok-123"
    assert body["model"] == "anthropic.claude-sonnet-5-5"
    assert r.text == "OK" and r.usd > 0 and not r.coerced


def test_non_claude_uses_chat_completions(fake):
    r = client(fake).complete(system="sys", prompt="hi", model="deepseek.v3.2")
    path, _, body = fake.requests[-1]
    assert path == "/v1/chat/completions"
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert r.text == "OK" and r.usage["input_tokens"] == 1000


def test_direct_provider_rejects_non_claude(fake):
    with pytest.raises(LLMError, match="gateway"):
        client(fake, "anthropic").complete(prompt="x", model="deepseek.v3.2")


def test_anthropic_direct_header(fake):
    client(fake, "anthropic").complete(prompt="x", model="claude-haiku-5-5")
    headers = {k.lower(): v for k, v in fake.requests[-1][1].items()}   # header names are case-insensitive
    assert headers["x-api-key"] == "tok-123"


def test_retries_429_then_succeeds(fake):
    fake.fail_first_429 = True
    r = client(fake).complete(prompt="x", model="claude-haiku-5-5")
    assert r.text == "OK" and len([q for q in fake.requests if q[0] == "/v1/messages"]) == 2


def test_4xx_not_retried_and_token_not_leaked(fake):
    fake.status = 400
    with pytest.raises(LLMError) as ei:
        client(fake).complete(prompt="x", model="claude-haiku-5-5")
    assert ei.value.status == 400 and "tok-123" not in str(ei.value)
    assert len([q for q in fake.requests if q[0] == "/v1/messages"]) == 1


def test_model_substitution_is_flagged(fake):
    fake.coerce_to = "claude-sonnet-5-5"            # gateway ignored the alias
    r = client(fake).complete(prompt="x", model="claude-opus-5-5")
    assert r.coerced and r.model_returned == "claude-sonnet-5-5"


def test_secrets_masked_before_sending(fake):
    client(fake).complete(prompt='password="hunter2hunter2" and AKIAIOSFODNN7EXAMPLE', model="claude-haiku-5-5")
    sent = json.dumps(fake.requests[-1][2])
    assert "hunter2hunter2" not in sent and "AKIAIOSFODNN7EXAMPLE" not in sent
    client(fake).complete(prompt="password=abcdef123456", model="claude-haiku-5-5", mask_input=False)
    assert "abcdef123456" in json.dumps(fake.requests[-1][2])


def test_redirects_are_not_followed(fake):
    fake.redirect_to = "http://127.0.0.1:1/steal"
    with pytest.raises(LLMError):
        client(fake).complete(prompt="x", model="claude-haiku-5-5")
    assert all(q[0] != "/steal" for q in fake.requests)


def test_missing_credentials():
    c = LLMClient(ProviderConfig(kind="anthropic", base_url="http://127.0.0.1:1", token=""), ledger=S.UsageLedger())
    with pytest.raises(LLMError) as ei:
        c.complete(prompt="x", model="claude-haiku-5-5")
    assert ei.value.status == 401


def test_catalog_filters_non_chat_and_provider_public_hides_token(fake):
    c = client(fake)
    ids = [m["id"] for m in c.list_models(force=True)]
    assert "deepseek.v3.2" in ids and "anthropic.claude-sonnet-5-5" in ids
    assert not any("embed" in i for i in ids)
    assert "tok-123" not in json.dumps(c.provider.public())
    # gateway alias resolution now uses the live catalog
    assert c.resolve("sonnet") == "anthropic.claude-sonnet-5-5"


# ── settings, budget ─────────────────────────────────────────────────────
def test_budget_cap_blocks_calls(fake):
    S.save({"budget": {"usd_cap": 0.001}})
    c = client(fake)
    c.complete(prompt="x", model="claude-opus-5-5")            # first call spends > cap
    with pytest.raises(S.BudgetExceeded):
        c.complete(prompt="x", model="claude-opus-5-5")


def test_settings_validation_and_roundtrip(fake):
    cfg = S.save({"models": {"triage": "claude-opus-5-5"}, "triage": {"votes": 3}})
    assert cfg["models"]["triage"] == "claude-opus-5-5" and cfg["triage"]["votes"] == 3
    for bad in ({"models": {"nope": "x"}}, {"models": {"triage": "a b"}},
                {"triage": {"votes": 9}}, {"triage": {"min_severity": "Huge"}},
                {"budget": {"usd_cap": -1}}, "string"):
        with pytest.raises((ValueError, TypeError)):
            S.save(bad)
    assert S.model_for("triage") == "claude-opus-5-5"
    assert S.model_for("quick") == "haiku"


def test_legacy_env_models_used_until_user_chooses(fake, monkeypatch):
    monkeypatch.setenv("MSRA_CLAUDE_MODEL", "claude-opus-5-5")
    assert S.model_for("poc") == "claude-opus-5-5"
    S.save({"models": {"poc": "claude-haiku-5-5"}})
    assert S.model_for("poc") == "claude-haiku-5-5"
