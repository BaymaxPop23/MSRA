"""Native Bedrock provider, exercised against a fake boto3 client (no AWS access)."""
import pytest

from msra.ai import settings as S
from msra.ai.client import LLMClient, LLMError, ProviderConfig


class ClientError(Exception):
    def __init__(self, code, msg="boom", http=400):
        super().__init__(msg)
        self.response = {"Error": {"Code": code, "Message": msg},
                         "ResponseMetadata": {"HTTPStatusCode": http}}


class FakeRuntime:
    def __init__(self, script=None):
        self.calls = []
        self.script = list(script or [])

    def converse(self, **kw):
        self.calls.append(kw)
        if self.script:
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return {"output": {"message": {"content": [{"text": "hello"}]}}, "stopReason": "end_turn",
                "usage": {"inputTokens": 10, "outputTokens": 5}}


class FakeControl:
    def list_inference_profiles(self):
        return {"inferenceProfileSummaries": [
            {"inferenceProfileId": "us.anthropic.claude-sonnet-5-5-v1:0", "inferenceProfileName": "Sonnet"},
            {"inferenceProfileId": "us.anthropic.claude-sonnet-4-6-v1:0", "inferenceProfileName": "Old"},
            {"inferenceProfileId": "us.amazon.embed-v1", "inferenceProfileName": "Emb"}]}

    def list_foundation_models(self, **kw):
        return {"modelSummaries": [
            {"modelId": "deepseek.v3-v1:0", "modelName": "DeepSeek", "inferenceTypesSupported": ["ON_DEMAND"]},
            {"modelId": "provisioned.only", "modelName": "P", "inferenceTypesSupported": ["PROVISIONED"]}]}


def make(runtime=None, region="us-east-1"):
    runtime = runtime or FakeRuntime()
    ctl = FakeControl()
    cfg = ProviderConfig(kind="bedrock", base_url="", region=region,
                         client_factory=lambda svc, reg: runtime if svc == "bedrock-runtime" else ctl)
    return LLMClient(cfg, ledger=S.UsageLedger()), runtime


@pytest.fixture(autouse=True)
def _cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("MSRA_AI_CONFIG", str(tmp_path / "ai.json"))
    monkeypatch.setattr("time.sleep", lambda *_: None)


def test_from_env_selects_bedrock(monkeypatch):
    monkeypatch.setenv("MSRA_LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.delenv("MSRA_BEDROCK_REGION", raising=False)
    cfg = ProviderConfig.from_env()
    assert cfg.kind == "bedrock" and cfg.region == "eu-west-1"
    pub = cfg.public()
    assert "token" not in str(pub).lower() and pub["region"] == "eu-west-1"


def test_no_region_is_not_configured():
    c, _ = make(region="")
    assert not c.provider.configured
    with pytest.raises(LLMError):
        c.complete(prompt="x", model="us.anthropic.claude-sonnet-5-5-v1:0")


def test_converse_request_and_usage():
    c, rt = make()
    r = c.complete(system="be brief", prompt="hi", model="us.anthropic.claude-sonnet-5-5-v1:0",
                   max_tokens=77, temperature=0.2, feature="quick")
    assert r.text == "hello" and r.usage["input_tokens"] == 10 and r.usd > 0 and not r.coerced
    kw = rt.calls[0]
    assert kw["modelId"] == "us.anthropic.claude-sonnet-5-5-v1:0"
    assert kw["system"] == [{"text": "be brief"}]
    assert kw["inferenceConfig"] == {"maxTokens": 77, "temperature": 0.2}
    assert kw["messages"][0]["content"] == [{"text": "hi"}]


def test_non_claude_models_use_converse_too():
    c, rt = make()
    c.complete(prompt="hi", model="deepseek.v3-v1:0")
    assert rt.calls[0]["modelId"] == "deepseek.v3-v1:0"


def test_input_is_masked_before_send():
    c, rt = make()
    c.complete(prompt="key AKIAIOSFODNN7EXAMPLE here", model="us.anthropic.claude-sonnet-5-5-v1:0")
    assert "AKIAIOSFODNN7EXAMPLE" not in rt.calls[0]["messages"][0]["content"][0]["text"]


def test_alias_resolves_to_newest_live_profile():
    c, rt = make()
    c.complete(prompt="hi", model="sonnet")
    assert rt.calls[0]["modelId"] == "us.anthropic.claude-sonnet-5-5-v1:0"


def test_catalog_filters_non_chat_and_provisioned():
    c, _ = make()
    ids = [m["id"] for m in c.list_models()]
    assert "deepseek.v3-v1:0" in ids and "us.anthropic.claude-sonnet-5-5-v1:0" in ids
    assert "us.amazon.embed-v1" not in ids and "provisioned.only" not in ids


def test_throttle_is_retried_then_succeeds():
    rt = FakeRuntime([ClientError("ThrottlingException", http=429), ClientError("ModelTimeoutException", http=408)])
    c, _ = make(rt)
    assert c.complete(prompt="hi", model="us.anthropic.claude-sonnet-5-5-v1:0").text == "hello"
    assert len(rt.calls) == 3


def test_auth_errors_are_not_retried_and_are_actionable():
    rt = FakeRuntime([ClientError("AccessDeniedException", "no model access", 403)])
    c, _ = make(rt)
    with pytest.raises(LLMError) as ei:
        c.complete(prompt="hi", model="us.anthropic.claude-sonnet-5-5-v1:0")
    assert len(rt.calls) == 1 and ei.value.status == 403 and "credentials" in str(ei.value)


def test_persistent_throttle_surfaces_429():
    rt = FakeRuntime([ClientError("ThrottlingException", http=429)] * 3)
    c, _ = make(rt)
    with pytest.raises(LLMError) as ei:
        c.complete(prompt="hi", model="us.anthropic.claude-sonnet-5-5-v1:0")
    assert ei.value.status == 429


def test_guardrail_with_no_text_is_a_refusal():
    rt = FakeRuntime([{"output": {"message": {"content": []}}, "stopReason": "guardrail_intervened", "usage": {}}])
    c, _ = make(rt)
    with pytest.raises(LLMError):
        c.complete(prompt="hi", model="us.anthropic.claude-sonnet-5-5-v1:0")
