import json
import time

import pytest

import msra.ai.client as ai_client
import msra.ai.routes as ai_routes
import server
from fake_llm import FakeLLM


def _findings(n=3):
    return {"package": "com.acme", "apk": "a.apk", "findings": [
        {"id": i, "fid": f"rule-x:/a/B{i}.java:1", "title": f"Issue {i}",
         "severity": "High" if i < n else "Low", "description": "d", "category": "WebView",
         "evidence": {"file": f"B{i}.java", "line": 1, "snippet": "webView.loadUrl(url);"}}
        for i in range(1, n + 1)]}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    fake = FakeLLM()
    monkeypatch.setenv("MSRA_LLM_BASE_URL", fake.url)
    monkeypatch.setenv("MSRA_LLM_TOKEN", "sekrit-token-xyz")
    monkeypatch.setenv("MSRA_AI_CONFIG", str(tmp_path / "ai.json"))
    monkeypatch.setattr(ai_client, "_client", None)            # rebuild client from env
    monkeypatch.setattr(server._db, "DB_PATH", tmp_path / "t.db")
    server._db.init_db()
    monkeypatch.setattr(server, "REPORTS_FOLDER", tmp_path / "reports")
    (tmp_path / "reports").mkdir()
    monkeypatch.setattr(server, "AUTH_TOKEN", "")
    server.app.config["TESTING"] = True
    sd = tmp_path / "reports" / "scan1"
    sd.mkdir()
    (sd / "findings.json").write_text(json.dumps(_findings()))
    server._db.upsert_scan("scan1", status="done", package="com.acme")
    ai_routes._jobs.clear()
    ai_routes.invalidate_feedback()
    server._ai_settings.LEDGER.reset()
    yield server.app.test_client(), fake
    fake.close()
    monkeypatch.setattr(ai_client, "_client", None)


def wait_done(c, timeout=10):
    t0 = time.time()
    while time.time() - t0 < timeout:
        job = c.get("/api/scans/scan1/ai-triage").get_json()
        if job["status"] != "running":
            return job
        time.sleep(0.05)
    raise AssertionError("triage did not finish")


def test_status_never_exposes_token(env):
    c, fake = env
    body = c.get("/api/ai/status").get_data(as_text=True)
    assert "sekrit-token-xyz" not in body
    j = json.loads(body)
    assert j["provider"]["kind"] == "gateway" and j["provider"]["configured"] is True
    assert "triage" in j["features"] and j["settings"]["triage"]["votes"] == 2


def test_models_catalog_from_gateway(env):
    c, _ = env
    ids = [m["id"] for m in c.get("/api/ai/models?refresh=1").get_json()["models"]]
    assert "deepseek.v3.2" in ids and not any("embed" in i for i in ids)


def test_settings_roundtrip_and_validation_and_csrf(env):
    c, _ = env
    r = c.put("/api/ai/settings", json={"models": {"triage": "deepseek.v3.2"}, "triage": {"votes": 3}})
    assert r.status_code == 200 and r.get_json()["models"]["triage"] == "deepseek.v3.2"
    assert c.put("/api/ai/settings", json={"models": {"triage": "bad id;"}}).status_code == 400
    assert c.put("/api/ai/settings", json={"triage": {"votes": 99}}).status_code == 400
    assert c.put("/api/ai/settings", json={"models": {"triage": "x"}},
                 headers={"Origin": "http://evil.example"}).status_code == 403


def test_connection_test_reports_substitution(env):
    c, fake = env
    fake.coerce_to = "anthropic.claude-sonnet-5-5"
    j = c.post("/api/ai/test", json={"model": "anthropic.claude-opus-5-5"}).get_json()
    assert j["ok"] and j["coerced"] is True and j["model_returned"] == "anthropic.claude-sonnet-5-5"
    assert c.post("/api/ai/test", json={"model": "bad model"}).status_code == 400


def test_full_triage_run_persists_and_surfaces_in_findings(env):
    c, fake = env
    fake.reply = json.dumps({"verdict": "true_positive", "confidence": 90, "reasoning": "reachable"})
    r = c.post("/api/scans/scan1/ai-triage", json={"votes": 2, "min_severity": "High"})
    assert r.status_code == 202 and r.get_json()["total"] == 2          # Low finding excluded
    job = wait_done(c)
    assert job["status"] == "done" and job["done"] == 2 and job["cost_usd"] > 0
    assert set(job["results"]) == {"1", "2"} and job["results"]["1"]["verdict"] == "true_positive"
    f = c.get("/api/scans/scan1/findings").get_json()["findings"]
    assert f[0]["ai_triage"]["verdict"] == "true_positive" and "ai_triage" not in f[2]
    # second run has nothing new to do unless forced
    assert c.post("/api/scans/scan1/ai-triage", json={"min_severity": "High"}).status_code == 400
    assert c.post("/api/scans/scan1/ai-triage", json={"min_severity": "High", "force": True}).status_code == 202
    wait_done(c)
    assert c.get("/api/ai/status").get_json()["usage"]["by_feature"]["triage"]["calls"] >= 8


def test_triage_secrets_are_masked_in_what_the_provider_sees(env):
    c, fake = env
    data = _findings(1)
    data["findings"][0]["evidence"]["snippet"] = 'String k = "AKIAIOSFODNN7EXAMPLE"; password="hunter2hunter2";'
    server._scan_dir("scan1").joinpath("findings.json").write_text(json.dumps(data))
    fake.reply = json.dumps({"verdict": "uncertain", "confidence": 10, "reasoning": "x"})
    assert c.post("/api/scans/scan1/ai-triage", json={"votes": 1, "min_severity": "Low"}).status_code == 202
    wait_done(c)
    sent = json.dumps([q[2] for q in fake.requests if q[2]])
    assert "AKIAIOSFODNN7EXAMPLE" not in sent and "hunter2hunter2" not in sent


def test_not_configured_and_bad_scan(env, monkeypatch):
    c, _ = env
    assert c.post("/api/scans/nope123/ai-triage", json={}).status_code == 404
    assert c.get("/api/scans/bad id/ai-triage").status_code in (400, 404)
    monkeypatch.setenv("MSRA_LLM_TOKEN", "")
    monkeypatch.setattr(ai_client, "_client", None)
    assert c.post("/api/scans/scan1/ai-triage", json={}).status_code == 400


def test_budget_cap_stops_triage_and_is_reported(env):
    c, fake = env
    c.put("/api/ai/settings", json={"budget": {"usd_cap": 0.0001}})
    fake.reply = json.dumps({"verdict": "true_positive", "confidence": 80, "reasoning": "x"})
    c.post("/api/scans/scan1/ai-triage", json={"votes": 2, "min_severity": "Low"})
    job = wait_done(c)
    assert job["status"] == "stopped" and "budget" in job["stopped"].lower()


def test_learning_loop_from_analyst_decisions(env):
    c, fake = env
    for i in (1, 2):
        assert c.patch(f"/api/scans/scan1/findings/{i}/triage", json={"status": "False Positive"}).status_code == 200
    c.patch("/api/scans/scan1/findings/3/triage", json={"status": "Confirmed"})
    j = c.get("/api/ai/learning?refresh=1").get_json()
    rule = next(r for r in j["rules"] if r["rule"] == "rule-x")
    assert rule["fp"] == 2 and rule["tp"] == 1 and j["decisions"] == 3
    f = c.get("/api/scans/scan1/findings").get_json()["findings"]
    assert f[0]["rule_feedback"]["fp"] == 2          # track record shown next to each finding


def test_cancel(env):
    c, fake = env
    assert c.post("/api/scans/scan1/ai-triage/cancel").status_code == 404


def test_feed_sync_wraps_untrusted_text_and_imports_rules_disabled(env, monkeypatch, tmp_path):
    c, fake = env
    import msra.rules_api as ra
    monkeypatch.setattr(ra, "USER_RULES_F", tmp_path / "user_rules.json")
    monkeypatch.setattr(ra, "OVERRIDES_F", tmp_path / "overrides.json")
    monkeypatch.setattr(ra, "_invalidate_cache", lambda: None)
    fake.reply = json.dumps([{"id": "ai-rule-1", "title": "T", "severity": "High", "category": "WebView",
                              "detection_type": "regex",
                              "patterns": [{"pattern": "foo\\(", "file_types": [".java"]}]}])
    monkeypatch.setattr(server, "_FEED_META", {"t": {"name": "T", "url": fake.url + "/feed"}})

    r = c.post("/api/intel/feed-sync", json={"feed": "t"})
    assert r.status_code == 200, r.get_json()
    j = r.get_json()
    assert j["added"] == 1 and j["imported_disabled"] is True

    # feed text reached the model only inside a nonce-delimited untrusted block
    prompt = next(q[2]["messages"][0]["content"] for q in fake.requests if q[2])
    assert "<untrusted_data_" in prompt and "addJavascriptInterface" in prompt
    # ...and the AI-authored rule starts disabled until an analyst enables it
    created = json.loads((tmp_path / "user_rules.json").read_text())["patterns"]
    assert len(created) == 1 and created[0]["id"].startswith("ai-") and created[0]["id"] != "ai-rule-1"
    assert created[0]["enabled"] is False
