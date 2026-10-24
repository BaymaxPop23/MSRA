"""Regressions for the backend review: each test pins a bug that was reproduced."""
import io
import json
import threading
import time
import zipfile
from pathlib import Path

import pytest

import msra.ai.client as ai_client
import msra.ai.routes as ai_routes
import msra.ai.settings as ai_settings
import msra.db as db
import server
from fake_llm import FakeLLM
from msra.corellium import CorelliumClient, validate_corellium_url


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    db.init_db()
    monkeypatch.setattr(server, "REPORTS_FOLDER", tmp_path / "reports")
    (tmp_path / "reports").mkdir()
    monkeypatch.setattr(server, "AUTH_TOKEN", "")
    monkeypatch.setattr(server, "_LOOPBACK_ONLY", False)
    monkeypatch.setattr(server, "DYNAMIC_CFG_F", tmp_path / "dyn.json")
    monkeypatch.setenv("MSRA_AI_CONFIG", str(tmp_path / "ai.json"))
    server.app.config["TESTING"] = True
    return server.app.test_client(), tmp_path


# ── 1. bundle extraction is streamed and capped ──────────────────────────
def test_extract_member_refuses_oversized_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "_MAX_EXTRACT_BYTES", 1024)
    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("base.apk", b"\0" * 100_000)               # tiny on the wire, 100 KB expanded
    with zipfile.ZipFile(z) as zf, pytest.raises(ValueError, match="too large"):
        server._extract_member(zf, "base.apk", tmp_path / "out.apk")
    assert not (tmp_path / "out.apk").exists()
    # unwrap falls back to the original file rather than crashing the scan
    assert server._unwrap_bundle(z, tmp_path) == z


def test_extract_member_streams_a_normal_entry(tmp_path):
    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("base.apk", b"PK-real-apk")
    with zipfile.ZipFile(z) as zf:
        out = server._extract_member(zf, "base.apk", tmp_path / "o.apk")
    assert out.read_bytes() == b"PK-real-apk"


# ── 2. Corellium endpoint cannot be pointed at internal hosts ────────────
@pytest.mark.parametrize("url", ["http://127.0.0.1:5599/x", "http://localhost/", "http://169.254.169.254/",
                                 "http://10.0.0.5/", "ftp://example.com", "", None, 5])
def test_corellium_url_rejects_internal_and_odd_targets(url):
    with pytest.raises(ValueError):
        validate_corellium_url(url)


def test_corellium_private_allowed_only_by_opt_in(monkeypatch):
    monkeypatch.setenv("MSRA_ALLOW_PRIVATE_CORELLIUM", "1")
    assert validate_corellium_url("http://10.0.0.5/") == "http://10.0.0.5"
    with pytest.raises(ValueError):
        validate_corellium_url("file:///etc/passwd")


def test_corellium_client_and_routes_validate_the_url(env):
    c, _ = env
    with pytest.raises(ValueError):
        CorelliumClient("tok", "http://127.0.0.1:1")
    r = c.post("/api/dynamic/corellium-test", json={"url": "http://127.0.0.1:5599/x", "token": "SECRET"})
    assert r.status_code == 400 and "rejected" in r.get_json()["error"]
    r = c.post("/api/dynamic/config", json={"corellium_url": "http://127.0.0.1:1"})
    assert r.status_code == 400


# ── 3. importing server never kills live jobs ────────────────────────────
def test_stale_reset_is_not_run_at_import(env):
    db.upsert_scan("live", status="scanning", package="p")
    import importlib
    importlib.reload(server)                      # a second importer
    assert db.get_scan("live")["status"] == "scanning"
    server._reset_stale_jobs()                    # only the real server does this
    assert db.get_scan("live")["status"] == "error"


# ── 4. one 202 under concurrency, not six ────────────────────────────────
def test_concurrent_ai_triage_starts_claim_a_single_job(tmp_path, monkeypatch):
    fake = FakeLLM()
    monkeypatch.setenv("MSRA_LLM_BASE_URL", fake.url)
    monkeypatch.setenv("MSRA_LLM_TOKEN", "t")
    monkeypatch.setenv("MSRA_AI_CONFIG", str(tmp_path / "ai.json"))
    monkeypatch.setattr(ai_client, "_client", None)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    db.init_db()
    monkeypatch.setattr(server, "REPORTS_FOLDER", tmp_path / "reports")
    sd = tmp_path / "reports" / "scan1"
    sd.mkdir(parents=True)
    (sd / "findings.json").write_text(json.dumps({"package": "p", "findings": [
        {"id": 1, "fid": "r", "title": "t", "severity": "High", "evidence": {"snippet": "x"}}]}))
    db.upsert_scan("scan1", status="done", package="p")
    monkeypatch.setattr(server, "AUTH_TOKEN", "")
    server.app.config["TESTING"] = True
    ai_routes._jobs.clear()
    fake.reply = json.dumps({"verdict": "uncertain", "confidence": 5, "reasoning": "x"})
    codes = []

    def go():
        codes.append(server.app.test_client().post("/api/scans/scan1/ai-triage", json={}).status_code)

    ts = [threading.Thread(target=go) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    try:
        assert sorted(codes).count(202) == 1, codes
        assert codes.count(409) == 5, codes
        assert len([r for r in fake.requests if r[2] and r[0] == "/v1/messages"]) <= 2 * 3   # one job's votes
    finally:
        t0 = time.time()
        while time.time() - t0 < 10 and ai_routes.active_jobs("scan1"):
            time.sleep(0.05)
        fake.close()


# ── 5. budget cap cannot be NaN ──────────────────────────────────────────
@pytest.mark.parametrize("bad", ["nan", "inf", float("nan"), -1, 1e9])
def test_budget_cap_rejects_non_finite_and_out_of_range(bad):
    with pytest.raises(ValueError):
        ai_settings.validate({"budget": {"usd_cap": bad}})
    with pytest.raises(ValueError):
        ai_settings.validate({"research": {"max_usd": bad}})


# ── 6. concurrent rule creation loses nothing ────────────────────────────
def test_concurrent_rule_creation_is_not_lost(tmp_path, monkeypatch):
    import msra.rules_api as ra
    monkeypatch.setattr(ra, "USER_RULES_F", tmp_path / "user_rules.json")
    monkeypatch.setattr(ra, "OVERRIDES_F", tmp_path / "overrides.json")
    monkeypatch.setattr(ra, "_invalidate_cache", lambda: None)
    errs = []

    def mk(i):
        try:
            ra.create_custom_rule({"id": f"r{i}", "title": f"t{i}", "severity": "Low",
                                   "detection_type": "regex", "patterns": [{"pattern": "foo", "file_types": [".java"]}], "category": "Other"})
        except Exception as e:                                           # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=mk, args=(i,)) for i in range(12)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs, errs
    assert len(json.loads((tmp_path / "user_rules.json").read_text())["patterns"]) == 12


# ── 7. deleting a scan with live jobs / orphan rows ──────────────────────
def test_delete_blocked_by_active_dynamic_job_and_late_updates_do_not_resurrect(env):
    c, tmp = env
    (tmp / "reports" / "scanA").mkdir()
    db.upsert_scan("scanA", status="done", package="p")
    db.upsert_job("j1", scan_id="scanA", status="running")
    r = c.delete("/api/scans/scanA")
    assert r.status_code == 409 and "dynamic job" in r.get_json()["error"]
    db.upsert_job("j1", status="done")
    assert c.delete("/api/scans/scanA").status_code == 200
    db.upsert_job("j1", status="running", progress=50)          # a late worker update
    assert db.get_job("j1") is None


def test_triage_on_unknown_scan_is_404_and_bodies_are_validated(env):
    c, tmp = env
    assert c.patch("/api/scans/nosuch/findings/1/triage", json={"status": "Fixed"}).status_code == 404
    (tmp / "reports" / "s1").mkdir()
    db.upsert_scan("s1", status="done", package="p")
    for body in ([], {"status": ["x"]}, {"status": {"a": 1}}, {"status": "Fixed", "suppression_note": {"a": 1}}):
        r = c.patch("/api/scans/s1/findings/1/triage", json=body)
        assert r.status_code == 400, body
    assert c.patch("/api/scans/s1/findings/1/triage", json={"status": "Fixed", "suppression_note": "x"}).status_code == 200


# ── 8. malformed input is a 4xx, never a 500 ─────────────────────────────
def test_bad_inputs_return_4xx(env):
    c, _ = env
    assert c.get("/?scan=../x").status_code == 400
    assert c.get("/?scan=a%00b").status_code == 400
    assert c.patch("/api/rules/nope/toggle").status_code == 404
    assert c.put("/api/rules/nope", json={"patterns": "notalist"}).status_code in (400, 404)
    assert c.post("/api/rules", json={"id": "x1", "title": "t", "patterns": ["bare-string"]}).status_code == 400
    assert c.post("/api/dynamic/config", json=[1, 2]).status_code == 200      # non-dict body is ignored
    for body in ({"mode": {"a": 1}}, {"mode": "nonsense"}, {"adb_serial": "a;rm -rf /"}, {"instance_id": ["x"]}):
        assert c.post("/api/dynamic/config", json=body).status_code == 400, body
    assert c.post("/api/download-poc/s1", json={"files": "notalist"}).status_code == 400


def test_dynamic_config_is_saved_atomically_and_validated(env):
    c, tmp = env
    assert c.post("/api/dynamic/config", json={"mode": "adb", "adb_serial": "127.0.0.1:6555"}).status_code == 200
    cfg = json.loads((tmp / "dyn.json").read_text())
    assert cfg["mode"] == "adb" and cfg["adb_serial"] == "127.0.0.1:6555"
    assert not list(tmp.glob("dyn.json.*.tmp"))
    (tmp / "dyn.json").write_text('{"mode": {"a": 1}}')                      # a previously-corrupted file
    assert server._load_dynamic_cfg()["mode"] == "adb"


def test_unhandled_api_errors_are_json_not_html(env, monkeypatch):
    c, _ = env
    monkeypatch.setattr(server, "_load_summaries", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    server.app.config["TESTING"] = False
    server.app.config["PROPAGATE_EXCEPTIONS"] = False
    r = c.get("/api/dashboard/stats")
    server.app.config["TESTING"] = True
    assert r.status_code == 500 and r.get_json() == {"error": "Internal error"}


# ── 11. snippet endpoint fails closed ────────────────────────────────────
def test_snippet_endpoint_cannot_read_outside_decompiled(env):
    c, tmp = env
    sd = tmp / "reports" / "s2"
    sd.mkdir()
    db.upsert_scan("s2", status="done", package="p")
    (sd / "findings.json").write_text(json.dumps({"package": "p", "findings": [
        {"id": 1, "title": "t", "severity": "High", "evidence": {"file": "/etc/hosts", "line": "12-14"}}]}))
    r = c.get("/api/scans/s2/findings/1/snippet")
    assert r.status_code == 404 and "decompiled" in r.get_json()["error"]          # no decompiled dir: closed
    (sd / "decompiled").mkdir()
    r = c.get("/api/scans/s2/findings/1/snippet")
    assert r.status_code in (403, 404)
    (tmp / "reports" / "s2_x").mkdir()                                              # sibling prefix trick
    (tmp / "reports" / "s2_x" / "f.txt").write_text("secret")
    (sd / "findings.json").write_text(json.dumps({"package": "p", "findings": [
        {"id": 1, "title": "t", "severity": "High",
         "evidence": {"file": str(tmp / "reports" / "s2_x" / "f.txt"), "line": 1}}]}))
    r = c.get("/api/scans/s2/findings/1/snippet")
    assert r.status_code in (403, 404) and b"secret" not in r.data


def test_duplicate_security_headers_removed():
    import re
    assert len(re.findall(r"def _security_headers", Path(server.__file__).read_text())) == 1
