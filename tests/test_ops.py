import os
import sqlite3
import time

import pytest

import server
from msra import maintenance as M


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(server, "AUTH_TOKEN", "")
    server.app.config["TESTING"] = True
    return server.app.test_client()


def test_healthz_is_open_even_with_auth_token(monkeypatch):
    monkeypatch.setattr(server, "AUTH_TOKEN", "secret-token")
    c = server.app.test_client()
    assert c.get("/healthz").status_code == 200
    assert c.get("/api/queue/status").status_code == 401          # everything else stays locked
    assert c.get("/healthz").get_json() == {"ok": True}           # and it leaks nothing


def test_healthz_still_checks_host(client):
    assert client.get("/healthz", headers={"Host": "evil.example"}).status_code == 403


def test_security_headers(client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert r.headers["Referrer-Policy"] in ("no-referrer", "same-origin")


def test_queue_status_shape(client):
    j = client.get("/api/queue/status").get_json()
    assert j["scan_pool"]["max_workers"] >= 1 and "queued" in j["dyn_pool"]


def test_env_workers_clamped(monkeypatch):
    monkeypatch.setenv("X_W", "999")
    assert server._env_workers("X_W", 2) == 32
    monkeypatch.setenv("X_W", "0")
    assert server._env_workers("X_W", 2) == 1
    monkeypatch.setenv("X_W", "junk")
    assert server._env_workers("X_W", 2) == 2


def test_db_has_indexes_and_closes_connections(tmp_path, monkeypatch):
    from msra import db
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "t.db")
    db.init_db()
    with sqlite3.connect(str(tmp_path / "t.db")) as c:
        names = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_scans_updated", "idx_jobs_scan"} <= names
    conn = db._conn()
    with conn:
        conn.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")                                    # closed on exit


def _old(p, age):
    t = time.time() - age
    os.utime(p, (t, t))


def test_prune_uploads_respects_ttl_and_active(tmp_path):
    (tmp_path / "aaa_old.apk").write_text("x"); _old(tmp_path / "aaa_old.apk", 7200)
    (tmp_path / "bbb_active.apk").write_text("x"); _old(tmp_path / "bbb_active.apk", 7200)
    (tmp_path / "ccc_new.apk").write_text("x")
    assert M.prune_uploads(tmp_path, 3600, ["bbb"]) == 1
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bbb_active.apk", "ccc_new.apk"]
    assert M.prune_uploads(tmp_path, 0, []) == 0                    # disabled


def test_prune_decompiled_keeps_reports(tmp_path):
    r = tmp_path / "scan1"; (r / "decompiled" / "sources").mkdir(parents=True)
    (r / "findings.json").write_text("[]")
    _old(r / "decompiled", 10 * 86400)
    act = tmp_path / "scan2"; (act / "decompiled").mkdir(parents=True); _old(act / "decompiled", 10 * 86400)
    assert M.prune_decompiled(tmp_path, 86400, ["scan2"]) == 1
    assert not (r / "decompiled").exists() and (r / "findings.json").exists() and (act / "decompiled").exists()


def test_janitor_off_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("MSRA_UPLOAD_TTL_HOURS", raising=False)
    monkeypatch.delenv("MSRA_DECOMPILED_TTL_DAYS", raising=False)
    assert M.start_janitor(tmp_path, tmp_path, lambda: []) is False
