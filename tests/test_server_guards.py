import pytest

import server


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(server, "AUTH_TOKEN", "")
    monkeypatch.setattr(server, "_LOOPBACK_ONLY", False)
    server.app.config["TESTING"] = True
    return server.app.test_client()


def test_invalid_scan_id_rejected(client):
    r = client.delete("/api/scans/..%2f..")
    assert r.status_code in (400, 404)
    r = client.get("/api/scan/bad id/status")
    assert r.status_code in (400, 404)


def test_delete_never_touches_parent(client):
    # '..' as a literal path component must never reach rmtree
    r = client.delete("/api/scans/..")
    assert r.status_code in (400, 404, 308, 301)
    assert server.REPORTS_FOLDER.exists()


def test_cross_origin_post_blocked(client):
    r = client.post("/api/dynamic/config", json={"mode": "adb"},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    r = client.post("/api/dynamic/config", json={"mode": "adb"},
                    headers={"Origin": "null"})
    assert r.status_code == 403


def test_host_header_enforced_on_loopback(client, monkeypatch):
    monkeypatch.setattr(server, "_LOOPBACK_ONLY", True)
    r = client.get("/api/queue/status", headers={"Host": "evil.example"})
    assert r.status_code == 403
    r = client.get("/api/queue/status", headers={"Host": "localhost:5001"})
    assert r.status_code == 200


def test_auth_token(client, monkeypatch):
    monkeypatch.setattr(server, "AUTH_TOKEN", "s3cret")
    assert client.get("/api/queue/status").status_code == 401
    assert client.get("/api/queue/status",
                      headers={"Authorization": "Bearer s3cret"}).status_code == 200
    assert client.get("/api/queue/status",
                      headers={"X-MSRA-Token": "wrong"}).status_code == 401


def test_dynamic_verify_rejects_bad_scan_id(client):
    r = client.post("/api/dynamic/verify", json={"scan_id": "../x", "finding": {}})
    assert r.status_code == 400


def test_extract_from_url_blocks_internal(client, monkeypatch):
    monkeypatch.setattr(server, "ANTHROPIC_API_KEY", "x")
    r = client.post("/api/intel/extract-from-url",
                    json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 400
    assert "not allowed" in r.get_json()["error"]


def test_security_headers(client):
    r = client.get("/api/queue/status")
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_login_flow_keeps_token_out_of_urls(client, monkeypatch):
    monkeypatch.setattr(server, "AUTH_TOKEN", "s3cret")
    # query-string token is no longer accepted
    assert client.get("/api/queue/status?token=s3cret").status_code == 401
    assert client.post("/login", data={"token": "nope"}).status_code == 401
    r = client.post("/login", data={"token": "s3cret"})
    assert r.status_code == 302
    cookie = r.headers["Set-Cookie"]
    assert "msra_session=" in cookie and "s3cret" not in cookie
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    assert client.get("/api/queue/status").status_code == 200
