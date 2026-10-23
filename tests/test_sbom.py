import pytest

import server
from msra.analysis import sbom as S


@pytest.fixture()
def tree(tmp_path):
    m = tmp_path / "resources" / "META-INF"
    (m / "maven" / "com.squareup.okhttp3" / "okhttp").mkdir(parents=True)
    (m / "maven" / "com.squareup.okhttp3" / "okhttp" / "pom.properties").write_text(
        "#x\ngroupId=com.squareup.okhttp3\nartifactId=okhttp\nversion=3.8.0\n")
    (m / "androidx.core_core.version").write_text("1.9.0\n")
    (m / "evil_..%2f.version").write_text("../../etc\n")
    (m / "maven" / "x").mkdir()
    (m / "maven" / "x" / "pom.properties").write_text("groupId=a b\nartifactId=c\nversion=1; rm -rf\n")
    return tmp_path


def test_collects_valid_components_only(tree):
    names = {(c.name, c.version) for c in S.collect_components(str(tree))}
    assert names == {("com.squareup.okhttp3:okhttp", "3.8.0"), ("androidx.core:core", "1.9.0")}


def test_cyclonedx_shape(tree):
    doc = S.to_cyclonedx(S.collect_components(str(tree)), "app")
    assert doc["bomFormat"] == "CycloneDX" and len(doc["components"]) == 2
    assert doc["components"][0]["purl"].startswith("pkg:maven/")


def fake_osv(url, body=None):
    if url == S.OSV_BATCH:
        assert all(set(q) == {"package", "version"} for q in body["queries"])   # coordinates only
        return {"results": [{"vulns": [{"id": "GHSA-aaaa-bbbb-cccc"}]} if q["package"]["name"].endswith("okhttp") else {}
                            for q in body["queries"]]}
    return {"id": "GHSA-aaaa-bbbb-cccc", "summary": "bad cert check", "aliases": ["CVE-2021-0341"],
            "database_specific": {"severity": "HIGH"}}


def test_lookup_and_findings(tree):
    v = S.lookup_vulns(S.collect_components(str(tree)), fetch=fake_osv)
    fs = S.vuln_findings(v)
    assert len(fs) == 1 and fs[0].severity == "High" and "CVE-2021-0341" in fs[0].description


def test_offline_lookup_degrades_to_empty(tree):
    import urllib.error
    def boom(*a, **k): raise urllib.error.URLError("offline")
    assert S.lookup_vulns(S.collect_components(str(tree)), fetch=boom) == {}


def test_http_helper_refuses_other_hosts():
    with pytest.raises(ValueError):
        S._http_json("https://evil.example/x")


def test_lookup_is_opt_in(tree, monkeypatch):
    calls = []
    monkeypatch.setattr(S, "lookup_vulns", lambda c, **k: calls.append(1) or {})
    monkeypatch.delenv("MSRA_OSV_LOOKUP", raising=False)
    fs = S.scan_sbom(str(tree))
    assert [f.fid for f in fs] == ["sbom-inventory"] and not calls
    monkeypatch.setenv("MSRA_OSV_LOOKUP", "1")
    S.scan_sbom(str(tree))
    assert calls


def test_sbom_endpoint(tree, monkeypatch, tmp_path):
    monkeypatch.setattr(server, "REPORTS_FOLDER", tmp_path / "rep")
    import shutil
    d = tmp_path / "rep" / "abc123" / "decompiled"
    d.parent.mkdir(parents=True)
    shutil.copytree(tree / "resources", d / "resources")
    monkeypatch.setattr(server, "AUTH_TOKEN", "")
    r = server.app.test_client().get("/api/scans/abc123/sbom.json")
    assert r.status_code == 200 and r.get_json()["components"]
    assert server.app.test_client().get("/api/scans/nope/sbom.json").status_code == 404
