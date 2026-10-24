"""Vetting: disprove pattern false positives with evidence, never demote real ones."""
import pytest

from msra.utils import Evidence, Finding
from msra.vetting import enclosing_method, vet_finding, vet_findings


def mk(title, line_text, line=10, path="/x/decompiled/sources/com/app/A.java", sev="Critical",
       extra=None, ctx=2):
    snippet = "\n".join(f"{n:04d}: {line_text if n == line else '  // pad'}"
                        for n in range(line - ctx, line + ctx + 1))
    return Finding("rule:x", title, sev, "d", "", [], Evidence(path, line, snippet, ""), None,
                   dict(extra or {"category": "OWASP-M4"}))


def status(f, pkg="com.app"):
    vet_findings([f], pkg)
    return f.extra["vetting"]["status"]


def test_ddl_in_oncreate_is_disproved_and_demoted():
    f = mk("SQL Injection in ContentProvider",
           'db.execSQL("CREATE TABLE " + name() + " (a TEXT)");')
    assert status(f) == "likely_fp"
    assert f.severity == "Low" and f.extra["vetting"]["original_severity"] == "Critical"
    assert f.extra["confidence"] == "low"
    assert "schema-setup" in f.extra["false_positive_check"][0]


def test_real_provider_sqli_is_kept(tmp_path):
    src = tmp_path / "decompiled/sources/com/app/P.java"
    src.parent.mkdir(parents=True)
    src.write_text("class P {\n  public Cursor query(Uri uri, String[] projection, String selection) {\n"
                   '    return db.rawQuery("SELECT * FROM t WHERE " + selection, null);\n  }\n}\n')
    f = mk("SQL Injection in ContentProvider",
           'return db.rawQuery("SELECT * FROM t WHERE " + selection, null);', line=3, path=str(src))
    assert status(f) == "needs_review" and f.severity == "Critical"


def test_non_ddl_with_provider_input_in_oncreate_still_kept():
    f = mk("SQL Injection in ContentProvider", 'db.execSQL("DROP TABLE " + uri.getLastPathSegment());')
    assert status(f) == "needs_review"


def test_statement_inside_oncreate_without_provider_input(tmp_path):
    src = tmp_path / "decompiled/sources/com/app/H.java"
    src.parent.mkdir(parents=True)
    src.write_text("class H extends SQLiteOpenHelper {\n  public void onCreate(SQLiteDatabase db) {\n"
                   "    db.execSQL(buildSchema());\n  }\n}\n")
    assert enclosing_method(str(src), 3, {}) == "onCreate"
    f = mk("SQL Injection in ContentProvider", "db.execSQL(buildSchema());", line=3, path=str(src))
    assert status(f) == "likely_fp" and "onCreate" in f.extra["vetting"]["reasons"][0]


def test_local_broadcast_is_not_an_implicit_intent_leak():
    f = mk("Sensitive Data in Implicit Intent", 'LocalBroadcastManager.getInstance(c).sendBroadcast(new Intent("X"));',
           sev="High")
    assert status(f) == "likely_fp" and f.severity == "Low"


def test_real_implicit_broadcast_is_kept():
    f = mk("Sensitive Data in Implicit Intent", 'sendBroadcast(new Intent("com.app.TOKEN").putExtra("t", tok));',
           sev="High")
    assert status(f) == "needs_review" and f.severity == "High"


def test_explicit_intent_is_not_implicit():
    f = mk("Sensitive Data in Implicit Intent", 'Intent i = new Intent("x"); i.setPackage("com.app");', sev="High")
    assert status(f) == "likely_fp"


def test_import_line_evidence_is_disproved():
    f = mk("Exported Activity with WebView URL Parameter", "import atws.activity.web.Gen2WebViewActivity;", sev="High")
    assert status(f) == "likely_fp" and "import" in f.extra["vetting"]["reasons"][0]


def test_class_declaration_without_sink_is_disproved_but_with_loadurl_kept():
    f = mk("Exported Activity with WebView URL Parameter", "public class W extends Activity {", sev="High", ctx=1)
    assert status(f) == "likely_fp"
    g = mk("Exported Activity with WebView URL Parameter", "public class W extends Activity {", sev="High", ctx=0)
    g.evidence.snippet += "\n0011:  web.loadUrl(getIntent().getStringExtra(\"u\"));"
    assert status(g) == "needs_review"


def test_library_code_is_demoted_but_app_package_under_google_is_not():
    lib = mk("Hardcoded thing", "x = 1;", path="/t/decompiled/sources/com/google/android/gms/X.java", sev="High")
    assert status(lib, "com.myapp") == "likely_fp"
    mine = mk("Hardcoded thing", "x = 1;", path="/t/decompiled/sources/com/google/myapp/X.java", sev="High")
    assert status(mine, "com.google.myapp") == "needs_review"


def test_taint_flows_get_positive_status():
    v = mk("Taint flow", "x", sev="High", extra={"data_flow": "call-chain-verified"})
    assert status(v) == "verified" and v.extra["confidence"] == "high"
    i = mk("Taint flow", "x", sev="High", extra={"data_flow": "intra-method"})
    assert status(i) == "likely"
    u = mk("Taint flow", "x", sev="High", extra={"data_flow": "call-chain", "confidence": "low"})
    assert status(u) == "needs_review"


def test_never_removes_and_survives_odd_findings(monkeypatch):
    bare = Finding("r", "No evidence", "High", "d", "", [], None, None)
    weird = Finding("r", "Sql injection", "High", "d", "", [], Evidence("", 0, "", ""), None, {})
    out, counts = vet_findings([bare, weird], "p")
    assert len(out) == 2 and sum(counts.values()) == 2


def test_disabled_by_env(monkeypatch):
    monkeypatch.setenv("MSRA_VETTING", "0")
    f = mk("SQL Injection in ContentProvider", 'db.execSQL("CREATE TABLE a");')
    out, counts = vet_findings([f], "com.app")
    assert counts == {} and f.severity == "Critical" and "vetting" not in (f.extra or {})


def _res(tmp_path, name, line, title="Hardcoded Credentials", fid="storage-hardcoded-credentials:x"):
    f = tmp_path / "decompiled/resources/res/values/strings.xml"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(f"<resources>\n{line}\n</resources>\n")
    return Finding(fid, title, "Critical", "d", "", [],
                   Evidence(str(f), 2, "0002: masked", ""), None, {"category": "x"})


@pytest.mark.parametrize("value", ["Password", "Contraseña", "كلمة المرور", "Platinum/Gold",
                                   "Invalid token {ctx}", "Your account %1$s is ready", "与服务器连接"])
def test_ui_label_strings_are_not_credentials(tmp_path, value):
    f = _res(tmp_path, "PASSWORD", f'    <string name="PASSWORD">{value}</string>')
    assert status(f) == "likely_fp" and "user-facing text" in f.extra["vetting"]["reasons"][0]


@pytest.mark.parametrize("value", ["AIzaSyD4mE9xQ2vPz8Kk3LrT7yWb5Nc1JhGf0aB", "hunter2", "s3cr3t-Tok3n-9f8a7b6c",
                                   "a3f9c1e7d2b84a60b1c2d3e4f5a6b7c8"])
def test_real_looking_secrets_in_resources_are_kept(tmp_path, value):
    f = _res(tmp_path, "api_key", f'    <string name="api_key">{value}</string>',
             title="Hardcoded credential-like value", fid="secret-high-entropy-literal:x")
    assert status(f) == "needs_review"


def test_provider_rule_on_a_receiver_is_disproved_but_unknown_base_is_kept(tmp_path):
    rx = tmp_path / "decompiled/sources/com/app/R.java"
    rx.parent.mkdir(parents=True)
    rx.write_text("public class R extends BroadcastReceiver {\n  void f(){ uri.getLastPathSegment(); }\n}\n")
    f = mk("ContentProvider Path Traversal via URI Decoding", "uri.getLastPathSegment();", line=2, path=str(rx))
    assert status(f) == "likely_fp" and "BroadcastReceiver" in f.extra["vetting"]["reasons"][0]
    pv = tmp_path / "decompiled/sources/com/app/Q.java"
    pv.write_text("public class Q extends AbstractC1234a {\n  void f(){ uri.getLastPathSegment(); }\n}\n")
    g = mk("ContentProvider Path Traversal via URI Decoding", "uri.getLastPathSegment();", line=2, path=str(pv))
    assert status(g) == "needs_review"


def test_cookie_claim_needs_cookie_evidence():
    f = mk("SSO Activity Exposes Session Cookies", 'super("ASsoLoginTelemetryManager");')
    assert status(f) == "likely_fp"
    g = mk("SSO Activity Exposes Session Cookies", "CookieManager.getInstance().getCookie(url);")
    assert status(g) == "needs_review"
