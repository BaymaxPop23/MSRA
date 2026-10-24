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


def helper_file(tmp_path, body, base="SQLiteOpenHelper", method="onCreate", name="H.java"):
    src = tmp_path / "decompiled/sources/com/app" / name
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(f"public class {name[:-5]} extends {base} {{\n  public void {method}(SQLiteDatabase db) {{\n"
                   f"{body}\n  }}\n}}\n")
    return str(src)


def test_ddl_in_oncreate_is_disproved_and_demoted(tmp_path):
    stmt = '    db.execSQL("CREATE TABLE " + name() + " (a TEXT)");'
    f = mk("SQL Injection in ContentProvider", stmt.strip(), line=3, path=helper_file(tmp_path, stmt))
    assert status(f) == "likely_fp"
    assert f.severity == "Low" and f.extra["vetting"]["original_severity"] == "Critical"
    assert f.extra["confidence"] == "low"
    assert "SQLiteOpenHelper" in f.extra["false_positive_check"][0]


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
    f = mk("Sensitive Data in Implicit Intent", 'new Intent("x").setPackage("com.app").putExtra("t", tok);', sev="High")
    assert status(f) == "likely_fp"


# ── adversarial: the scanned app controls the code these heuristics read ──
def test_ddl_outside_a_sqliteopenhelper_is_kept(tmp_path):
    stmt = '    db.execSQL("CREATE TABLE " + name());'
    p = helper_file(tmp_path, stmt, base="ContentProvider", method="onCreate", name="P.java")
    f = mk("SQL Injection in ContentProvider", stmt.strip(), line=3, path=p)
    assert status(f) == "needs_review" and f.severity == "Critical"
    q = helper_file(tmp_path, stmt, base="SomethingElse", method="onCreate", name="Q.java")
    assert status(mk("SQL Injection in ContentProvider", stmt.strip(), line=3, path=q)) == "needs_review"


def test_schema_helper_that_also_mentions_a_provider_is_kept(tmp_path):
    stmt = '    db.execSQL("CREATE TABLE " + name());  // ContentProvider'
    p = helper_file(tmp_path, stmt)
    assert status(mk("SQL Injection in ContentProvider", stmt.strip(), line=3, path=p)) == "needs_review"


def test_localbroadcast_mention_elsewhere_in_the_line_does_not_suppress():
    for line in ('sendBroadcast(new Intent("a").putExtra("t", tok)); // LocalBroadcastManager',
                 'String s = "LocalBroadcastManager"; sendBroadcast(new Intent("a").putExtra("t", tok));',
                 'ctx.sendBroadcast(i); Object o = LocalBroadcastManager.class;'):
        f = mk("Sensitive Data in Implicit Intent", line, sev="High")
        assert status(f) == "needs_review" and f.severity == "High", line


def test_setpackage_on_a_different_intent_does_not_suppress():
    f = mk("Sensitive Data in Implicit Intent",
           'other.setPackage("x"); sendBroadcast(new Intent("a").putExtra("t", tok));', sev="High")
    assert status(f) == "needs_review"


def test_star_prefixed_continuation_line_is_not_a_comment():
    f = mk("Exported Activity with WebView URL Parameter", "* web.loadUrl(u);", sev="High")
    assert status(f) == "needs_review"


def test_inner_class_cannot_launder_a_provider_finding(tmp_path):
    p = tmp_path / "decompiled/sources/com/app/M.java"
    p.parent.mkdir(parents=True)
    p.write_text("public class M extends AbstractC1a {\n  void f(){ uri.getLastPathSegment(); }\n"
                 "  static class R extends BroadcastReceiver {}\n}\n")
    f = mk("ContentProvider Path Traversal via URI Decoding", "uri.getLastPathSegment();", line=2, path=str(p))
    assert status(f) == "needs_review"


def test_severity_cap_can_be_turned_off(tmp_path, monkeypatch):
    monkeypatch.setenv("MSRA_VETTING_CAP", "0")
    f = mk("Sensitive Data in Implicit Intent", 'LocalBroadcastManager.getInstance(c).sendBroadcast(new Intent("X"));',
           sev="High")
    assert status(f) == "likely_fp" and f.severity == "High"
    assert f.extra["vetting"]["original_severity"] == "High"


def test_import_line_evidence_is_disproved():
    f = mk("Exported Activity with WebView URL Parameter", "import atws.activity.web.Gen2WebViewActivity;", sev="High")
    assert status(f) == "likely_fp" and "import" in f.extra["vetting"]["reasons"][0]


def test_class_declaration_without_sink_is_disproved_but_with_loadurl_kept():
    f = mk("Exported Activity with WebView URL Parameter", "public class W extends Activity {", sev="High", ctx=1)
    assert status(f) == "likely_fp"
    g = mk("Exported Activity with WebView URL Parameter", "public class W extends Activity {", sev="High", ctx=0)
    g.evidence.snippet += "\n0011:  web.loadUrl(getIntent().getStringExtra(\"u\"));"
    assert status(g) == "needs_review"


def test_library_namespace_lowers_confidence_but_never_demotes():
    lib = mk("Hardcoded thing", "x = 1;", path="/t/decompiled/sources/com/google/android/gms/X.java", sev="High")
    assert status(lib, "com.myapp") == "needs_review"          # a package name is not proof
    assert lib.severity == "High" and lib.extra["confidence"] == "low"
    assert "not proof" in lib.extra["vetting"]["reasons"][-1]
    mine = mk("Hardcoded thing", "x = 1;", path="/t/decompiled/sources/com/google/myapp/X.java", sev="High")
    assert status(mine, "com.google.myapp") == "needs_review"
    assert mine.extra.get("confidence") != "low"


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


def _res(tmp_path, name, line, title="Hardcoded Credentials", fid="storage-hardcoded-credentials:x",
         translated=None):
    f = tmp_path / "decompiled/resources/res/values/strings.xml"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(f"<resources>\n{line}\n</resources>\n")
    if translated:                                    # the same string name in another locale
        g = tmp_path / "decompiled/resources/res/values-de/strings.xml"
        g.parent.mkdir(parents=True, exist_ok=True)
        g.write_text(f'<resources>\n    <string name="{name}">{translated}</string>\n</resources>\n')
    return Finding(fid, title, "Critical", "d", "", [],
                   Evidence(str(f), 2, "0002: masked", ""), None, {"category": "x"})


@pytest.mark.parametrize("value", ["Contraseña", "كلمة المرور",
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


# ── structure-aware checks (brace depth, statements, method span) ─────────
def test_enclosing_class_uses_brace_depth_not_nearest_declaration():
    from msra.vetting import enclosing_class
    src = ["public class M extends AbstractC1a {",
           "  static class R extends BroadcastReceiver { void g(){ } }",
           "  void f(){ uri.getLastPathSegment(); }",
           "}"]
    assert enclosing_class(src, 3) == ("M", "AbstractC1a")            # R closed before line 3
    assert enclosing_class(src, 2)[0] == "M"                           # R opens and closes on line 2
    assert enclosing_class(["class M extends X {", "  class R extends Service {", "    int a;"], 3) == ("R", "Service")
    assert enclosing_class(["class A {", "  }", "}", "}"], 4) is None   # inconsistent braces: fail closed
    tricky = ['class A extends Service {', '  String s = "} class B extends Activity {";', '  void f(){}', '}']
    assert enclosing_class(tricky, 3) == ("A", "Service")              # braces in strings are ignored


def test_closed_receiver_before_the_line_cannot_launder_a_provider_finding(tmp_path):
    p = tmp_path / "decompiled/sources/com/app/M.java"
    p.parent.mkdir(parents=True)
    p.write_text("public class M extends AbstractC1a {\n  static class R extends BroadcastReceiver { }\n"
                 "  void f(){ uri.getLastPathSegment(); }\n}\n")
    f = mk("ContentProvider Path Traversal via URI Decoding", "uri.getLastPathSegment();", line=3, path=str(p))
    assert status(f) == "needs_review"


def test_one_unsafe_send_among_several_statements_keeps_the_finding():
    safe = 'LocalBroadcastManager.getInstance(c).sendBroadcast(new Intent("X"));'
    f = mk("Sensitive Data in Implicit Intent", safe + ' sendBroadcast(new Intent("a").putExtra("t", tok));', sev="High")
    assert status(f) == "needs_review" and f.severity == "High"
    g = mk("Sensitive Data in Implicit Intent", safe + ' log("ok");', sev="High")
    assert status(g) == "likely_fp"
    h = mk("Sensitive Data in Implicit Intent", safe + " " + safe, sev="High")
    assert status(h) == "likely_fp"


def test_schema_check_uses_the_class_that_encloses_the_line(tmp_path):
    p = tmp_path / "decompiled/sources/com/app/D.java"
    p.parent.mkdir(parents=True)
    # a helper class exists in the file, but the flagged line sits in a different (non-helper) class
    p.write_text("class Helper extends SQLiteOpenHelper { void onCreate(SQLiteDatabase d){ } }\n"
                 "class Other extends Base {\n  void onCreate(SQLiteDatabase db) {\n"
                 '    db.execSQL("CREATE TABLE " + name());\n  }\n}\n')
    f = mk("SQL Injection in ContentProvider", 'db.execSQL("CREATE TABLE " + name());', line=4, path=str(p))
    assert status(f) == "needs_review"


def test_provider_input_held_in_a_variable_keeps_the_sql_finding(tmp_path):
    p = tmp_path / "decompiled/sources/com/app/E.java"
    p.parent.mkdir(parents=True)
    p.write_text("public class E extends SQLiteOpenHelper {\n"
                 "  void drop(SQLiteDatabase db, Uri uri) {\n    String t = uri.getLastPathSegment();\n"
                 '    db.execSQL("DROP TABLE " + t);\n  }\n}\n')
    f = mk("SQL Injection in ContentProvider", 'db.execSQL("DROP TABLE " + t);', line=4, path=str(p))
    assert status(f) == "needs_review" and f.severity == "Critical"
    q = tmp_path / "decompiled/sources/com/app/F.java"
    q.write_text("public class F extends SQLiteOpenHelper {\n  static void b(SQLiteDatabase db, Kind k) {\n"
                 '    db.execSQL("CREATE TABLE IF NOT EXISTS " + k.tableName() + " (a TEXT)");\n  }\n}\n')
    g = mk("SQL Injection in ContentProvider", 'db.execSQL("CREATE TABLE IF NOT EXISTS " + k.tableName() + " (a TEXT)");',
           line=3, path=str(q))
    assert status(g) == "likely_fp"


def test_single_word_label_needs_a_translation_as_proof_when_the_name_is_credential_like(tmp_path):
    line = '    <string name="PASSWORD">Password</string>'
    assert status(_res(tmp_path, "PASSWORD", line)) == "needs_review"            # no proof it is a label
    assert status(_res(tmp_path, "PASSWORD", line, translated="Passwort")) == "likely_fp"


def test_credential_named_dictionary_word_is_kept_even_if_capitalised(tmp_path):
    for value in ("Administrator", "Welcome"):
        line = f'    <string name="admin_password">{value}</string>'
        assert status(_res(tmp_path, "admin_password", line)) == "needs_review"
    # a non-secret name + plain word is still treated as a label
    assert status(_res(tmp_path, "tier_name", '    <string name="tier_name">Gold</string>')) == "likely_fp"


def test_platinum_gold_label_is_proven_by_its_translation(tmp_path):
    line = '    <string name="IB_TOKEN_PROTOCOL_NAME_5">Platinum/Gold</string>'
    assert status(_res(tmp_path, "IB_TOKEN_PROTOCOL_NAME_5", line, title="Hardcoded credential-like value",
                       fid="secret-high-entropy-literal:x")) == "needs_review"
    assert status(_res(tmp_path, "IB_TOKEN_PROTOCOL_NAME_5", line, title="Hardcoded credential-like value",
                       fid="secret-high-entropy-literal:x", translated="Platinum/goud")) == "likely_fp"
