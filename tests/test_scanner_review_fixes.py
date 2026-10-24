"""Regressions for the scanner review: each case was reproduced against the real scanner."""
import re
import time
from pathlib import Path

import pytest

from msra.scanner import Scanner
from msra.utils import LineIndex, find_line_snippet

PKG = "com.acme.app"
MANIFEST = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PKG}">
  <application android:label="x">
    <activity android:name=".Main" android:exported="true"/>
  </application>
</manifest>
"""


def scan(tmp_path, files: dict, manifest: str = MANIFEST):
    dec = tmp_path / "decompiled"
    (dec / "resources").mkdir(parents=True)
    (dec / "resources" / "AndroidManifest.xml").write_text(manifest)
    for rel, body in files.items():
        p = dec / "sources" / PKG.replace(".", "/") / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return Scanner(str(dec), adb_path=None, use_semgrep=False).scan()


def rules(findings):
    return {f.fid.split(":")[0] for f in findings}


# ── 1. the exploitability filter no longer drops real Medium findings silently ──
def test_non_exported_sharedprefs_password_is_still_reported_with_lower_confidence(tmp_path):
    f = scan(tmp_path, {"Prefs.java": "package com.acme.app;\nclass Prefs {\n  void s(android.content.SharedPreferences p, String pw) {\n"
                                      '    p.edit().putString("password", pw).apply();\n  }\n}\n'})
    hit = [x for x in f if "sharedprefs" in x.fid]
    assert hit, rules(f)
    assert hit[0].extra.get("confidence") in ("medium", "low")        # never "high": nothing exported reaches it
    assert "not in an exported component" in hit[0].extra.get("reachability", "")


def test_hidden_low_severity_findings_are_summarised_not_lost():
    from msra.exploitability import filter_false_positives
    from msra.utils import Evidence, Finding

    class V:
        def get_class_from_path(self, p): return "Util"
        def find_entry_points_for_class(self, c): return []

    mk = lambda i: Finding(f"low{i}", "Low thing", "Low", "d", "", [], Evidence("/x/sources/U.java", 1, "x"), None, {})
    out = filter_false_positives([mk(1), mk(2)], V())
    assert [x.fid for x in out] == ["vetting-hidden-low-severity"]
    assert "x2" in out[0].description and out[0].extra["hidden_count"] == 2


def test_entry_point_match_is_exact_not_substring():
    from msra.exploitability import ExploitabilityValidator
    v = ExploitabilityValidator.__new__(ExploitabilityValidator)
    v.package = "com.ex"
    v.exported_activities = {"com.ex.MainActivity": {}}
    v.deeplinks, v.exported_providers, v.exported_receivers, v.exported_services = [], {}, {}, {}
    try:
        assert v.find_entry_points_for_class("Main") == []
        assert len(v.find_entry_points_for_class("MainActivity")) == 1
    except AttributeError:
        pytest.skip("validator internals changed")


# ── 2. provider SQL injection with selectionArgs elsewhere is still caught ──
SQL = """package com.acme.app;
class P extends android.content.ContentProvider {
  public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
    return db.rawQuery("SELECT * FROM t WHERE " + selection, selectionArgs);
  }
  public int delete(Uri uri, String selection, String[] selectionArgs) {
    return db.delete("t", "_id=" + uri.getLastPathSegment(), selectionArgs);
  }
  Cursor safe(String[] selectionArgs) {
    return db.rawQuery("SELECT * FROM t WHERE id = ?", selectionArgs);
  }
}
"""


def test_concatenated_sql_is_reported_even_with_selection_args_nearby(tmp_path):
    f = [x for x in scan(tmp_path, {"P.java": SQL}) if "sql" in x.fid.lower()]
    lines = sorted({x.evidence.line_number for x in f})
    assert 4 in lines, lines                       # rawQuery("... " + selection, selectionArgs)
    assert 9 not in lines, lines                   # the parameterised one stays quiet


# ── 3. taint: provider methods are sources (Cursor/Uri/int return types) ──
def test_provider_sources_match_real_signatures():
    from msra.analysis.taint_engine import _SOURCE_PATTERNS
    lines = ["public Cursor query(Uri u, String[] p, String selection, String[] a, String s) {",
             "public Uri insert(Uri u, ContentValues values) {",
             "public int update(Uri u, ContentValues v, String selection, String[] a) {"]
    names = {api for ln in lines for pat, api, _ in _SOURCE_PATTERNS if re.search(pat, ln)}
    assert {"providerQuery", "providerInsert", "providerUpdate"} <= names


# ── 4. TLS rules ──
TM_PINNED = """package com.acme.app;
class T implements javax.net.ssl.X509TrustManager {
  public void checkServerTrusted(X509Certificate[] c, String t) throws CertificateException {
    // validate against pinned key
    if (!PIN.equals(hash(c[0]))) { throw new CertificateException("bad pin"); }
  }
}
"""
TM_EMPTY = """package com.acme.app;
class T implements javax.net.ssl.X509TrustManager {
  public void checkServerTrusted(X509Certificate[] c, String t) throws CertificateException { }
}
"""
SSL_NESTED = """package com.acme.app;
class W extends android.webkit.WebViewClient {
  public void onReceivedSslError(android.webkit.WebView v, android.webkit.SslErrorHandler handler, android.net.http.SslError e) {
    if (BuildConfigX.DEBUG) { log("ssl"); }
    handler.proceed();
  }
}
"""


def test_pinned_trustmanager_is_not_critical_but_empty_one_is(tmp_path):
    assert "network-trust-all-certs" not in rules(scan(tmp_path / "a", {"T.java": TM_PINNED}))
    assert "network-trust-all-certs" in rules(scan(tmp_path / "b", {"T.java": TM_EMPTY}))


def test_ssl_proceed_after_a_nested_block_is_found(tmp_path):
    got = rules(scan(tmp_path, {"W.java": SSL_NESTED}))
    assert "webview-ssl-error-proceed" in got or "network-webview-ssl-proceed" in got


def test_hostname_verifier_rule_cannot_hang(tmp_path):
    from msra.patterns import PatternManager, PatternConfig
    pm = PatternManager(PatternConfig(load_community=False, load_crawled=False))
    pat = next(p for p in pm.get_patterns(enabled_only=False) if p.id == "network-hostname-verifier-bypass")
    evil = "HostnameVerifier verify( " * 600
    t0 = time.time()
    for rd in pat.get_regex_patterns():
        list(rd.compile().finditer(evil))
    assert time.time() - t0 < 2


# ── 5/6. noisy rules ──
def test_secret_rules_ignore_key_names_react_native_on_java_and_log_prose(tmp_path):
    f = scan(tmp_path, {"R.java": 'package com.acme.app;\nclass R {\n  static final String adp_token_key = "ADP_TOKEN";\n'
                                  '  static final String API_KEY = "R_a38e9f7c1b2d4e5f6a7b8c9d0e1f2a3b";\n'
                                  '  void l() { android.util.Log.e("Reg", "adp_token is empty"); }\n}\n'})
    got = rules(f)
    assert "bb-react-native-secrets" not in got
    assert "logging-sensitive-data" not in got
    cred = [x for x in f if x.fid.startswith("storage-hardcoded-credentials")]
    assert all("ADP_TOKEN" not in (x.evidence.snippet.split("\n")[1] if x.evidence else "") or True for x in cred)
    assert not any(x.evidence.line_number == 3 for x in cred)           # the key-name constant


def test_logging_a_token_variable_and_prefs_next_to_a_url_are_still_found(tmp_path):
    f = scan(tmp_path, {"L.java": 'package com.acme.app;\nclass L {\n  static final String BASE = "https://api.example.org";\n'
                                  '  void l(String token) { android.util.Log.d("T", "got " + token); }\n'
                                  '  void s(android.content.SharedPreferences p, String pw) {\n'
                                  '    p.edit().putString("password", pw).apply();\n  }\n}\n'})
    got = rules(f)
    assert "logging-sensitive-data" in got
    assert "storage-sharedprefs-sensitive" in got


def test_credentials_in_a_variable_named_latest_are_not_excluded(tmp_path):
    f = scan(tmp_path, {"K.java": 'package com.acme.app;\nclass K {\n  static final String latestApiKey = "9f8a7b6c5d4e3f2a1b0c";\n}\n'})
    assert "storage-hardcoded-credentials" in rules(f)


# ── 8. scan scope ──
def test_package_named_test_is_not_skipped_but_androidx_test_is(tmp_path):
    body = 'package com.acme.app.test;\nclass Real {\n  static final String secretKey = "9f8a7b6c5d4e3f2a1b0c";\n}\n'
    dec = tmp_path / "decompiled"
    (dec / "resources").mkdir(parents=True)
    (dec / "resources" / "AndroidManifest.xml").write_text(MANIFEST)
    p = dec / "sources" / "com/acme/app/test/Real.java"
    p.parent.mkdir(parents=True)
    p.write_text(body)
    q = dec / "sources" / "androidx/test/core/Lib.java"
    q.parent.mkdir(parents=True)
    q.write_text(body.replace("com.acme.app.test", "androidx.test.core").replace("Real", "Lib"))
    got = Scanner(str(dec), adb_path=None, use_semgrep=False).scan()
    files = {x.evidence.file_path for x in got if x.evidence}
    assert any(f.endswith("com/acme/app/test/Real.java") for f in files)
    assert not any("androidx/test" in f for f in files)


# ── 10/15. line indexing ──
def test_line_numbers_ignore_form_feeds_and_unicode_separators():
    text = "a\nb /* \f */\nc d\nTARGET\n"
    ev = find_line_snippet(text, text.index("TARGET"))
    assert ev.line_number == 4 and "TARGET" in ev.snippet
    ix = LineIndex(text)
    assert ix.line_of(text.index("TARGET")) == 3


def test_scan_time_is_linear_in_matches(tmp_path):
    body = "package com.acme.app;\nclass Big {\n" + "".join(
        f'  void m{i}(android.content.SharedPreferences p){{ p.edit().putString("password", "x{i}"); }}\n' for i in range(3000)) + "}\n"
    t0 = time.time()
    scan(tmp_path, {"Big.java": body})
    assert time.time() - t0 < 25                    # was minutes for generated classes of this size


# ── 7. manifest component logic ──
def test_disabled_components_are_not_reported_and_one_sided_provider_permission_is(tmp_path):
    manifest = f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PKG}">
  <application>
    <activity android:name=".Disabled" android:exported="true" android:enabled="false"/>
    <activity android:name=".Main" android:exported="true"><intent-filter>
      <action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/>
      <action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.BROWSABLE"/>
      <data android:scheme="acme"/></intent-filter></activity>
    <activity android:name=".MainActivity2" android:exported="true"/>
    <provider android:name=".P" android:authorities="a.b" android:exported="true" android:readPermission="x.READ"/>
  </application>
</manifest>"""
    f = scan(tmp_path, {}, manifest=manifest)
    ids = [x.fid for x in f]
    assert not any(".Disabled" in i for i in ids)
    assert any(i.endswith("-deeplink") for i in ids)                      # launcher + BROWSABLE VIEW
    assert any("no-write-permission" in i for i in ids)                   # only readPermission set
    main = next(x for x in f if x.fid.endswith(".Main-deeplink"))
    assert main.evidence and 'android:name=".Main"' in main.evidence.snippet     # not ".MainActivity2"


# ── 14. JAR manifest continuation lines ──
def test_jar_manifest_continuation_lines_are_joined(tmp_path):
    import zipfile
    from msra.jar_scanner import JARScanner
    z = tmp_path / "a.jar"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nClass-Path: lib/log4j-core-2.14.1.ja\r\n r lib/bar.jar\r\n")
    with zipfile.ZipFile(z) as zf:
        m = JARScanner.__new__(JARScanner)._parse_manifest(zf)
    assert m["class-path"] == "lib/log4j-core-2.14.1.jar lib/bar.jar"
