from pathlib import Path

from msra.scanner import Scanner

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg}">
  <application android:label="x">
    <activity android:name=".Main" android:exported="true"/>
  </application>
</manifest>
"""

VULN = """package {pkg};
import android.webkit.WebView;
public class Main extends android.app.Activity {{
    void f(WebView w) {{
        w.getSettings().setJavaScriptEnabled(true);
        w.addJavascriptInterface(new Object(), "bridge");
        w.loadUrl(getIntent().getStringExtra("url"));
    }}
}}
"""


def _tree(root: Path, pkg: str):
    dec = root / "decompiled"
    (dec / "resources").mkdir(parents=True)
    (dec / "resources" / "AndroidManifest.xml").write_text(MANIFEST.format(pkg=pkg))
    src = dec / "sources" / pkg.replace(".", "/")
    src.mkdir(parents=True)
    (src / "Main.java").write_text(VULN.format(pkg=pkg))
    return dec


def test_scanner_defaults_adb_path(tmp_path):
    dec = _tree(tmp_path, "com.acme.app")
    sc = Scanner(str(dec), adb_path=None, use_semgrep=False)
    assert sc.adb_path == "adb"


def test_workspace_named_test_is_not_skipped(tmp_path):
    # The absolute path contains /test/ - must not cause every file to be skipped
    ws = tmp_path / "test" / "run1"
    ws.mkdir(parents=True)
    dec = _tree(ws, "com.acme.app")
    sc = Scanner(str(dec), adb_path=None, use_semgrep=False)
    findings = sc.scan()
    assert sc.scan_stats["app_files"] >= 1
    assert any("Main.java" in (f.evidence.file_path if f.evidence else "") for f in findings)


def test_app_under_library_namespace_is_still_scanned(tmp_path):
    dec = _tree(tmp_path, "com.github.someapp")
    sc = Scanner(str(dec), adb_path=None, use_semgrep=False)
    findings = sc.scan()
    assert sc.scan_stats.get("library_files", 0) == 0
    assert any("Main.java" in (f.evidence.file_path if f.evidence else "") for f in findings)


def test_android_scanner_does_not_load_other_platform_rules():
    from msra.patterns import PatternManager
    ids = {p.id for p in PatternManager().get_patterns(enabled_only=False)}
    assert not any(i.startswith(("ios-", "jar-", "exe-", "pe-")) for i in ids)
