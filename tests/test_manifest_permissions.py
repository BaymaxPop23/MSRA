import json
from pathlib import Path

import pytest

from msra.scanner import Scanner

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>
  <uses-permission android:name="android.permission.CAMERA"/>
  <application android:label="x">
    <service android:name=".A11y" android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE" android:exported="false"/>
  </application>
</manifest>"""


@pytest.fixture()
def decompiled(tmp_path, monkeypatch):
    monkeypatch.setenv("MSRA_OVERRIDES_FILE", str(tmp_path / "ov.json"))
    res = tmp_path / "dec" / "resources"
    res.mkdir(parents=True)
    (res / "AndroidManifest.xml").write_text(MANIFEST)
    (tmp_path / "dec" / "sources").mkdir()
    return tmp_path / "dec"


def fids(decompiled):
    return {f.fid for f in Scanner(str(decompiled), adb_path="adb").scan()}


def test_permission_rules_fire(decompiled):
    ids = fids(decompiled)
    assert "permission-system-alert-window" in ids
    assert "permission-bind-accessibility" in ids
    assert "permission-install-packages" not in ids and "permission-device-admin" not in ids


def test_hub_toggle_disables_permission_rule(decompiled, tmp_path):
    (tmp_path / "ov.json").write_text(json.dumps({"disabled": ["permission-system-alert-window"], "enabled": []}))
    ids = fids(decompiled)
    assert "permission-system-alert-window" not in ids and "permission-bind-accessibility" in ids


def test_every_manifest_json_rule_has_a_native_check():
    """A `manifest` rule in patterns.json that nothing evaluates is silently dead."""
    data = json.loads((Path(__file__).parents[1] / "data/builtin/patterns.json").read_text())
    pats = data["patterns"] if isinstance(data, dict) else data
    native = set(Scanner._PERMISSION_RULES) | {
        "logging-debuggable-build", "storage-backup-enabled", "permission-dangerous-unused",
        "component-broadcast-receiver-exported", "component-service-exported",
        "component-provider-exported", "component-activity-exported"}   # covered by dedicated scanner logic
    ids = {p["id"] for p in pats if p.get("detection", {}).get("type") == "manifest"}
    assert ids <= native, f"manifest rules with no evaluator: {ids - native}"
