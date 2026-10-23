import json
from pathlib import Path

import pytest

import msra.rules_api as ra
from msra.patterns import PatternManager
from msra.patterns.manager import PatternConfig

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def rules_env(tmp_path, monkeypatch):
    """Throwaway user-rule + override files; built-ins are read from the real data dir."""
    monkeypatch.setattr(ra, "USER_RULES_F", tmp_path / "user_rules.json")
    monkeypatch.setattr(ra, "OVERRIDES_F", tmp_path / "overrides.json")
    monkeypatch.setattr(ra, "_invalidate_cache", lambda: None)
    monkeypatch.setattr(ra, "_rules_cache", None, raising=False)
    monkeypatch.setenv("MSRA_OVERRIDES_FILE", str(tmp_path / "overrides.json"))
    return tmp_path


def builtin_ids(name):
    """Ids of rules that ship ENABLED (a few ship disabled, which would make 'disable' a no-op)."""
    pats = json.loads((ROOT / "data" / "builtin" / name).read_text())["patterns"]
    return [p["id"] for p in pats if p.get("enabled", True)]


RULE = {"title": "T", "severity": "High", "category": "Other",
        "patterns": [{"pattern": "foo\\(", "file_types": [".java"]}]}


# ── id collisions ────────────────────────────────────────────────────────
@pytest.mark.parametrize("fname", ["patterns.json", "ios_patterns.json", "jar_patterns.json", "exe_patterns.json"])
def test_custom_rule_cannot_reuse_any_builtin_id(rules_env, fname):
    with pytest.raises(ValueError, match="already exists"):
        ra.create_custom_rule({**RULE, "id": builtin_ids(fname)[0]})


def test_enabled_false_is_stored_and_listed_disabled(rules_env):
    r = ra.create_custom_rule({**RULE, "id": "mine-1", "enabled": False})
    assert r["enabled"] is False


def test_set_rule_enabled_is_idempotent_and_rejects_unknown(rules_env):
    rid = builtin_ids("patterns.json")[0]
    assert ra.set_rule_enabled(rid, False)["enabled"] is False
    assert ra.set_rule_enabled(rid, False)["enabled"] is False          # not a toggle
    assert json.loads((rules_env / "overrides.json").read_text())["disabled"] == [rid]
    assert ra.set_rule_enabled(rid, True)["enabled"] is True
    assert json.loads((rules_env / "overrides.json").read_text())["disabled"] == []
    with pytest.raises(ValueError, match="Unknown"):
        ra.set_rule_enabled("no-such-rule", False)
    assert "no-such-rule" not in (rules_env / "overrides.json").read_text()


# ── scans now honour overrides and custom rules ──────────────────────────
def _android_enabled(data_dir):
    pm = PatternManager(PatternConfig(data_dir=data_dir, load_community=False, load_crawled=False))
    return {p.id: p.enabled for p in pm.get_patterns(enabled_only=False)}


def test_android_scan_respects_disabled_override(tmp_path):
    data = tmp_path / "data"
    (data / "custom").mkdir(parents=True)
    (data / "builtin").mkdir()
    for f in (ROOT / "data" / "builtin").glob("*.json"):
        (data / "builtin" / f.name).write_text(f.read_text())
    rid = builtin_ids("patterns.json")[0]
    assert _android_enabled(data)[rid] is True
    (data / "custom" / "overrides.json").write_text(json.dumps({"disabled": [rid], "enabled": []}))
    assert _android_enabled(data)[rid] is False


def test_android_scan_loads_custom_rules_but_never_lets_them_shadow_builtins(tmp_path):
    data = tmp_path / "data"
    (data / "custom").mkdir(parents=True)
    (data / "builtin").mkdir()
    for f in (ROOT / "data" / "builtin").glob("*.json"):
        (data / "builtin" / f.name).write_text(f.read_text())
    rid = builtin_ids("patterns.json")[0]
    evil = {"id": rid, "title": "hijacked", "severity": "Info", "enabled": False,
            "detection": {"type": "regex", "patterns": [{"pattern": "x"}]}}
    good = {"id": "mine-1", "title": "Mine", "severity": "High", "category": "Other",
            "detection": {"type": "regex", "patterns": [{"pattern": "foo\\(", "file_types": [".java"]}]}}
    (data / "custom" / "user_rules.json").write_text(json.dumps({"patterns": [evil, good]}))
    pm = PatternManager(PatternConfig(data_dir=data, load_community=False, load_crawled=False))
    got = {p.id: p for p in pm.get_patterns(enabled_only=False)}
    assert "mine-1" in got and got["mine-1"].enabled
    assert got[rid].title != "hijacked" and got[rid].enabled          # built-in untouched


@pytest.mark.parametrize("cls,mod,fname", [
    ("IOSScanner", "msra.ios_scanner", "ios_patterns.json"),
    ("JarScanner", "msra.jar_scanner", "jar_patterns.json"),
    ("ExeScanner", "msra.exe_scanner", "exe_patterns.json"),
])
def test_other_platform_scanners_respect_overrides(rules_env, cls, mod, fname):
    import importlib
    m = importlib.import_module(mod)
    klass = next(v for k, v in vars(m).items() if isinstance(v, type) and k.lower().endswith("scanner")
                 and v.__module__ == mod)
    rid = builtin_ids(fname)[0]
    assert rid in {p["id"] for p in klass().patterns}
    (rules_env / "overrides.json").write_text(json.dumps({"disabled": [rid], "enabled": []}))
    assert rid not in {p["id"] for p in klass().patterns}


# ── feed import cannot hijack or enable anything ─────────────────────────
def test_feed_sync_ignores_ai_chosen_ids_and_enabled_flag(rules_env, monkeypatch):
    import server
    from fake_llm import FakeLLM
    import msra.ai.client as ai_client
    victim = builtin_ids("patterns.json")[0]
    fake = FakeLLM()
    try:
        monkeypatch.setenv("MSRA_LLM_BASE_URL", fake.url)
        monkeypatch.setenv("MSRA_LLM_TOKEN", "t")
        monkeypatch.setenv("MSRA_AI_CONFIG", str(rules_env / "ai.json"))
        monkeypatch.setattr(ai_client, "_client", None)
        monkeypatch.setattr(server, "AUTH_TOKEN", "")
        monkeypatch.setattr(server, "_FEED_META", {"t": {"name": "T", "url": fake.url + "/feed"}})
        fake.reply = json.dumps([
            {"id": victim, "title": "Hijack attempt", "severity": "Info", "enabled": True, "category": "Other",
             "detection_type": "regex", "patterns": [{"pattern": "zzz", "file_types": [".java"]}]},
            {"id": "ai-chosen", "title": "Pushy rule", "severity": "High", "enabled": True, "category": "Other",
             "detection_type": "regex", "patterns": [{"pattern": "foo\\(", "file_types": [".java"]}]},
        ])
        server.app.config["TESTING"] = True
        r = server.app.test_client().post("/api/intel/feed-sync", json={"feed": "t"})
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["imported_disabled"] is True

        rules = {x["id"]: x for x in ra._compute_all_rules()}
        assert rules[victim]["title"] != "Hijack attempt" and rules[victim]["enabled"]      # built-in intact
        assert "ai-chosen" not in rules                                                    # id was not honoured
        ai_rules = [x for x in rules.values() if x["id"].startswith("ai-")]
        assert len(ai_rules) == 2
        assert all(x["enabled"] is False for x in ai_rules)                                 # never active unreviewed
        assert all("needs-review" in x.get("tags", []) for x in ai_rules)
    finally:
        fake.close()
        monkeypatch.setattr(ai_client, "_client", None)
