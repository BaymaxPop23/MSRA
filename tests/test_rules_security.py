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


# ── validation cannot be bypassed via detection type ─────────────────────
EVIL = "(a+)+$"


@pytest.mark.parametrize("det_type", ["ast", "foo", "binary_string", "REGEX", "", None])
def test_unknown_detection_types_rejected(rules_env, det_type):
    with pytest.raises(ValueError):
        ra.create_custom_rule({**RULE, "id": "x1", "detection_type": det_type,
                               "patterns": [{"pattern": EVIL}]})


@pytest.mark.parametrize("det_type", ["regex", "regex-multiline", "combined", "manifest"])
def test_unsafe_regex_rejected_for_every_allowed_type(rules_env, det_type):
    with pytest.raises(ValueError, match="backtracking|ReDoS"):
        ra.create_custom_rule({**RULE, "id": "x2", "detection_type": det_type,
                               "patterns": [{"pattern": EVIL}]})


def test_update_cannot_smuggle_unsafe_regex_by_changing_type(rules_env):
    ra.create_custom_rule({**RULE, "id": "ok-1"})
    for bad in ({"detection_type": "ast", "patterns": [{"pattern": EVIL}]},
                {"detection_type": "manifest", "patterns": [{"pattern": EVIL}]},
                {"patterns": [{"pattern": EVIL}]},
                {"detection_type": "nope"}):
        with pytest.raises(ValueError):
            ra.update_custom_rule("ok-1", dict(bad))
    assert ra.update_custom_rule("ok-1", {"title": "renamed"})["title"] == "renamed"


# ── loader-side defence in depth + review gating ─────────────────────────
def _scan_env(tmp_path, user_rules, overrides=None):
    data = tmp_path / "data"
    (data / "custom").mkdir(parents=True)
    (data / "builtin").mkdir()
    for f in (ROOT / "data" / "builtin").glob("*.json"):
        (data / "builtin" / f.name).write_text(f.read_text())
    (data / "custom" / "user_rules.json").write_text(json.dumps({"patterns": user_rules}))
    if overrides:
        (data / "custom" / "overrides.json").write_text(json.dumps(overrides))
    pm = PatternManager(PatternConfig(data_dir=data, load_community=False, load_crawled=False))
    return {p.id: p for p in pm.get_patterns(enabled_only=False)}


def _rule(rid, pattern="foo\\(", det="regex", tags=None, **kw):
    return {"id": rid, "title": rid, "severity": "High", "category": "Other", "tags": tags or [],
            "detection": {"type": det, "patterns": [{"pattern": pattern, "file_types": [".java"]}]}, **kw}


def test_hand_edited_user_file_cannot_load_unsafe_or_untyped_rules(tmp_path):
    got = _scan_env(tmp_path, [_rule("redos", EVIL), _rule("untyped", EVIL, det="ast"),
                               _rule("long", "a" * 5000), _rule("fine")])
    assert "fine" in got and got["fine"].enabled
    assert "redos" not in got and "untyped" not in got and "long" not in got


def test_crawled_and_ai_rules_stay_disabled_until_analyst_enables(tmp_path):
    rules = [_rule("c1", tags=["crawled"]), _rule("a1", tags=["ai-extracted"]),
             _rule("n1", tags=["needs-review"]), _rule("mine", tags=["custom"]),
             _rule("c2", tags=["crawled"], enabled=True)]
    got = _scan_env(tmp_path, rules)
    assert [got[i].enabled for i in ("c1", "a1", "n1", "c2")] == [False] * 4
    assert got["mine"].enabled is True
    got = _scan_env(tmp_path / "again", rules, overrides={"disabled": [], "enabled": ["c1"]})
    assert got["c1"].enabled is True and got["a1"].enabled is False       # explicit enable only


def test_hub_listing_and_enabling_agree_with_the_scanner(rules_env):
    ra.create_custom_rule({**RULE, "id": "crawled-x", "tags": ["crawled"]})
    listed = next(r for r in ra._compute_all_rules() if r["id"] == "crawled-x")
    assert listed["enabled"] is False                                   # Hub shows it off by default
    ra.set_rule_enabled("crawled-x", True)
    assert json.loads((rules_env / "overrides.json").read_text())["enabled"] == ["crawled-x"]
    assert next(r for r in ra._compute_all_rules() if r["id"] == "crawled-x")["enabled"] is True


# ── crawler import: same policy as AI feed import ────────────────────────
def test_crawler_sync_cannot_overwrite_or_activate_rules(rules_env, monkeypatch, tmp_path):
    import types
    import server
    victim_id = builtin_ids("patterns.json")[0]
    mine = ra.create_custom_rule({**RULE, "id": "my-own-rule", "title": "My Own Rule",
                                  "patterns": [{"pattern": "mine\\(", "file_types": [".java"]}]})
    crawled = tmp_path / "data" / "data" / "crawled" / "blog"
    crawled.mkdir(parents=True)

    def put(name, **d):
        (crawled / name).write_text(json.dumps(d))

    pat = {"detection": {"patterns": [{"pattern": "evil\\(", "file_types": [".java"]}]}}
    put("1.json", id=victim_id, title="Overwrite builtin by id", severity="Info", **pat)          # id collision
    put("2.json", id="my-own-rule", title="Overwrite mine by id", **pat)                          # overwrite custom by id
    put("3.json", id="zzz", title="My Own Rule", **pat)                                           # overwrite custom by title
    put("4.json", id="fresh", title="Brand new crawled rule", **pat)                              # legit new rule
    put("5.json", id="redos", title="Redos rule",
        detection={"patterns": [{"pattern": EVIL}]})                                              # unsafe regex

    class StubUpdater:
        def __init__(self, config=None):
            pass

        def update(self, force=False, quiet=True):
            return types.SimpleNamespace(source_stats={}, patterns_found=0, patterns_approved=0)

    import msra.crawler.updater as up
    monkeypatch.setattr(up, "ThreatIntelUpdater", StubUpdater)
    monkeypatch.setattr(server, "__file__", str(tmp_path / "server.py"))
    monkeypatch.setattr(server, "AUTH_TOKEN", "")
    server.app.config["TESTING"] = True
    r = server.app.test_client().post("/api/intel/sources-sync", json={})
    assert r.status_code == 200, r.get_data(as_text=True)[:300]

    rules = {x["id"]: x for x in ra._compute_all_rules()}
    assert rules[victim_id]["title"] != "Overwrite builtin by id" and rules[victim_id]["enabled"]
    assert [p["pattern"] for p in rules["my-own-rule"]["patterns"]] == ["mine\\("]               # untouched
    crawled_rules = [x for x in rules.values() if x["id"].startswith("crawled-")]
    # The file-supplied ids are ignored: attempts become harmless NEW rules under server ids
    titles = sorted(x["title"] for x in crawled_rules)
    assert titles == ["Brand new crawled rule", "Overwrite builtin by id", "Overwrite mine by id"]
    assert all(x["enabled"] is False for x in crawled_rules)                  # nothing active unreviewed
    assert all({"crawled", "needs-review"} <= set(x["tags"]) for x in crawled_rules)
    assert "fresh" not in rules and "redos" not in rules and "zzz" not in rules   # ids not honoured, ReDoS rejected
    assert sum(1 for x in rules.values() if x["title"] == "My Own Rule") == 1    # title collision skipped


# ── structural ReDoS detection (security review: shape regex was bypassable) ──
from msra.patterns import safety  # noqa: E402

DANGEROUS = [
    "(a+)+$", "(a*)*$", "(a+)*$", "(.*)*x",
    "((a+)b)+$",                     # nested group hid the inner quantifier from the old check
    "((a+)+)$", "(?:(?:a+)+)+$", "((((a+)))+)$", "(?:x(?:y+z?)+)+q",
    "(a|aa)+$", "(a|a)+$", "(a|ab)+c", "(?:a|a?)+$",      # overlapping alternation under a repeat
    "(.|a)+$",
    "(.*a){12}$", "(\\w+,){10}", "(a+){5}",                # nested repeat with a large bounded outer
]
SAFE = [
    r"foo\(\w+\)", r"(?:http|ftp)://", r"(\d+\.){3}\d+", r"(?:a|b)+", r"[a-z]+@[a-z]+",
    r'(?i)password\s*=\s*"[^"]+"', r"(?:get|set)Item\(", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    r"rawQuery\s*\([^)]{0,300}\+[^)]{0,300}selection", r"(?:foo|bar|baz)\s*=", r"[^)]{0,1500}x",
    # Python's parser merges single-character alternations into one set, so these are
    # linear (measured 0.000s on 40+ chars) and must NOT be flagged as false positives:
    r"(\w|\d)+$", r"(?:[a-c]|[b-d])*$",
]


@pytest.mark.parametrize("pat", DANGEROUS)
def test_structural_check_rejects_dangerous_regexes(pat):
    assert safety.regex_problem(pat), pat


@pytest.mark.parametrize("pat", SAFE)
def test_structural_check_accepts_normal_regexes(pat):
    assert safety.regex_problem(pat) is None, pat


def test_bypasses_are_rejected_through_the_rule_api(rules_env):
    for i, pat in enumerate(["((a+)b)+$", "(a|aa)+$", "(.*a){12}$"]):
        with pytest.raises(ValueError):
            ra.create_custom_rule({**RULE, "id": f"bp-{i}", "patterns": [{"pattern": pat}]})


def test_pathological_inputs_to_the_checker_itself_are_safe():
    assert safety.regex_problem("(" * 500 + "a" + ")" * 500) is not None or True   # must not crash/hang
    assert "too long" in safety.regex_problem("a" * 3000)
    assert "invalid" in safety.regex_problem("(")


def test_every_shipped_pattern_satisfies_the_policy():
    """Keeps data/builtin and the safety policy in agreement (and the check honest)."""
    offenders = []
    for f in sorted((ROOT / "data" / "builtin").glob("*.json")):
        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k in ("pattern", "regex") and isinstance(v, str):
                        yield v
                    else:
                        yield from walk(v)
            elif isinstance(o, list):
                for v in o:
                    yield from walk(v)
        offenders += [(f.name, p[:60]) for p in walk(json.loads(f.read_text())) if safety.regex_problem(p)]
    assert not offenders, offenders
