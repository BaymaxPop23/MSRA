"""Keep the test suite away from the developer's real data (rules, configs, scan database).

These must be set before `server` / `msra.db` / `msra.rules_api` are imported, so they live at
module level. Individual tests may still override them with monkeypatch."""
import atexit
import os
import shutil
import tempfile

_tmp = tempfile.mkdtemp(prefix="msra_tests_")
atexit.register(shutil.rmtree, _tmp, ignore_errors=True)
os.environ.setdefault("MSRA_CUSTOM_DIR", os.path.join(_tmp, "custom"))
os.environ.setdefault("MSRA_DB_PATH", os.path.join(_tmp, "msra.db"))
os.environ.setdefault("MSRA_AI_CONFIG", os.path.join(_tmp, "ai_config.json"))
os.environ.setdefault("MSRA_DYNAMIC_CONFIG", os.path.join(_tmp, "dynamic_config.json"))
# (MSRA_OVERRIDES_FILE is intentionally not set: pattern tests pass their own data_dir; it is read-only)
