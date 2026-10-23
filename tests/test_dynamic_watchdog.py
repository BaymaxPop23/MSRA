import time

import pytest

import server
from msra.dynamic import adb_util


def test_run_adb_raises_after_deadline():
    adb_util.set_deadline(0.01)
    try:
        time.sleep(0.05)
        with pytest.raises(adb_util.JobDeadline):
            adb_util.run_adb(["devices"])
        with pytest.raises(adb_util.JobDeadline):
            adb_util.sleep(1)
    finally:
        adb_util.clear_deadline()


def test_sleep_is_clamped_to_deadline():
    adb_util.set_deadline(0.2)
    try:
        t0 = time.monotonic()
        try:
            adb_util.sleep(30)
        except adb_util.JobDeadline:
            pass
        assert time.monotonic() - t0 < 2
    finally:
        adb_util.clear_deadline()


def test_deadline_not_swallowed_by_except_exception():
    adb_util.set_deadline(0.01)
    time.sleep(0.03)
    try:
        with pytest.raises(adb_util.JobDeadline):
            try:
                adb_util.run_adb(["devices"])
            except Exception:       # the pattern used all over the probe code
                pass
    finally:
        adb_util.clear_deadline()


def test_worker_marks_stuck_job_as_timed_out(monkeypatch):
    updates = []
    monkeypatch.setattr(server, "_update_job", lambda job_id, **kw: updates.append(kw))
    monkeypatch.setattr(server, "_dynamic_device_cleanup", lambda cfg, finding: None)

    def stuck(*a, **k):
        while True:                 # a probe loop that never finishes on its own
            server._run_adb(["devices"], timeout=1)
            adb_util.sleep(0.05)

    monkeypatch.setattr(server, "_dynamic_verify_pipeline", stuck)
    monkeypatch.setattr(server, "_job_budget", lambda cfg: 1)   # bypass the 60s floor
    t0 = time.monotonic()
    server._dynamic_verify_worker("job1", "scan1", 0, {"package": "com.a"},
                                  {"job_timeout": 1, "adb_serial": "test-serial"}, False)
    assert time.monotonic() - t0 < 6
    assert updates and updates[-1]["status"] == "error"
    assert "Timed out" in updates[-1]["message"]
    assert adb_util._ctx.deadline is None      # cleared so cleanup can run


def test_jobs_on_same_device_are_serialised():
    a = server._device_lock("devX")
    assert a is server._device_lock("devX")
    assert a is not server._device_lock("devY")


def test_restore_steps_still_run_after_deadline():
    """Regression: the verifier re-enable in a finally must not be skippable."""
    calls = []
    adb_util.set_deadline(0.01)
    try:
        time.sleep(0.05)
        with pytest.raises(adb_util.JobDeadline):
            adb_util.run_adb(["devices"])
        with adb_util.no_deadline():
            calls.append(adb_util.run_adb(["devices"], timeout=1))     # must not raise
        with pytest.raises(adb_util.JobDeadline):                      # deadline restored
            adb_util.run_adb(["devices"])
    finally:
        adb_util.clear_deadline()
    assert calls


def test_job_budget_is_clamped(monkeypatch):
    assert server._job_budget({"job_timeout": 1}) == 60
    assert server._job_budget({"job_timeout": 10**9}) == 3600
    assert server._job_budget({"job_timeout": "junk"}) == 900
    assert server._job_budget({}) == 900
