import pytest

from msra import security as sec


@pytest.mark.parametrize("sid", ["abc123", "a-b_c", "0" * 12, "atws.app", "com.example.app", "insecureshop_dynamic"])
def test_valid_scan_ids(sid):
    assert sec.is_valid_scan_id(sid)


@pytest.mark.parametrize("sid", ["", ".", "..", "../x", "a/b", "a b", "x" * 65, None, 5,
                                 ".hidden", "a..b", "a.", "a/../b", "a\\b", "a%2fb", "..%2f"])
def test_invalid_scan_ids(sid):
    assert not sec.is_valid_scan_id(sid)


@pytest.mark.parametrize("pkg", ["com.example.app", "a.b", "app"])
def test_valid_packages(pkg):
    assert sec.is_valid_package(pkg)


@pytest.mark.parametrize("pkg", ["", "com.x; rm -rf /", "com.x'y", "1abc.def", "a..b", "$(id)"])
def test_invalid_packages(pkg):
    assert not sec.is_valid_package(pkg)


def test_safe_join_blocks_escape(tmp_path):
    assert sec.safe_join(tmp_path, "ok") == (tmp_path / "ok").resolve()
    with pytest.raises(ValueError):
        sec.safe_join(tmp_path, "..")
    with pytest.raises(ValueError):
        sec.safe_join(tmp_path, "../../etc")


def test_safe_filename():
    assert sec.safe_filename("../../etc/passwd") == "passwd"
    assert sec.safe_filename("a b(1).apk") == "a_b_1_.apk"
    assert sec.safe_filename("") == "file"
    cleaned = sec.safe_filename('x"\r\ny')
    assert not any(c in cleaned for c in '"\r\n')


def test_csv_safe():
    assert sec.csv_safe("=cmd()") == "'=cmd()"
    assert sec.csv_safe("@x") == "'@x"
    assert sec.csv_safe("plain") == "plain"
    assert sec.csv_safe(None) == ""


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://example.com/x", "http://127.0.0.1/",
    "http://localhost:8080/", "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/", "http://[::1]/", "http://0.0.0.0/", "gopher://x",
])
def test_ssrf_blocked(url):
    with pytest.raises(sec.UnsafeURLError):
        sec.check_public_url(url)


def test_rule_validation(tmp_path):
    from msra import rules_api as ra
    ok = {"severity": "high", "patterns": [{"pattern": r"foo\(\w+\)"}]}
    ra._validate_patterns(ok)
    assert ok["severity"] == "High"          # normalised
    for bad in (
        {"severity": "<script>"},
        {"id": "../x"},
        {"patterns": [{"pattern": "(a+)+$"}]},
        {"patterns": [{"pattern": "("}]},
        {"patterns": [{"pattern": "x" * 3000}]},
        {"patterns": [{"pattern": "a"}] * 60},
    ):
        with pytest.raises(ValueError):
            ra._validate_patterns(dict(bad))


def test_device_shell_args_are_quoted():
    """Payloads reach the provider verbatim but cannot break out of the shell."""
    from msra.dynamic.device.adb_device import ADBDevice

    sent = []

    class Probe(ADBDevice):
        def __init__(self):            # no real device
            pass

        def _shell(self, cmd, *a, **k):
            sent.append(cmd)
            return True, ""

    d = Probe()
    d.query_content_provider("content://a/x;reboot", ["id;id", "b"], "1' OR '1'='1; reboot")
    d.start_activity("com.a", "Main;reboot", extras={"k;id": "v'; reboot #"}, data_uri="x';reboot")
    joined = "\n".join(sent)
    assert "--where '1'\"'\"' OR '\"'\"'1'\"'\"'='\"'\"'1; reboot'" in joined
    assert "'content://a/x;reboot'" in joined and "'id;id:b'" in joined
    assert "'com.a/Main;reboot'" in joined and "'k;id'" in joined


def test_existing_scan_directories_are_addressable():
    """Regression: legacy scans named after the package (atws.app) must keep working."""
    import os
    reports = os.path.join(os.path.dirname(__file__), "..", "reports")
    if not os.path.isdir(reports):
        pytest.skip("no reports dir")
    for d in os.listdir(reports):
        if os.path.isdir(os.path.join(reports, d)):
            assert sec.is_valid_scan_id(d), f"existing scan '{d}' would be rejected"
