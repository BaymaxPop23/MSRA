import os

from msra.analysis.hybrid import detect, scan_hybrid, _HERMES_MAGIC

AWS = "AKIAIOSFODNN7EXAMPLE"


def tree(tmp_path):
    res = tmp_path / "resources"
    (res / "assets").mkdir(parents=True)
    (res / "lib" / "arm64-v8a").mkdir(parents=True)
    return res


def test_react_native_plain_bundle_secret_found_and_masked(tmp_path):
    res = tree(tmp_path)
    (res / "assets" / "index.android.bundle").write_text(
        'var a=1;var cfg={aws:"%s",x:2};function f(){return 1}' % AWS)
    fs = scan_hybrid(str(tmp_path))
    ids = {f.fid.split(":")[0] for f in fs}
    assert "hybrid-framework-react-native" in ids
    secrets = [f for f in fs if f.extra.get("framework") == "react-native" and f.evidence]
    assert secrets, "secret in RN bundle not found"
    assert all(AWS not in (f.evidence.snippet or "") for f in secrets)    # masked


def test_hermes_bytecode_strings_extracted(tmp_path):
    res = tree(tmp_path)
    (res / "assets" / "index.android.bundle").write_bytes(
        _HERMES_MAGIC + b"\x00\x01\x02" + AWS.encode() + b"\x00\xff\xfe")
    fs = scan_hybrid(str(tmp_path))
    assert any(f.extra.get("framework") == "react-native" and f.evidence for f in fs)


def test_flutter_libapp_strings(tmp_path):
    res = tree(tmp_path)
    (res / "lib" / "arm64-v8a" / "libapp.so").write_bytes(b"\x7fELF\x00\x00" + AWS.encode() + b"\x00\x00")
    (res / "lib" / "arm64-v8a" / "libflutter.so").write_bytes(b"\x7fELF")
    fs = scan_hybrid(str(tmp_path))
    assert any(f.fid == "hybrid-framework-flutter" for f in fs)
    assert any(f.extra.get("framework") == "flutter" and f.evidence for f in fs)


def test_plain_native_app_reports_nothing(tmp_path):
    tree(tmp_path)
    assert detect(str(tmp_path)) == {} and scan_hybrid(str(tmp_path)) == []


def test_huge_single_line_bundle_is_fast(tmp_path):
    import time
    res = tree(tmp_path)
    (res / "assets" / "index.android.bundle").write_text("a=" + "x" * 3_000_000 + ";")
    t = time.monotonic()
    scan_hybrid(str(tmp_path))
    assert time.monotonic() - t < 15
