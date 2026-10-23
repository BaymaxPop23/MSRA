from msra.analysis.deep import run_deep_analysis


def test_empty_tree_never_raises(tmp_path):
    extra, flows = run_deep_analysis(str(tmp_path), {}, "com.x")
    assert extra == [] and flows == []


def test_bad_manifest_data_is_contained(tmp_path):
    extra, flows = run_deep_analysis(str(tmp_path / "missing"), {"components": "garbage"}, "com.x")
    assert isinstance(extra, list) and isinstance(flows, list)
