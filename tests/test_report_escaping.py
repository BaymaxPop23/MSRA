from msra.report import generate_html_report
from msra.utils import Evidence, Finding


def test_hostile_values_do_not_break_out(tmp_path):
    f = Finding(
        fid="x", title="<img src=x onerror=alert(1)>", severity="High\"onmouseover=\"x",
        description="d", attack_path="a", adb_commands=[],
        evidence=Evidence(file_path="a.java", line_number=1, snippet="s"),
        references=["javascript:alert(1)"],
        extra={"confidence": '"><script>alert(2)</script>', "code_class": "'><b>"},
    )
    out = tmp_path / "r.html"
    generate_html_report([f], str(out),
                         {"package": "a';alert(3);//", "title": "t"}, {})
    full = out.read_text()
    # The reportData block is type=application/json (inert); it just must not
    # be closable early by "</script>" inside the data.
    import re
    m = re.search(r'<script type="application/json" id="reportData">(.*?)</script>', full, re.S)
    assert m, "reportData block missing"
    assert "</" not in m.group(1)
    html_out = full.replace(m.group(0), "")
    assert "<script>alert(2)</script>" not in html_out
    # The package name only reaches executable JS via a sanitised string literal
    assert "a.download = 'a';alert" not in html_out
    assert 'a.download = "a__alert_3____"+' in html_out
    assert 'href="javascript:' not in html_out
    assert "<img src=x onerror" not in html_out
