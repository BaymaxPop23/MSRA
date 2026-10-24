from pathlib import Path

from msra.analysis.taint_engine import TaintEngine

MAIN = """package com.t;
import android.app.Activity;
import android.os.Bundle;

public class Main extends Activity {
    private Helper helper = new Helper();

    protected void onCreate(Bundle b) {
        String u = getIntent().getStringExtra("url");
        helper.load(u);
    }
}
"""

HELPER = """package com.t;
import android.webkit.WebView;

public class Helper {
    WebView web;
    public void load(String target) {
        web.loadUrl(target);
    }
}
"""

LOCAL = """package com.t;
import android.app.Activity;
import android.os.Bundle;
import android.database.sqlite.SQLiteDatabase;

public class Local extends Activity {
    SQLiteDatabase db;

    protected void onCreate(Bundle b) {
        String q = getIntent().getStringExtra("q");
        String where = "name = '" + q + "'";
        db.rawQuery("select * from t where " + where, null);
    }
}
"""

UNQUAL = """package com.t;
import android.app.Activity;
import android.os.Bundle;
import android.database.sqlite.SQLiteDatabase;

public class Unqual extends Activity {
    SQLiteDatabase db;

    protected void onCreate(Bundle b) {
        String v = getIntent().getStringExtra("v");
        run(v);
    }

    private void run(String s) {
        db.execSQL(s);
    }
}
"""

UNRELATED = """package com.t;
import android.app.Activity;
import android.os.Bundle;
import android.database.sqlite.SQLiteDatabase;

public class Unrelated extends Activity {
    SQLiteDatabase db;

    protected void onCreate(Bundle b) {
        String ignored = getIntent().getStringExtra("x");
        String fixed = "select 1";
        db.rawQuery(fixed, null);
    }
}
"""

SAFE = """package com.t;
import android.app.Activity;
import android.os.Bundle;
import android.database.sqlite.SQLiteDatabase;

public class Safe extends Activity {
    SQLiteDatabase db;

    protected void onCreate(Bundle b) {
        String q = getIntent().getStringExtra("q");
        db.rawQuery("select * from t where name = ?", new String[]{q}, selectionArgs);
    }
}
"""

MANIFEST = {
    "_package": "com.t",
    "activities": [{"name": "com.t.%s" % n, "exported": True}
                   for n in ("Main", "Local", "Unqual", "Unrelated", "Safe")],
}


def _flows(tmp_path: Path):
    src = tmp_path / "sources" / "com" / "t"
    src.mkdir(parents=True, exist_ok=True)
    for name, text in (("Main", MAIN), ("Helper", HELPER), ("Local", LOCAL),
                       ("Unqual", UNQUAL), ("Unrelated", UNRELATED), ("Safe", SAFE)):
        (src / f"{name}.java").write_text(text)
    return TaintEngine(str(tmp_path), MANIFEST).analyze()


def _by_comp(flows, comp):
    return [f for f in flows if f.source.component_class == f"com.t.{comp}"]


def test_typed_field_call_resolves_across_classes(tmp_path):
    flows = _by_comp(_flows(tmp_path), "Main")
    assert flows, "Main -> helper.load -> loadUrl should be found"
    f = flows[0]
    assert f.sink.sink_type == "webview"
    assert f.hop_path[-1] == "com.t.Helper.load"
    assert f.data_flow == "call-chain-verified"     # u -> arg 0 -> param 'target' -> loadUrl(target)
    assert f.severity == "Critical"


def test_same_method_flow_verified_through_assignments(tmp_path):
    flows = _by_comp(_flows(tmp_path), "Local")
    assert flows and flows[0].data_flow == "intra-method"
    assert flows[0].severity == "Critical"


def test_unqualified_intra_class_call(tmp_path):
    flows = _by_comp(_flows(tmp_path), "Unqual")
    assert flows, "onCreate -> run() -> execSQL should be found"
    assert flows[0].hop_path[-1] == "com.t.Unqual.run"


def test_source_not_reaching_sink_is_not_verified(tmp_path):
    flows = _by_comp(_flows(tmp_path), "Unrelated")
    assert flows and all(f.data_flow == "unverified-same-method" for f in flows)
    assert all(f.severity == "Medium" for f in flows)


def test_sql_sanitizer_is_type_specific(tmp_path):
    flows = _by_comp(_flows(tmp_path), "Safe")
    assert flows and all(f.is_sanitized for f in flows)
    # ...but weak checks are no longer treated as sanitizers
    flows_local = _by_comp(_flows(tmp_path), "Local")
    assert flows_local and not flows_local[0].is_sanitized


def test_hostile_input_does_not_blow_up(tmp_path):
    import time
    src = tmp_path / "sources" / "com" / "t"
    src.mkdir(parents=True)
    (src / "Evil.java").write_text(
        "package com.t;\npublic class Evil {\n"
        + "A<" * 20000 + "\n"
        + "void f() {" + "x " * 50000 + "\n}\n}\n")
    t0 = time.time()
    TaintEngine(str(tmp_path), {"_package": "com.t"}).analyze()
    assert time.time() - t0 < 5


HOP_SRC = """package com.t;
import android.app.Activity;
import android.os.Bundle;

public class Hop extends Activity {
    Mid mid = new Mid();
    protected void onCreate(Bundle b) {
        String evil = getIntent().getStringExtra("e");
        mid.go("const", evil, "const2");
    }
}
"""
MID = """package com.t;
public class Mid {
    Leaf leaf = new Leaf();
    public void go(String a, String b, String c) {
        String x = b + "/x";
        leaf.run(a, x);
    }
}
"""
LEAF = """package com.t;
import android.webkit.WebView;
public class Leaf {
    WebView web;
    public void run(String safe, String url) {
        web.loadUrl(url);
    }
}
"""
CONST_SRC = HOP_SRC.replace("Hop", "Const").replace('mid.go("const", evil, "const2")', 'mid.go(evil, "const", "const2")')


def _hop_flows(tmp_path, hop_src, name):
    src = tmp_path / "sources" / "com" / "t"
    src.mkdir(parents=True)
    (src / f"{name}.java").write_text(hop_src)
    (src / "Mid.java").write_text(MID)
    (src / "Leaf.java").write_text(LEAF)
    m = {"_package": "com.t", "activities": [{"name": f"com.t.{name}", "exported": True}]}
    return [f for f in TaintEngine(str(tmp_path), m).analyze() if f.sink.sink_type == "webview"]


def test_two_hop_argument_mapping_verified(tmp_path):
    fl = _hop_flows(tmp_path, HOP_SRC, "Hop")
    assert fl and fl[0].data_flow == "call-chain-verified" and len(fl[0].hop_path) == 3


def test_tainted_arg_in_wrong_position_is_not_verified(tmp_path):
    # evil lands in Mid.go's param 'a', which is passed to Leaf's UNUSED 'safe' param
    fl = _hop_flows(tmp_path, CONST_SRC, "Const")
    assert fl and fl[0].data_flow == "call-chain"
    assert fl[0].severity != "Critical"


def test_method_extraction_handles_jadx_style_constructors_and_comments(tmp_path):
    src = '''package com.t;
public final /* synthetic */ class R implements Runnable {
    public /* synthetic */ R(String a, int b) {
        this.a = a;
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (x) { y(); }
    }
}
'''
    e = TaintEngine(str(tmp_path), {})
    got = {n: ln for n, _b, ln in e._extract_methods(src, src.splitlines(), "com.t.R", "R.java")}
    assert {"R", "run"} <= set(got)
    assert got["R"] == 3 and got["run"] == 8          # line numbers point at the declaration
    assert e._method_params[("com.t.R", "R")] == ["a", "b"]


def test_activity_component_type_is_not_mangled(tmp_path):
    """'activities'.rstrip('s') used to give 'activitie', so Activity PoCs were never built."""
    flows = _by_comp(_flows(tmp_path), "Local")
    assert flows and flows[0].source.component_type == "activity"
    assert "Activitie " not in flows[0].title and "Activity" in flows[0].title
    assert flows[0].poc_command.startswith("adb shell am start ")


# ── review fixes: method attribution, de-duplication, append/+= propagation ──
def _one(tmp_path, name, body, activity=True):
    src = tmp_path / "sources" / "com" / "t"
    src.mkdir(parents=True, exist_ok=True)
    (src / f"{name}.java").write_text(body)
    m = {"_package": "com.t", "activities": [{"name": f"com.t.{name}", "exported": activity}]}
    return TaintEngine(str(tmp_path), m).analyze()


def test_methods_by_line_does_not_leak_into_field_initializers():
    from msra.analysis.taint_engine import _methods_by_line
    src = ["public class A {",
           "    void first() {",
           "        run();",
           "    }",
           "    static class Inner {",
           '        static final File F = new File(base(), "x");',
           "        void second() { go(); }",
           "    }",
           "}"]
    m = _methods_by_line(src)
    assert m[2] == "first"
    assert m[5] == "unknown"                    # field initializer: not attributed to first()
    assert m[6] == "second"


def test_two_distinct_sinks_in_one_method_are_two_flows(tmp_path):
    body = """package com.t;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
public class Two extends Activity {
    WebView a; WebView b;
    protected void onCreate(Bundle s) {
        String u = getIntent().getStringExtra("u");
        a.loadUrl(u);
        b.loadUrl(u);
    }
}
"""
    flows = [f for f in _one(tmp_path, "Two", body) if f.sink.sink_type == "webview"]
    assert sorted(f.sink.line_number for f in flows) == [9, 10]


def test_stringbuilder_append_and_plus_equals_propagate_taint(tmp_path):
    body = """package com.t;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.WebView;
public class Sb extends Activity {
    WebView w;
    protected void onCreate(Bundle s) {
        String u = getIntent().getStringExtra("u");
        StringBuilder sb = new StringBuilder("https://");
        sb.append(u);
        String url = "https://x/";
        url += u;
        w.loadUrl(sb.toString());
        w.loadUrl(url);
    }
}
"""
    flows = [f for f in _one(tmp_path, "Sb", body) if f.sink.sink_type == "webview"]
    assert {f.sink.line_number for f in flows} == {13, 14}
    assert all(f.data_flow == "intra-method" for f in flows), [f.data_flow for f in flows]


def test_unproven_flows_are_capped_but_proven_ones_keep_their_severity(tmp_path):
    from msra.analysis.taint_engine import to_finding
    flows = [f for f in _flows(tmp_path)]
    assert flows
    for fl in flows:
        f = to_finding(fl)
        order = ("Info", "Low", "Medium", "High", "Critical")
        if fl.data_flow in ("intra-method", "call-chain-verified"):
            assert f.severity == fl.severity
        elif fl.data_flow == "unverified-same-method":
            assert f.severity == "Info" and f.extra.get("original_severity") in (None, fl.severity)
        elif fl.data_flow == "call-chain" and fl.sink.sink_type not in ("sql", "webview", "exec"):
            assert order.index(f.severity) <= order.index("Low")


def test_method_attribution_is_fast_on_hostile_lines():
    import time
    from msra.analysis.taint_engine import _methods_by_line
    lines = ["a " * 50000 + "(", "public " + "x<" * 3000 + " f(" + "(" * 3000, "void m(" + "a," * 20000 + ") {", "}"]
    t0 = time.time()
    out = _methods_by_line(lines * 5)
    assert len(out) == 20 and time.time() - t0 < 3
