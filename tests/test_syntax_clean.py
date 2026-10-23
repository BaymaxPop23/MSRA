import warnings
from pathlib import Path


def test_server_py_has_no_invalid_escapes():
    src = (Path(__file__).parents[1] / "server.py").read_text()
    with warnings.catch_warnings():
        warnings.simplefilter("error")          # invalid escapes become errors in future Pythons
        compile(src, "server.py", "exec")
