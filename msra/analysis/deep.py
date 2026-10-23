"""Taint + ICC analysis shared by the web scan pipeline and the CLI."""
from __future__ import annotations

import logging
from typing import Any, List, Tuple

_log = logging.getLogger(__name__)

_ICC_REFS = [
    "https://developer.android.com/topic/security/risks/intent-injection",
    "https://owasp.org/www-project-mobile-top-10/",
]


def _icc_to_finding(chain):
    from msra.utils import Evidence, Finding
    return Finding(
        fid=f"ICC_{chain.sink.sink_type.upper()}_{chain.entry_point.split('.')[-1].upper()}",
        title=(f"ICC taint chain: exported {chain.entry_point.split('.')[-1]} -> "
               f"{chain.icc_target.split('.')[-1]} -> {chain.sink.sink_api}"),
        severity=chain.severity,
        description=(
            f"An exported component forwards untrusted Intent extras to an internal "
            f"component via ICC. Key '{chain.extra_key}' reaches {chain.sink.sink_api} "
            f"({chain.sink.sink_type}) in {chain.icc_target}."),
        attack_path=(f"Exported: {chain.entry_point}\n-> ICC ({chain.extra_key!r})\n"
                     f"-> Internal: {chain.icc_target}\n-> Sink: {chain.sink.sink_api}"),
        adb_commands=chain.poc_commands,
        evidence=Evidence(file_path=chain.sink.file_path, line_number=chain.sink.line_number,
                          snippet=chain.sink.code_snippet, matched_text=chain.sink.sink_api),
        references=list(_ICC_REFS),
        extra={"icc_chain": True, "extra_key": chain.extra_key},
    )


def run_deep_analysis(decompiled_dir: str, manifest_data: dict, package: str) -> Tuple[List[Any], list]:
    """Return (extra_findings, taint_flows). Never raises: analysis failures are logged."""
    extra: List[Any] = []
    flows: list = []
    manifest = dict(manifest_data or {})
    manifest.setdefault("_package", package)
    try:
        from msra.analysis.taint_engine import TaintEngine, to_finding
        flows = TaintEngine(str(decompiled_dir), manifest).analyze()
        extra.extend(to_finding(f) for f in flows)
    except Exception as exc:
        _log.warning("Taint engine failed (non-fatal): %s", exc)
        flows = []
    try:
        from msra.analysis.icc_graph import ICCGraph
        chains = ICCGraph(str(decompiled_dir), manifest).build().get_exploitable_chains(flows)
        extra.extend(_icc_to_finding(c) for c in chains)
    except Exception as exc:
        _log.debug("ICC graph failed (non-fatal): %s", exc)
    return extra, flows
