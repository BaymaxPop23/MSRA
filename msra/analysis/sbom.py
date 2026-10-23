"""Software bill of materials + optional known-vulnerability lookup.

Inventory is offline: Maven coordinates are read from the metadata that Gradle/Maven leave
inside the APK (META-INF/maven/*/*/pom.properties and META-INF/<group>_<artifact>.version).
The CVE lookup is opt-in (MSRA_OSV_LOOKUP=1) and sends ONLY public package coordinates
(group:artifact + version) to api.osv.dev - never app code, names, or paths.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional

from ..utils import Evidence, Finding

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
_MAX_COMPONENTS = 1500
_MAX_VULN_DETAILS = 60
_VER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$")
_PART = re.compile(r"^[A-Za-z0-9_.\-]{1,120}$")


@dataclass(frozen=True)
class Component:
    group: str
    artifact: str
    version: str
    source: str = ""

    @property
    def name(self) -> str:
        return f"{self.group}:{self.artifact}"

    @property
    def purl(self) -> str:
        return f"pkg:maven/{self.group}/{self.artifact}@{self.version}"


def _valid(group: str, artifact: str, version: str) -> bool:
    return bool(_PART.match(group) and _PART.match(artifact) and _VER.match(version))


def _props(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh.read(8192).splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def collect_components(decompiled_dir: str) -> List[Component]:
    roots = [os.path.join(decompiled_dir, "resources"), decompiled_dir]
    seen: Dict[tuple, Component] = {}
    for root in roots:
        meta = os.path.join(root, "META-INF")
        if not os.path.isdir(meta):
            continue
        for base, _dirs, files in os.walk(meta):
            for name in files:
                path = os.path.join(base, name)
                if name == "pom.properties" and "maven" in base:
                    p = _props(path)
                    g, a, v = p.get("groupId", ""), p.get("artifactId", ""), p.get("version", "")
                elif name.endswith(".version") and base.rstrip("/\\") == meta.rstrip("/\\"):
                    stem = name[:-len(".version")]
                    if "_" not in stem:
                        continue
                    g, a = stem.split("_", 1)
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                            v = fh.read(128).strip()
                    except OSError:
                        continue
                else:
                    continue
                if _valid(g, a, v):
                    seen.setdefault((g, a, v), Component(g, a, v, os.path.relpath(path, decompiled_dir)))
            if len(seen) >= _MAX_COMPONENTS:
                break
    return sorted(seen.values(), key=lambda c: (c.group, c.artifact, c.version))


def to_cyclonedx(components: Iterable[Component], app_name: str = "app") -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {"component": {"type": "application", "name": app_name},
                     "tools": [{"name": "MSRA"}]},
        "components": [{"type": "library", "group": c.group, "name": c.artifact,
                        "version": c.version, "purl": c.purl} for c in components],
    }


# ── vulnerability lookup ───────────────────────────────────────────────────
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _http_json(url: str, body: Optional[dict] = None, timeout: float = 20) -> dict:
    if not url.startswith("https://api.osv.dev/"):
        raise ValueError("refusing non-OSV URL")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json", "User-Agent": "MSRA/2.0"})
    with _OPENER.open(req, timeout=timeout) as resp:
        out = json.loads(resp.read(2_000_000).decode("utf-8", "replace"))
    return out if isinstance(out, dict) else {}


_SEV = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}


def _severity(vuln: dict) -> str:
    sev = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    return _SEV.get(sev, "Medium")


def lookup_vulns(components: List[Component],
                 fetch: Callable[[str, Optional[dict]], dict] = _http_json) -> Dict[Component, List[dict]]:
    """Return {component: [osv vuln, ...]} for vulnerable components. Network errors -> {}."""
    if not components:
        return {}
    result: Dict[Component, List[dict]] = {}
    try:
        for i in range(0, len(components), 500):
            chunk = components[i:i + 500]
            resp = fetch(OSV_BATCH, {"queries": [
                {"package": {"name": c.name, "ecosystem": "Maven"}, "version": c.version} for c in chunk]})
            for c, r in zip(chunk, resp.get("results") or []):
                ids = [v.get("id") for v in (r or {}).get("vulns") or [] if isinstance(v, dict) and v.get("id")]
                if ids:
                    result[c] = [{"id": x} for x in ids]
        details: Dict[str, dict] = {}
        budget = _MAX_VULN_DETAILS
        for vulns in result.values():
            for v in vulns:
                if v["id"] in details:
                    v.update(details[v["id"]]); continue
                if budget <= 0 or not re.match(r"^[A-Za-z0-9._\-]{3,60}$", v["id"]):
                    continue
                budget -= 1
                d = fetch(OSV_VULN + v["id"], None)
                details[v["id"]] = d
                v.update(d)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        pass                                    # offline / blocked: inventory still works
    return result


def vuln_findings(vulns: Dict[Component, List[dict]]) -> List[Finding]:
    order = ["Low", "Medium", "High", "Critical"]
    out: List[Finding] = []
    for comp, items in vulns.items():
        worst = max((_severity(v) for v in items), key=order.index, default="Medium")
        ids = [v.get("id", "?") for v in items][:8]
        aliases = sorted({a for v in items for a in v.get("aliases", []) if a.startswith("CVE-")})[:8]
        summary = next((v.get("summary") for v in items if v.get("summary")), "")
        out.append(Finding(
            fid=f"sbom-vuln:{comp.name}:{comp.version}",
            title=f"Vulnerable dependency: {comp.name} {comp.version}",
            severity=worst,
            description=(f"{comp.name} {comp.version} has {len(items)} known advisories ({', '.join(ids)})"
                         + (f"; CVEs: {', '.join(aliases)}" if aliases else "") + f". {summary}").strip(),
            attack_path="Exploit depends on whether the vulnerable code path is reachable from the app.",
            adb_commands=[], evidence=Evidence(file_path=comp.source, line_number=1,
                                               snippet=comp.purl, matched_text=comp.purl),
            references=[f"https://osv.dev/vulnerability/{i}" for i in ids],
            extra={"category": "Vulnerable Components", "cwe": ["CWE-1104"], "purl": comp.purl,
                   "advisories": ids, "cves": aliases}))
    return out


def scan_sbom(decompiled_dir: str) -> List[Finding]:
    """Scanner hook: an Info inventory finding always; advisories only when opted in."""
    comps = collect_components(decompiled_dir)
    if not comps:
        return []
    findings: List[Finding] = [Finding(
        fid="sbom-inventory", title=f"Software bill of materials: {len(comps)} components",
        severity="Info",
        description=("Libraries identified from build metadata: "
                     + ", ".join(f"{c.name}@{c.version}" for c in comps[:15])
                     + (" ..." if len(comps) > 15 else "")
                     + ". Full CycloneDX export: /api/scans/<id>/sbom.json."),
        attack_path="", adb_commands=[], evidence=None,
        references=["https://cyclonedx.org/"], extra={"category": "Vulnerable Components", "components": len(comps)})]
    if os.environ.get("MSRA_OSV_LOOKUP") == "1":
        findings.extend(vuln_findings(lookup_vulns(comps)))
    return findings
