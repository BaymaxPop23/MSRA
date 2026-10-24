"""Hardcoded-secret detection for decompiled Android apps.

Two complementary detectors:
  * known-format rules (AWS, Google, Stripe, Slack, GitHub, JWT, private keys...)
  * a generic "secret-looking assignment" rule gated by Shannon entropy

Matched values are always masked in findings so reports do not leak the secret
they are warning about. Also extracts Firebase configuration from
google-services.json / strings.xml.
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from ..utils import Evidence, Finding

# Files worth scanning (text only). Binary assets are skipped by extension/size.
_TEXT_EXTS = (".java", ".kt", ".xml", ".json", ".properties", ".js", ".html",
              ".txt", ".cfg", ".conf", ".yml", ".yaml", ".gradle", ".plist")
_MAX_FILE_BYTES = 2_000_000

# Paths that routinely hold high-entropy noise (hashes, generated ids)
_SKIP_PATH_PARTS = ("/res/drawable", "/res/layout", "/res/anim", "/res/color",
                    "/res/mipmap", "/res/menu", "/res/navigation", "/res/raw/")


@dataclass(frozen=True)
class SecretRule:
    rid: str
    title: str
    severity: str
    regex: "re.Pattern[str]"
    group: int = 0
    cwe: str = "CWE-798"


def _r(p: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(p, flags)


RULES: Tuple[SecretRule, ...] = (
    SecretRule("secret-aws-access-key", "Hardcoded AWS access key id", "High",
               _r(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b"), 1),
    SecretRule("secret-aws-secret-key", "Hardcoded AWS secret access key", "Critical",
               _r(r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key['\"\s:=]+([A-Za-z0-9/+=]{40})\b"), 1),
    SecretRule("secret-google-api-key", "Hardcoded Google API key", "Medium",
               _r(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), 1),
    SecretRule("secret-gcp-service-account", "Embedded GCP service-account private key", "Critical",
               _r(r'"private_key_id"\s*:\s*"([0-9a-f]{40})"'), 1),
    SecretRule("secret-private-key-block", "Embedded private key (PEM)", "Critical",
               _r(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"
                  r"(?:[\s\S]{0,8000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)?)"), 1),
    SecretRule("secret-stripe-live-key", "Hardcoded Stripe live secret key", "Critical",
               _r(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"), 1),
    SecretRule("secret-slack-token", "Hardcoded Slack token", "High",
               _r(r"\b(xox[abprs]-[0-9A-Za-z\-]{10,72})\b"), 1),
    SecretRule("secret-slack-webhook", "Hardcoded Slack webhook URL", "Medium",
               _r(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"), 1),
    SecretRule("secret-github-token", "Hardcoded GitHub token", "Critical",
               _r(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), 1),
    SecretRule("secret-twilio-key", "Hardcoded Twilio API key", "High",
               _r(r"\b(SK[0-9a-fA-F]{32})\b"), 1),
    SecretRule("secret-sendgrid-key", "Hardcoded SendGrid API key", "High",
               _r(r"\b(SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64})\b"), 1),
    SecretRule("secret-mailgun-key", "Hardcoded Mailgun API key", "High",
               _r(r"\b(key-[0-9a-zA-Z]{32})\b"), 1),
    SecretRule("secret-anthropic-key", "Hardcoded Anthropic API key", "Critical",
               _r(r"\b(sk-ant-[A-Za-z0-9_\-]{20,})\b"), 1),
    SecretRule("secret-openai-key", "Hardcoded OpenAI API key", "Critical",
               _r(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b"), 1),
    SecretRule("secret-jwt", "Hardcoded JSON Web Token", "Medium",
               _r(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"), 1,
               "CWE-798"),
    SecretRule("secret-basic-auth-url", "Credentials embedded in URL", "High",
               _r(r"\bhttps?://([A-Za-z0-9._~%\-]{2,64}:[^\s/@'\"<>]{3,128}@[A-Za-z0-9.\-]{1,255})"), 1,
               "CWE-522"),
    SecretRule("secret-firebase-server-key", "Hardcoded Firebase Cloud Messaging server key", "High",
               _r(r"\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})\b"), 1),
)

# Generic: name looks secret-ish and value is a long high-entropy literal.
_NAME_RE = r"(?:secret|passwd|password|pwd|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|private[_\-]?key|token|credential)"
# Identifier affixes are bounded and generic matching is done per line (see
# _MAX_GENERIC_LINE) so minified one-line bundles cannot trigger polynomial
# backtracking on attacker-controlled input.
_ASSIGN_RE = re.compile(
    r"(?i)\b[\w.\-]{0,40}" + _NAME_RE + r"[\w.\-]{0,40}['\"]?\s{0,4}(?:=>|=|:|,)\s{0,4}['\"]([^'\"\s]{12,200})['\"]")
_XML_ASSIGN_RE = re.compile(
    r"(?i)<string\s{1,4}name=\"[\w.\-]{0,40}" + _NAME_RE + r"[\w.\-]{0,40}\"[^>\n]{0,80}>([^<\s]{12,200})</string>")
_MAX_GENERIC_LINE = 2000

_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|<.*>|\$\{.*\}|%s|%\d|your[_\-]|insert|change[_\-]?me|"
    r"example|sample|dummy|test|todo|null|none|undefined|password|secret|token|"
    r"android\.|com\.|org\.|net\.|https?://(?:www\.)?(?:example|localhost))")
# Values that merely name a resource / class / key constant
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$|^[A-Z][A-Za-z]+(?:-[A-Za-z0-9]{1,12}){1,4}$")
# second alternative: Header-Style-Names ("Acceptance-Encoding-1"): words joined by hyphens, not a secret


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def mask(value: str) -> str:
    """Show just enough to identify the secret, never the whole value."""
    v = value.strip()
    if len(v) <= 8:
        return "*" * len(v)
    return f"{v[:4]}{'*' * min(len(v) - 8, 16)}{v[-4:]}"


def _looks_secret(value: str) -> bool:
    if len(value) < 12 or _PLACEHOLDER_RE.match(value):
        return False
    if _IDENTIFIER_RE.match(value) and not any(c.isdigit() for c in value):
        return False                      # camelCase / snake_case constant name
    if re.fullmatch(r"[0-9a-fA-F]{32,}", value):
        return shannon_entropy(value) > 3.0   # hex digest-ish secrets
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return shannon_entropy(value) >= 3.5 and classes >= 3


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{40,}")


def _snippet(text: str, line: int, redact: str, full_redact: bool = False) -> str:
    if full_redact:
        return f"{line:04d}: [key material redacted]"
    lines = text.splitlines()
    if not lines:
        return ""
    line = max(1, min(line, len(lines)))
    out = []
    for i in range(max(1, line - 1), min(len(lines), line + 1) + 1):
        out.append(f"{i:04d}: {lines[i - 1].strip()[:200]}")
    snippet = "\n".join(out)
    if redact:
        snippet = snippet.replace(redact, mask(redact))
    # Belt and braces: any long token-like run is masked, whatever rule matched
    return _LONG_TOKEN_RE.sub(lambda m: mask(m.group(0)), snippet)


def _iter_files(roots: Iterable[str]):
    for root in roots:
        if not root or not os.path.isdir(root):
            continue
        for base, _, files in os.walk(root):
            nb = base.replace("\\", "/")
            if any(part in nb + "/" for part in _SKIP_PATH_PARTS):
                continue
            for name in files:
                if not name.lower().endswith(_TEXT_EXTS):
                    continue
                path = os.path.join(base, name)
                try:
                    if os.path.getsize(path) > _MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                yield path


def _make_finding(rid: str, title: str, severity: str, cwe: str, path: str,
                  line: int, text: str, secret: str, kind: str,
                  confidence: str = "high", full_redact: bool = False) -> Finding:
    masked = "[redacted]" if full_redact else (mask(secret) if secret else "")
    return Finding(
        fid=f"{rid}:{path}:{line}",
        title=title,
        severity=severity,
        description=(f"A {kind} was found hardcoded in the app ({masked or 'value masked'}). "
                     "Anyone who unpacks the APK can recover it."),
        attack_path=("Extract the APK, search decompiled sources/resources for the literal, "
                     "and use it directly against the backing service."),
        adb_commands=[],
        evidence=Evidence(file_path=path, line_number=line,
                          snippet=_snippet(text, line, secret, full_redact), matched_text=masked),
        references=["https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage",
                    "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0001/"],
        extra={"cwe": [cwe], "category": "Hardcoded Secrets", "confidence": confidence,
               "rule_id": rid, "secret_kind": kind},
    )


def scan_text(path: str, text: str) -> List[Finding]:
    findings: List[Finding] = []
    seen: set = set()

    for rule in RULES:
        for m in rule.regex.finditer(text):
            secret = m.group(rule.group) if rule.group else m.group(0)
            key = (rule.rid, secret)
            if key in seen:
                continue
            seen.add(key)
            findings.append(_make_finding(
                rule.rid, rule.title, rule.severity, rule.cwe, path,
                _line_of(text, m.start()), text, secret if rule.group else "", rule.title.lower(),
                full_redact=(rule.rid == "secret-private-key-block")))

    for lineno, line_text in enumerate(text.splitlines(), start=1):
        if len(line_text) > _MAX_GENERIC_LINE:
            continue                      # minified blobs: known-format rules only
        for rx in (_ASSIGN_RE, _XML_ASSIGN_RE):
            for m in rx.finditer(line_text):
                value = m.group(1)
                if (rx is _ASSIGN_RE and ("${" in value or "%" in value)) or not _looks_secret(value):
                    continue
                key = ("secret-generic", value)
                if key in seen or any(value in sv for _, sv in seen if isinstance(sv, str) and sv != value):
                    continue              # already reported by a specific rule
                seen.add(key)
                findings.append(_make_finding(
                    "secret-high-entropy-literal", "Hardcoded credential-like value",
                    "Medium", "CWE-798", path, lineno, text, value,
                    "high-entropy credential-like string", confidence="medium"))

    # A snippet shows neighbouring lines, which may hold *other* secrets from
    # this file - mask every secret we found in every snippet.
    all_secrets = sorted({sec for _, sec in seen if isinstance(sec, str) and len(sec) >= 8},
                         key=len, reverse=True)
    for f in findings:
        for sec in all_secrets:
            f.evidence.snippet = f.evidence.snippet.replace(sec, mask(sec))
    return findings


def _firebase_findings(path: str, text: str) -> List[Finding]:
    """Surface Firebase project endpoints so they can be probed for open rules."""
    out: List[Finding] = []
    m = re.search(r'"firebase_url"\s*:\s*"(https://[A-Za-z0-9\-]+\.firebaseio\.com)"', text) or \
        re.search(r"(https://[A-Za-z0-9\-]+(?:-default-rtdb)?\.firebaseio\.com)", text)
    if m:
        url = m.group(1)
        f = _make_finding(
            "secret-firebase-database-url", "Firebase Realtime Database endpoint exposed",
            "Info", "CWE-200", path, _line_of(text, m.start()), text, "", "Firebase database URL",
            confidence="high")
        f.description = (f"The app talks to the Firebase Realtime Database at {url}. "
                         "If its security rules are open, anyone can read or write the data.")
        f.attack_path = f"curl -s '{url}/.json?shallow=true'   # 200 with data (not 401) means world-readable"
        f.extra["firebase_url"] = url
        out.append(f)
    return out


def scan_paths(roots: Iterable[str], max_findings: int = 400) -> List[Finding]:
    """Scan decompiled sources, resources and assets for hardcoded secrets."""
    findings: List[Finding] = []
    for path in _iter_files(roots):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        findings.extend(scan_text(path, text))
        if path.endswith((".json", ".xml")):
            findings.extend(_firebase_findings(path, text))
        if len(findings) >= max_findings:
            break
    return findings[:max_findings]
