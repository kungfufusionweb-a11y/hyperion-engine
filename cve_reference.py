"""Hyperion Security Engine — curated CVE reference set.

A small, hand-picked set of real, publicly documented CVEs used as few-shot
grounding for the LLM analysis layer (ai_llm.py). Each entry is a real CVE
with an NVD-verifiable CVSS base score and an OWASP Top 10 2021 category
mapping. The purpose is to give the model concrete real-world anchors for
OWASP classification and CVSS severity calibration rather than relying on
its prior alone.

These are reference anchors for the prompt only. The scanner does not look
up these CVE IDs against code; it detects vulnerability patterns and the
LLM uses these examples to ground its scoring and category choices.
"""

from __future__ import annotations

__all__ = ["CVE_REFERENCE_EXAMPLES", "format_examples_for_prompt"]

# All CVSS base scores below are taken from the NVD "Primary" metric for
# each CVE. CVE-2014-3704 has no CVSS v3.x metric on NVD; its NVD base
# score is 7.5 (CVSS v2.0). The remaining six have NVD CVSS v3.1 base
# scores. Severity strings are consistent with the score under the
# standard thresholds: >=9.0 Critical, >=7.0 High, >=4.0 Medium, else Low.
CVE_REFERENCE_EXAMPLES: list[dict] = [
    {
        "cve_id": "CVE-2020-1747",
        "owasp_category": "A08:2021-Software and Data Integrity Failures",
        "cvss_score": 9.8,
        "severity": "Critical",
        "vulnerability_class": "insecure_deserialization",
        "description": "PyYAML before 5.3.1 permits arbitrary code execution when processing untrusted YAML through the full_load method or the FullLoader.",
        "general_remediation": "Use yaml.safe_load or yaml.load with an explicit SafeLoader for any untrusted YAML input, and prefer data-only formats where feasible.",
    },
    {
        "cve_id": "CVE-2021-44228",
        "owasp_category": "A03:2021-Injection",
        "cvss_score": 10.0,
        "severity": "Critical",
        "vulnerability_class": "insecure_deserialization",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 allows remote code execution through attacker-controlled JNDI lookup strings in log messages or configuration parameters.",
        "general_remediation": "Disable JNDI lookups and remote class loading in the logging stack, restrict logged data, and upgrade to a Log4j2 release that removes lookup substitution.",
    },
    {
        "cve_id": "CVE-2018-1335",
        "owasp_category": "A03:2021-Injection",
        "cvss_score": 8.1,
        "severity": "High",
        "vulnerability_class": "dangerous_call",
        "description": "Apache Tika 1.7 through 1.17 allows remote command injection through crafted HTTP headers processed by the tika-server header parser.",
        "general_remediation": "Validate and constrain all user-controllable header values before they reach a command interpreter, run parsers in a sandboxed least-privilege process, and keep parsers patched.",
    },
    {
        "cve_id": "CVE-2014-3704",
        "owasp_category": "A03:2021-Injection",
        "cvss_score": 7.5,
        "severity": "High",
        "vulnerability_class": "sql_injection",
        "description": "Drupal core 7.x before 7.32 allows remote SQL injection through improper construction of prepared statements when query arguments are supplied as arrays.",
        "general_remediation": "Use parameterized queries and a vetted data-access layer that strictly separates code from data, and never build query strings through concatenation or array-key interpolation.",
    },
    {
        "cve_id": "CVE-2015-7755",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_score": 9.8,
        "severity": "Critical",
        "vulnerability_class": "hardcoded_secret",
        "description": "Juniper ScreenOS 6.2.0r15 through 6.2.0r18 and affected 6.3.0r12 through 6.3.0r20 builds contain a hardcoded backdoor password that permits unauthenticated remote administrative access via SSH or TELNET.",
        "general_remediation": "Eliminate hardcoded credentials from source and firmware, generate unique secrets per deployment, store them in a dedicated secrets manager, and audit images for embedded credentials.",
    },
    {
        "cve_id": "CVE-2014-6271",
        "owasp_category": "A03:2021-Injection",
        "cvss_score": 9.8,
        "severity": "Critical",
        "vulnerability_class": "dangerous_call",
        "description": "GNU Bash through 4.3 permits remote code execution through specially crafted environment variable values, exploitable across privilege boundaries such as CGI handlers and SSH ForceCommand.",
        "general_remediation": "Avoid invoking shells with untrusted data, prefer argument-array APIs over shell invocation, and keep command interpreters and CGI handlers patched to fixed versions.",
    },
    {
        "cve_id": "CVE-2017-5638",
        "owasp_category": "A03:2021-Injection",
        "cvss_score": 9.8,
        "severity": "Critical",
        "vulnerability_class": "dangerous_call",
        "description": "Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 allows remote code execution through improper exception handling in the Jakarta Multipart parser when processing crafted file-upload headers.",
        "general_remediation": "Validate and constrain all user-controllable header and multipart data before parser processing, disable risky parsers when unused, and keep the framework patched to a release that handles malformed input safely.",
    },
]

_REQUIRED_KEYS = (
    "cve_id",
    "owasp_category",
    "cvss_score",
    "severity",
    "vulnerability_class",
    "description",
    "general_remediation",
)

_VALID_SEVERITIES = ("Critical", "High", "Medium", "Low")


def _expected_severity(score: float) -> str:
    """Standard CVSS severity thresholds: >=9.0 Critical, >=7.0 High, >=4.0 Medium, else Low."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _validate_entry(entry: dict) -> None:
    """Internal sanity check used at import time. Raises on malformed data."""
    missing = [k for k in _REQUIRED_KEYS if k not in entry]
    if missing:
        raise ValueError(f"CVE entry missing required keys: {missing}")
    score = entry["cvss_score"]
    if not isinstance(score, (int, float)) or not (0.0 <= float(score) <= 10.0):
        raise ValueError(f"{entry.get('cve_id')}: cvss_score {score!r} out of [0.0, 10.0]")
    severity = entry["severity"]
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"{entry['cve_id']}: severity {severity!r} not one of {_VALID_SEVERITIES}"
        )
    if _expected_severity(float(score)) != severity:
        raise ValueError(
            f"{entry['cve_id']}: severity {severity!r} inconsistent with "
            f"cvss_score {score} (expected {_expected_severity(float(score))!r})"
        )


for _entry in CVE_REFERENCE_EXAMPLES:
    _validate_entry(_entry)


def format_examples_for_prompt() -> str:
    """Render CVE_REFERENCE_EXAMPLES as a compact plain-text calibration block.

    Plain text rather than full JSON to keep prompt token usage reasonable.
    Intended for insertion into ai_llm.py's system prompt as few-shot
    grounding for OWASP category mapping and CVSS severity scoring.
    """
    lines = []
    for entry in CVE_REFERENCE_EXAMPLES:
        lines.append(
            f"- {entry['cve_id']} "
            f"[{entry['vulnerability_class']}, {entry['owasp_category']}, "
            f"{entry['cvss_score']} {entry['severity']}]: "
            f"{entry['description']} "
            f"Remediation: {entry['general_remediation']}"
        )
    return "\n".join(lines)
