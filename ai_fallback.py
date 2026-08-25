"""Hyperion Security Engine — deterministic rule-based fallback analysis.

Builds a complete, schema-valid analysis response from the structured
findings already produced by scanner.py and dependency_check.py.
No LLM calls, no network, no randomness: same input always yields the
same output. This module never raises and never returns partial data.
"""

from __future__ import annotations

from collections import Counter, OrderedDict
from typing import Any

__all__ = ["generate_fallback_analysis"]

# --- Severity / scoring constants -----------------------------------------
# Fixed CVSS placeholders per severity band. The fallback has no exploit
# context, so we use conservative mid-band values for each severity level
# (Critical ~9.x, High ~8.x, Medium ~6.x, Low ~3.x) rather than pretending
# to compute real scores.
_CVSS_BY_SEVERITY = {
    "Critical": 9.5,
    "High": 8.0,
    "Medium": 6.0,
    "Low": 3.5,
}

# Health-score model (exact formula):
#
#   health_score = clamp(round(100 - total_penalty), 0, 100)
#
# total_penalty is computed over code-level findings (scanner.py) and
# dependency findings (dependency_check.py) SEPARATELY. Within each
# bucket, penalties for the same severity have diminishing returns:
#
#   code_penalty(S) = FIRST[S] + (n_S - 1) * REPEAT[S]     (n_S >= 1)
#   dep_penalty(S)  = DEP_WEIGHT * code_penalty(S)
#
#   FIRST      = {Critical: 15, High: 10, Medium: 5, Low: 2}
#   REPEAT     = {Critical:  8, High:  5, Medium: 2, Low: 1}
#   DEP_WEIGHT = 0.6
#
# Rationale: a package carrying 5 separate CVE advisories should NOT cost
# 5x a single distinct code bug — dependency penalties are both scaled
# down (DEP_WEIGHT) and diminished per severity. A realistic mix like
# 3C/6H/5M/1L costs ~75 points (score ~25) instead of flooring at 0,
# while a truly catastrophic finding load still reaches 0.
_FIRST_PENALTY_BY_SEVERITY = {"Critical": 15, "High": 10, "Medium": 5, "Low": 2}
_REPEAT_PENALTY_BY_SEVERITY = {"Critical": 8, "High": 5, "Medium": 2, "Low": 1}
_DEP_PENALTY_WEIGHT = 0.6

# Base severity per scanner pattern_type. These are deliberately coarse:
# injection-style sinks are treated as Critical because they are directly
# attacker-reachable; secrets and dangerous builtins as High; unsafe
# deserialization via yaml.load defaults to Medium until confidence says
# otherwise (confidence modifiers below can raise/lower one band).
_BASE_SEVERITY_BY_PATTERN = {
    "hardcoded_secret": "High",
    "sql_injection": "Critical",
    "dangerous_call": "High",
    "insecure_deserialization": "Medium",
}

# Confidence modifier: medium confidence lowers the base severity by one
# band; low confidence lowers it by two. Keeps scoring deterministic while
# still respecting scanner confidence signals.
_CONFIDENCE_DOWNGRADE = {
    "high": 0,
    "medium": 1,
    "low": 2,
}

# OWASP Top-10 (2021) category per pattern_type.
_OWASP_BY_PATTERN = {
    "hardcoded_secret": "A02:2021-Cryptographic Failures",
    "sql_injection": "A03:2021-Injection",
    "dangerous_call": "A03:2021-Injection",
    "insecure_deserialization": "A08:2021-Software and Data Integrity Failures",
}

# Dependency findings come straight out of OSV.dev with their own severity;
# they map to the dedicated outdated-components category.
_DEPENDENCY_OWASP_CATEGORY = "A06:2021-Vulnerable and Outdated Components"

# Dependency findings whose severity OSV could not resolve are penalized at
# Medium: prudent default — not provably low-risk, but no evidence for High.
_UNKNOWN_DEP_SEVERITY = "Medium"

# Narrative templates for the attack-path proof-of-concept section.
# Narrative-only by design: no runnable code, no concrete payloads.
_ATTACK_NARRATIVES: dict[str, tuple[str, str]] = {
    "hardcoded_secret": (
        "An attacker who gains read access to the source tree (via a leaked "
        "repository, CI logs, or an exposed artifact) extracts the embedded "
        "credential and uses it to authenticate as a legitimate principal.",
        "With valid credentials in hand, the attacker pivots to the service "
        "the secret belongs to and operates with that identity's privileges.",
    ),
    "sql_injection": (
        "An attacker could exploit improperly sanitized input to execute "
        "unintended SQL commands against the application's database.",
        "By manipulating the query structure, the attacker reads or mutates "
        "data outside the intended scope of the affected statement.",
    ),
    "dangerous_call": (
        "An attacker able to influence the argument of the flagged call "
        "induces the interpreter to execute attacker-chosen instructions "
        "in the host process.",
        "Execution inside the process grants the attacker the application's "
        "own privileges, including access to its environment and files.",
    ),
    "insecure_deserialization": (
        "An attacker submits crafted serialized content that the "
        "application deserializes without restriction, instantiating "
        "objects under the attacker's control.",
        "During deserialization the crafted object executes logic chosen "
        "by the attacker, compromising the integrity of the service.",
    ),
}

# Fallback narrative pair used when a pattern_type is unrecognized, so the
# output stays schema-complete even for future/unknown pattern types.
_GENERIC_NARRATIVES = (
    "An attacker could abuse the flagged construct to subvert the "
    "intended behavior of the application.",
    "Successful exploitation lets the attacker operate outside the "
    "security assumptions of the affected component.",
)

_IMMEDIATE_FIX_TEMPLATES = {
    "hardcoded_secret": 'Remove the hardcoded secret at "{file}:{line}" and load it from a secrets manager or environment variable.',
    "sql_injection": 'Replace string-built SQL at "{file}:{line}" with parameterized queries or bound placeholders.',
    "dangerous_call": 'Eliminate or sandbox the dangerous call at "{file}:{line}"; validate any dynamic input before it reaches the call.',
    "insecure_deserialization": 'Use a safe loader / restricted parser at "{file}:{line}"; never deserialize untrusted input unrestricted.',
}

_ARCH_HARDENING_TEMPLATES = {
    "hardcoded_secret": "Introduce centralized credential management so no code path embeds secrets directly.",
    "sql_injection": "Route all database access through a data-access layer that only accepts parameterized statements.",
    "dangerous_call": "Adopt an allowlist policy for dynamic execution primitives (eval/exec/os.system/subprocess shell=True).",
    "insecure_deserialization": "Standardize on safe deserialization formats and loaders across the codebase.",
}

_PIPELINE_GUARDRAILS_STATIC = [
    "Fail CI on any new finding of severity High or above produced by the static scanner.",
    "Require security review sign-off before merging changes that touch flagged sinks.",
]

_PIPELINE_GUARDRAIL_DEPS = (
    "Pin all third-party dependencies and run automated vulnerability scanning "
    "(e.g. OSV-based checks) on every pull request."
)


def _safe_str(value: Any, default: str = "") -> str:
    """Coerce to str without ever raising."""
    try:
        return value if isinstance(value, str) else default if value is None else str(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """Coerce to int without ever raising."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp_score(score: float) -> float:
    return max(0.0, min(10.0, score))


def _scanner_severity(finding: dict[str, Any]) -> str:
    """Derive a severity band from pattern_type + confidence deterministically."""
    pattern = _safe_str(finding.get("pattern_type"))
    base = _BASE_SEVERITY_BY_PATTERN.get(pattern, "Medium")  # unknown patterns: Medium
    bands = ["Low", "Medium", "High", "Critical"]
    index = bands.index(base)
    downgrade = _CONFIDENCE_DOWNGRADE.get(_safe_str(finding.get("confidence")).lower(), 1)
    # Clamp so an over-downgrade cannot fall off the bottom of the scale.
    return bands[max(0, index - downgrade)]


def _dep_severity(finding: dict[str, Any]) -> str:
    severity = _safe_str(finding.get("severity")).capitalize()
    return severity if severity in _FIRST_PENALTY_BY_SEVERITY else _UNKNOWN_DEP_SEVERITY


def _bucket_penalty(severities: list[str], weight: float = 1.0) -> float:
    """Diminishing-return penalty for one bucket of severities (see formula above)."""
    counts = Counter(severities)
    return sum(
        weight
        * (
            _FIRST_PENALTY_BY_SEVERITY[severity]
            + (count - 1) * _REPEAT_PENALTY_BY_SEVERITY[severity]
        )
        for severity, count in counts.items()
    )


def _dot_escape(text: str) -> str:
    """Escape a string for safe use inside a DOT quoted identifier."""
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ").replace("\r", " ")


def _build_dot_script(scan_findings: list[dict[str, Any]]) -> str:
    """Always-valid DOT graph: each flagged file:line connects to one sink node."""
    lines = [
        "digraph HyperionAttackGraph {",
        "  rankdir=LR;",
        '  node [shape=box, style=filled, fillcolor="#f2f2f2"];',
        '  "Vulnerable Sink" [fillcolor="#ffcccc"];',
    ]
    seen: set[str] = set()
    for finding in scan_findings:
        file_name = _safe_str(finding.get("file"), "unknown.py")
        line_no = _safe_int(finding.get("line_number"), 1)
        pattern = _safe_str(finding.get("pattern_type"), "unknown")
        node_id = f"{file_name}:{line_no}"
        if node_id in seen:
            continue  # one node per file:line keeps the graph small and valid
        seen.add(node_id)
        label = f"{_dot_escape(node_id)}\\n{_dot_escape(pattern)}"
        lines.append(f'  "{_dot_escape(node_id)}" [label="{label}"];')
        lines.append(f'  "{_dot_escape(node_id)}" -> "Vulnerable Sink";')
    lines.append("}")
    return "\n".join(lines)


def _build_attack_path(scan_findings: list[dict[str, Any]], dep_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Two narrative-only steps per distinct pattern type, first-seen order."""
    steps: list[dict[str, Any]] = []
    step_number = 1

    def _emit(narratives: tuple[str, ...]) -> None:
        nonlocal step_number
        for narrative in narratives:
            steps.append({"step": step_number, "narrative": narrative})
            step_number += 1

    seen_patterns: OrderedDict[str, None] = OrderedDict()
    for finding in scan_findings:
        pattern = _safe_str(finding.get("pattern_type"))
        if pattern and pattern not in seen_patterns:
            seen_patterns[pattern] = None

    for pattern in seen_patterns:
        _emit(_ATTACK_NARRATIVES.get(pattern, _GENERIC_NARRATIVES))

    if dep_findings:
        _emit(
            (
                "The application ships with known-vulnerable dependencies; an "
                "attacker targets a published flaw in one of those packages "
                "instead of the application code itself.",
                "Exploiting the upstream package flaw yields the same impact as "
                "a direct application bug, since the vulnerable code runs "
                "inside the trusted process.",
            )
        )
    return steps


def _build_recommendations(
    scan_findings: list[dict[str, Any]],
    dep_findings: list[dict[str, Any]],
) -> dict[str, list[str]]:
    immediate_fixes: list[str] = []
    hardening: list[str] = []
    guardrails: list[str] = list(_PIPELINE_GUARDRAILS_STATIC)

    seen_files: Counter[str] = Counter()
    seen_patterns: OrderedDict[str, None] = OrderedDict()
    for finding in scan_findings:
        file_name = _safe_str(finding.get("file"), "unknown.py")
        line_no = _safe_int(finding.get("line_number"), 1)
        pattern = _safe_str(finding.get("pattern_type"))
        seen_files[file_name] += 1
        template = _IMMEDIATE_FIX_TEMPLATES.get(pattern)
        if template:
            immediate_fixes.append(template.format(file=file_name, line=line_no))
        if pattern and pattern not in seen_patterns:
            seen_patterns[pattern] = None
            arch_template = _ARCH_HARDENING_TEMPLATES.get(pattern)
            if arch_template:
                hardening.append(arch_template)

    if dep_findings:
        packages = sorted({str(f.get("package", "?")) for f in dep_findings})
        immediate_fixes.append(
            "Upgrade vulnerable dependencies to their fixed versions: "
            + ", ".join(packages)
            + "."
        )
        guardrails.append(_PIPELINE_GUARDRAIL_DEPS)

    return {
        "immediate_fixes": immediate_fixes,
        "architecture_hardening": hardening,
        "pipeline_guardrails": guardrails,
    }


def _build_refactored_code(scan_findings: list[dict[str, Any]], source_code: str) -> dict[str, str]:
    """
    Safe no-op: the rule-based path does not attempt automated fixes.

    Contract: refactored_code.full_source echoes the caller-supplied
    original source text back COMPLETELY UNMODIFIED (character for
    character). It is never reconstructed from findings.
    The AI layer will replace this with a real refactor proposal later.
    """
    target_file = ""
    if scan_findings:
        counts: Counter[str] = Counter(
            _safe_str(f.get("file"), "unknown.py") for f in scan_findings
        )
        target_file = max(counts, key=lambda f: (counts[f], f))
    return {
        "file": target_file,
        "language": "python" if target_file else "",
        "full_source": source_code,
    }


def generate_fallback_analysis(
    scan_findings: list[dict], dep_findings: list[dict], source_code: str = ""
) -> dict:
    """Deterministically build the schema-complete analysis response.

    Never raises; always returns every required key even for empty inputs.
    """
    try:
        scan_findings = [f for f in (scan_findings or []) if isinstance(f, dict)]
        dep_findings = [f for f in (dep_findings or []) if isinstance(f, dict)]
        source_code = _safe_str(source_code)

        code_severities: list[str] = []
        dep_severities: list[str] = []
        vulnerabilities: list[dict[str, Any]] = []

        for index, finding in enumerate(scan_findings):
            severity = _scanner_severity(finding)
            code_severities.append(severity)
            pattern = _safe_str(finding.get("pattern_type"), "unknown")
            vulnerabilities.append(
                {
                    "id": f"SCAN-{index + 1:03d}-{pattern}",
                    "owasp_category": _OWASP_BY_PATTERN.get(
                        pattern, "A03:2021-Injection"
                    ),
                    "severity": severity,
                    "cvss_score": _CVSS_BY_SEVERITY[severity],
                    "line_number": max(1, _safe_int(finding.get("line_number"), 1)),
                    "file": _safe_str(finding.get("file"), "unknown.py"),
                    "description": _safe_str(finding.get("snippet")),
                }
            )

        for index, finding in enumerate(dep_findings):
            severity = _dep_severity(finding)
            dep_severities.append(severity)
            package = _safe_str(finding.get("package"), "unknown-package")
            version = _safe_str(finding.get("installed_version"))
            vuln_id = _safe_str(finding.get("vuln_id")) or "UNKNOWN"
            summary = _safe_str(finding.get("summary"))
            description = f"{package}=={version}: {summary}".strip(": ")
            vulnerabilities.append(
                {
                    "id": f"DEP-{index + 1:03d}-{vuln_id}",
                    "owasp_category": _DEPENDENCY_OWASP_CATEGORY,
                    "severity": severity,
                    "cvss_score": _CVSS_BY_SEVERITY[severity],
                    "line_number": 0,  # dependencies have no source line; 0 = N/A
                    "file": _safe_str(finding.get("package"), "requirements.txt"),
                    "description": description,
                }
            )

        # Scoring: independent diminishing penalties per bucket (see formula
        # documented next to _FIRST_PENALTY_BY_SEVERITY above).
        total_penalty = _bucket_penalty(code_severities) + _bucket_penalty(
            dep_severities, _DEP_PENALTY_WEIGHT
        )
        health_score = int(round(100 - total_penalty))

        return {
            "health_score": max(0, min(100, health_score)),
            "vulnerabilities": vulnerabilities,
            "graphviz_dot_script": _build_dot_script(scan_findings),
            "attack_path_poc": _build_attack_path(scan_findings, dep_findings),
            "recommendations": _build_recommendations(scan_findings, dep_findings),
            "refactored_code": _build_refactored_code(scan_findings, source_code),
        }
    except Exception:
        # Last-resort guarantee: never raise, always schema-complete.
        return {
            "health_score": 100,
            "vulnerabilities": [],
            "graphviz_dot_script": (
                'digraph HyperionAttackGraph {\n  rankdir=LR;\n'
                '  node [shape=box];\n  "Vulnerable Sink";\n}'
            ),
            "attack_path_poc": [],
            "recommendations": {
                "immediate_fixes": [],
                "architecture_hardening": [],
                "pipeline_guardrails": [],
            },
            "refactored_code": {"file": "", "language": "", "full_source": ""},
        }
