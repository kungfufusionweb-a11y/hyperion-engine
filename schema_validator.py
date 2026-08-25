"""Hyperion Security Engine — schema validation module.

Validates analysis-response dicts against the engine's response contract.
Shared by the LLM response path and ai_fallback.py. Never raises: every
failure mode returns (False, "<specific reason>").
"""

from __future__ import annotations

from typing import Any

__all__ = ["validate_schema"]

_TOP_LEVEL_KEYS = (
    "health_score",
    "vulnerabilities",
    "graphviz_dot_script",
    "attack_path_poc",
    "recommendations",
    "refactored_code",
)

_VULNERABILITY_KEYS = (
    "id",
    "owasp_category",
    "severity",
    "cvss_score",
    "line_number",
    "file",
    "description",
)

_STEP_KEYS = ("step", "narrative")

_RECOMMENDATION_KEYS = ("immediate_fixes", "architecture_hardening", "pipeline_guardrails")

_REFACTORED_CODE_KEYS = ("file", "language", "full_source")

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_float(value: Any) -> bool:
    return isinstance(value, float) and not isinstance(value, bool)


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_num(value: Any) -> bool:
    return _is_int(value) or _is_float(value)


def validate_schema(data: dict) -> tuple[bool, str]:
    """Validate *data* against the Hyperion analysis-response contract.

    Returns (True, "") when valid, otherwise (False, reason) where reason
    pinpoints the exact offending path and value. Never raises.
    """
    try:
        return _validate(data)
    except Exception as exc:  # defensive: validation itself must never raise
        return False, f"schema validation failed unexpectedly: {exc!r}"


def _validate(data: Any) -> tuple[bool, str]:
    if data is None:
        return False, "input is None; expected a dict matching the analysis schema"
    if not isinstance(data, dict):
        return False, f"top-level input must be a dict, got {type(data).__name__}"
    if not data:
        return False, "input is an empty dict; expected all required keys: " + ", ".join(_TOP_LEVEL_KEYS)

    # --- top-level key presence -------------------------------------------
    missing = [key for key in _TOP_LEVEL_KEYS if key not in data]
    if missing:
        return False, f"missing required top-level key(s): {', '.join(missing)}"

    # --- health_score ------------------------------------------------------
    score = data["health_score"]
    if not _is_int(score):
        return False, (
            f"health_score must be an int, got {type(score).__name__} ({score!r})"
        )
    if not 0 <= score <= 100:
        return False, f"health_score must be between 0 and 100 inclusive, got {score}"

    # --- vulnerabilities ---------------------------------------------------
    ok, reason = _validate_vulnerabilities(data["vulnerabilities"])
    if not ok:
        return False, reason

    # --- graphviz_dot_script -----------------------------------------------
    dot = data["graphviz_dot_script"]
    if not _is_str(dot):
        return False, f"graphviz_dot_script must be a str, got {type(dot).__name__}"
    if not dot.strip().lower().startswith("digraph"):
        return False, (
            "graphviz_dot_script must start with 'digraph' after stripping "
            f"whitespace, got: {dot[:60]!r}"
        )

    # --- attack_path_poc -----------------------------------------------------
    steps = data["attack_path_poc"]
    if not isinstance(steps, list):
        return False, f"attack_path_poc must be a list, got {type(steps).__name__}"
    for index, step_item in enumerate(steps):
        prefix = f"attack_path_poc[{index}]"
        if not isinstance(step_item, dict):
            return False, f"{prefix} must be a dict, got {type(step_item).__name__}"
        step_missing = [key for key in _STEP_KEYS if key not in step_item]
        if step_missing:
            return False, f"{prefix} missing required key(s): {', '.join(step_missing)}"
        if not _is_int(step_item["step"]):
            return False, (
                f"{prefix}.step must be an int, got "
                f"{type(step_item['step']).__name__} ({step_item['step']!r})"
            )
        if not _is_str(step_item["narrative"]):
            return False, (
                f"{prefix}.narrative must be a str, got "
                f"{type(step_item['narrative']).__name__}"
            )

    # --- recommendations -------------------------------------------------------
    recs = data["recommendations"]
    if not isinstance(recs, dict):
        return False, f"recommendations must be a dict, got {type(recs).__name__}"
    extra = sorted(set(recs) - set(_RECOMMENDATION_KEYS))
    if extra:
        return False, (
            "recommendations contains unexpected key(s): "
            + ", ".join(extra)
            + "; allowed keys are exactly: "
            + ", ".join(_RECOMMENDATION_KEYS)
        )
    rec_missing = [key for key in _RECOMMENDATION_KEYS if key not in recs]
    if rec_missing:
        return False, f"recommendations missing required key(s): {', '.join(rec_missing)}"
    for key in _RECOMMENDATION_KEYS:
        value = recs[key]
        if not isinstance(value, list):
            return False, f"recommendations.{key} must be a list of str, got {type(value).__name__}"
        for index, item in enumerate(value):
            if not _is_str(item):
                return False, (
                    f"recommendations.{key}[{index}] must be a str, got "
                    f"{type(item).__name__} ({item!r})"
                )

    # --- refactored_code ---------------------------------------------------------
    refactored = data["refactored_code"]
    if not isinstance(refactored, dict):
        return False, f"refactored_code must be a dict, got {type(refactored).__name__}"
    ref_missing = [key for key in _REFACTORED_CODE_KEYS if key not in refactored]
    if ref_missing:
        return False, f"refactored_code missing required key(s): {', '.join(ref_missing)}"
    for key in _REFACTORED_CODE_KEYS:
        if not _is_str(refactored[key]):
            return False, (
                f"refactored_code.{key} must be a str, got "
                f"{type(refactored[key]).__name__} ({refactored[key]!r})"
            )

    return True, ""


def _validate_vulnerabilities(vulns: Any) -> tuple[bool, str]:
    if not isinstance(vulns, list):
        return False, f"vulnerabilities must be a list, got {type(vulns).__name__}"
    for index, vuln in enumerate(vulns):
        prefix = f"vulnerabilities[{index}]"
        if not isinstance(vuln, dict):
            return False, f"{prefix} must be a dict, got {type(vuln).__name__}"
        vuln_missing = [key for key in _VULNERABILITY_KEYS if key not in vuln]
        if vuln_missing:
            return False, f"{prefix} missing required key(s): {', '.join(vuln_missing)}"

        severity = vuln["severity"]
        if not _is_str(severity) or severity not in _VALID_SEVERITIES:
            return False, (
                f"{prefix}.severity must be one of Critical/High/Medium/Low, got {severity!r}"
            )

        cvss = vuln["cvss_score"]
        if not _is_num(cvss):
            return False, f"{prefix}.cvss_score must be a float, got {type(cvss).__name__} ({cvss!r})"
        if not 0.0 <= float(cvss) <= 10.0:
            return False, f"{prefix}.cvss_score must be between 0.0 and 10.0, got {cvss}"

        line = vuln["line_number"]
        if not _is_int(line):
            return False, f"{prefix}.line_number must be an int, got {type(line).__name__} ({line!r})"

        for key in ("id", "owasp_category", "file", "description"):
            if not _is_str(vuln[key]):
                return False, (
                    f"{prefix}.{key} must be a str, got {type(vuln[key]).__name__} ({vuln[key]!r})"
                )
    return True, ""
