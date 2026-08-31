"""Hyperion Security Engine — LLM-backed analysis path.

Sits alongside ai_fallback.py: attempts a real LLM analysis built from the
scanner findings, dependency findings, and the full source file in ONE
batched prompt. The model's answer must pass schema_validator.validate_schema()
before it is returned. On ANY failure — missing API key, invalid JSON, schema
violation, 60-second timeout, or network/API error — this module falls back to
ai_fallback.generate_fallback_analysis(). It never raises and never returns
a dict that has not passed validate_schema().
"""

from __future__ import annotations

import json
import logging
import os
import socket
import urllib.error
import urllib.request
from typing import Any

import ai_fallback
from schema_validator import validate_schema

__all__ = ["analyze_with_llm", "get_analysis"]

logger = logging.getLogger("hyperion.ai_llm")

# --- API configuration ------------------------------------------------------
# The API key is NEVER hardcoded: it comes from the caller or the
# environment. Endpoint and model are env-overridable so any
# OpenAI-compatible chat-completions API can be swapped in without code
# changes. No third-party HTTP dependency: stdlib urllib only.
# Measured baseline: this schema's typical output (~1500 tokens) takes
# ~46s on the current provider/model (3 runs: 46.2s, 46.2s, 46.4s).
# 60s gives headroom over that baseline without inviting indefinite hangs.
_API_TIMEOUT_SECONDS = 60
_ENV_API_KEY = "HYPERION_LLM_API_KEY"
_ENV_API_URL = "HYPERION_LLM_API_URL"
_ENV_MODEL = "HYPERION_LLM_MODEL"
_DEFAULT_API_URL = "https://api.openai.com/v1/chat/completions"
_DEFAULT_MODEL = "gpt-4o-mini"

_SYSTEM_PROMPT = """\
You are the analysis core of the Hyperion Security Engine: a senior
application-security analyst. You receive, in one batch: (1) static-scanner
findings, (2) dependency-vulnerability findings, and (3) the complete
source code of the file under review. Produce one holistic security
assessment of that file.

OUTPUT CONTRACT — obey exactly:
1. Return ONLY valid JSON. No markdown code fences, no backticks, and no
   prose before or after the JSON object.
2. The JSON object must contain exactly these top-level keys —
   health_score, vulnerabilities, graphviz_dot_script, attack_path_poc,
   recommendations, refactored_code — matching this schema:
   {
     "health_score": int, 0-100 (100 = clean),
     "vulnerabilities": [
       {
         "id": str, unique identifier,
         "owasp_category": str, OWASP Top 10 2021 (e.g. "A03:2021-Injection"),
         "severity": one of "Critical" | "High" | "Medium" | "Low",
         "cvss_score": number 0.0-10.0 consistent with the severity,
         "line_number": int, line in the supplied source,
         "file": str,
         "description": str
       }
     ],
     "graphviz_dot_script": str, a valid Graphviz DOT script that MUST
       start with "digraph",
     "attack_path_poc": [{"step": int, 1-based and ordered, "narrative": str}],
     "recommendations": {
       "immediate_fixes": [str],
       "architecture_hardening": [str],
       "pipeline_guardrails": [str]
     },
     "refactored_code": {"file": str, "language": str, "full_source": str}
   }
3. attack_path_poc must be narrative and educational ONLY: describe in
   plain language how an attacker could chain the weaknesses. NEVER
   provide runnable exploit code, payloads, or commands — describe the
   path, do not demonstrate it.
4. refactored_code.full_source must be the COMPLETE corrected file —
   every line, including unchanged ones — never a fragment, an excerpt,
   or a placeholder such as "... rest unchanged ...".
5. BREVITY — keep the output compact without losing analytical value:
   - Each vulnerabilities[].description must be ONE concise sentence.
   - attack_path_poc must contain AT MOST 5 steps: group related
     vulnerabilities into a single combined attack-chain narrative where
     it makes sense, rather than one step per finding.
   - Each item in every recommendations list (immediate_fixes,
     architecture_hardening, pipeline_guardrails) must be ONE concise
     sentence.
   These brevity limits NEVER apply to refactored_code.full_source,
   which stays complete and unabridged per rule 4.
6. Every key must always be present; use empty lists when there is
   nothing to report.
"""


def _build_user_prompt(
    scan_findings: list[dict], dep_findings: list[dict], source_code: str
) -> str:
    """One batched user message: findings, dependency findings, full source."""
    return (
        "Analyze the following inputs and return the JSON assessment.\n\n"
        "=== STATIC SCANNER FINDINGS ===\n"
        + json.dumps(scan_findings, indent=2, default=str)
        + "\n\n=== DEPENDENCY VULNERABILITY FINDINGS ===\n"
        + json.dumps(dep_findings, indent=2, default=str)
        + "\n\n=== FULL SOURCE CODE ===\n"
        + source_code
    )


def _strip_code_fences(text: str) -> str:
    """Remove markdown code fences models sometimes wrap JSON in.

    Handles both ```json ... ``` and bare ``` ... ``` wrappers. Anything
    else is returned stripped; non-JSON survives to json.loads() and
    fails there (triggering the fallback), which is the correct outcome.
    """
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    first_newline = stripped.find("\n")
    if first_newline == -1:
        return ""  # a bare fence with nothing after it is not JSON
    body = stripped[first_newline + 1 :]
    closing = body.rfind("```")
    if closing != -1:
        body = body[:closing]
    return body.strip()


def _call_llm_api(system_prompt: str, user_prompt: str, api_key: str) -> str:
    """Perform the actual HTTP call to the LLM endpoint.

    Isolated as the single network seam: tests monkeypatch this function,
    so the test suite never touches the network. Uses stdlib urllib only
    (the project has no third-party HTTP dependency). The urlopen timeout
    is the hard cap on the API call itself.
    """
    payload = json.dumps(
        {
            "model": os.environ.get(_ENV_MODEL, _DEFAULT_MODEL),
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        url=os.environ.get(_ENV_API_URL, _DEFAULT_API_URL),
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=_API_TIMEOUT_SECONDS) as response:
        raw_body = response.read().decode("utf-8")
    body = json.loads(raw_body)
    return body["choices"][0]["message"]["content"]


def _minimal_contract() -> dict:
    """Smallest dict that passes validate_schema(); last-resort output."""
    return {
        "health_score": 100,
        "vulnerabilities": [],
        "graphviz_dot_script": "digraph HyperionAttackGraph {}",
        "attack_path_poc": [],
        "recommendations": {
            "immediate_fixes": [],
            "architecture_hardening": [],
            "pipeline_guardrails": [],
        },
        "refactored_code": {"file": "", "language": "", "full_source": ""},
    }


def _fallback(
    scan_findings: list[dict],
    dep_findings: list[dict],
    source_code: str,
    reason: str,
) -> dict:
    """Log the fallback reason and return the deterministic analysis."""
    logger.warning("fallback_triggered: %s", reason)
    result = ai_fallback.generate_fallback_analysis(scan_findings, dep_findings, source_code)
    ok, why = validate_schema(result)
    if ok:
        return result
    # Defensive: ai_fallback's contract makes this unreachable, but this
    # module must never return anything that fails validate_schema().
    logger.warning(
        "fallback output failed schema validation (%s); emitting minimal contract", why
    )
    return _minimal_contract()


def _analyze_impl(
    scan_findings: list[dict],
    dep_findings: list[dict],
    source_code: str,
    api_key: str | None,
) -> dict:
    resolved_key = api_key or os.environ.get(_ENV_API_KEY, "")
    if not resolved_key:
        return _fallback(scan_findings, dep_findings, source_code, "no_api_key")

    user_prompt = _build_user_prompt(scan_findings, dep_findings, source_code)

    try:
        raw_response = _call_llm_api(_SYSTEM_PROMPT, user_prompt, resolved_key)
    except (TimeoutError, socket.timeout) as exc:
        return _fallback(scan_findings, dep_findings, source_code, f"timeout: {exc}")
    except urllib.error.URLError as exc:
        return _fallback(scan_findings, dep_findings, source_code, f"network_error: {exc}")
    except Exception as exc:
        return _fallback(
            scan_findings, dep_findings, source_code,
            f"api_error: {type(exc).__name__}: {exc}",
        )

    if not isinstance(raw_response, str) or not raw_response.strip():
        return _fallback(
            scan_findings, dep_findings, source_code,
            "invalid_json: empty or non-string API response",
        )

    try:
        parsed = json.loads(_strip_code_fences(raw_response))
    except Exception as exc:
        return _fallback(scan_findings, dep_findings, source_code, f"invalid_json: {exc}")

    ok, reason = validate_schema(parsed)
    if not ok:
        return _fallback(
            scan_findings, dep_findings, source_code,
            f"schema_validation_failed: {reason}",
        )

    logger.warning("llm_success")
    return parsed


def analyze_with_llm(
    scan_findings: list[dict],
    dep_findings: list[dict],
    source_code: str,
    api_key: str | None = None,
) -> dict:
    """LLM-backed analysis with a guaranteed safety net.

    Resolution order for the API key: explicit parameter, then the
    HYPERION_LLM_API_KEY environment variable — never hardcoded. Any
    failure mode returns ai_fallback.generate_fallback_analysis(...).
    Never raises; never returns a dict that failed validate_schema().
    """
    try:
        return _analyze_impl(scan_findings, dep_findings, source_code, api_key)
    except Exception as exc:  # absolute guarantee: this function never raises
        return _fallback(
            scan_findings, dep_findings, source_code,
            f"unexpected_error: {type(exc).__name__}: {exc}",
        )


def get_analysis(
    scan_findings: list[dict],
    dep_findings: list[dict],
    source_code: str,
    api_key: str | None = None,
) -> dict:
    """Single entry point for the UI layer; wraps analyze_with_llm."""
    return analyze_with_llm(scan_findings, dep_findings, source_code, api_key=api_key)
