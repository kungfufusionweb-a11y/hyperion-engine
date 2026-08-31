import json
import logging
import pathlib
import sys
import urllib.error

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import ai_llm
from ai_fallback import generate_fallback_analysis
from schema_validator import validate_schema

# Every test monkeypatches ai_llm._call_llm_api: no real network calls.

SAMPLE_SOURCE = '''import os
import pickle

API_KEY = "sk-live-abc123xyz789"


def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)


def load_data(raw_bytes):
    return pickle.loads(raw_bytes)
'''

SAMPLE_SCAN_FINDINGS = [
    {
        "file": "app.py",
        "line_number": 4,
        "column": 0,
        "snippet": 'API_KEY = "sk-live-abc123xyz789"',
        "pattern_type": "hardcoded_secret",
        "confidence": "high",
    },
    {
        "file": "app.py",
        "line_number": 8,
        "column": 0,
        "snippet": 'query = "SELECT * FROM users WHERE id = " + user_id',
        "pattern_type": "sql_injection",
        "confidence": "high",
    },
    {
        "file": "app.py",
        "line_number": 13,
        "column": 0,
        "snippet": "return pickle.loads(raw_bytes)",
        "pattern_type": "insecure_deserialization",
        "confidence": "medium",
    },
]

SAMPLE_DEP_FINDINGS = [
    {
        "package": "pyyaml",
        "installed_version": "5.3",
        "vuln_id": "GHSA-0000-pyyaml",
        "severity": "High",
        "summary": "unsafe yaml.load allows arbitrary code execution",
        "fixed_version": "5.4",
    }
]

API_KEY = "test-api-key-not-real"


def _valid_llm_response():
    """A complete response dict that passes validate_schema()."""
    return {
        "health_score": 35,
        "vulnerabilities": [
            {
                "id": "LLM-001-sql_injection",
                "owasp_category": "A03:2021-Injection",
                "severity": "Critical",
                "cvss_score": 9.1,
                "line_number": 8,
                "file": "app.py",
                "description": "User-controlled input concatenated directly into a SQL statement.",
            },
            {
                "id": "LLM-002-hardcoded_secret",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "severity": "High",
                "cvss_score": 7.5,
                "line_number": 4,
                "file": "app.py",
                "description": "Live API key embedded directly in source code.",
            },
        ],
        "graphviz_dot_script": (
            "digraph HyperionAttackGraph {\n"
            "  rankdir=LR;\n"
            '  "attacker input" -> "sql_injection" -> "database";\n'
            "}"
        ),
        "attack_path_poc": [
            {
                "step": 1,
                "narrative": "An attacker supplies a crafted identifier that is concatenated into the SQL statement without sanitization.",
            },
            {
                "step": 2,
                "narrative": "The altered query executes and exposes records outside the statement's intended scope.",
            },
        ],
        "recommendations": {
            "immediate_fixes": [
                "Replace string-built SQL with parameterized queries.",
                "Move the API key to a secrets manager or environment variable.",
            ],
            "architecture_hardening": [
                "Route all database access through a parameterizing data-access layer.",
            ],
            "pipeline_guardrails": [
                "Fail CI on any new finding of severity High or above.",
            ],
        },
        "refactored_code": {
            "file": "app.py",
            "language": "python",
            "full_source": SAMPLE_SOURCE,
        },
    }


def _mock_api(monkeypatch, response=None, exc=None):
    """Replace ai_llm._call_llm_api; record (system, user, key) per call."""
    calls = []

    def fake_call(system_prompt, user_prompt, api_key):
        calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "api_key": api_key,
            }
        )
        if exc is not None:
            raise exc
        return response

    monkeypatch.setattr(ai_llm, "_call_llm_api", fake_call)
    return calls


def _analyze(monkeypatch, response=None, exc=None, api_key=API_KEY):
    _mock_api(monkeypatch, response=response, exc=exc)
    return ai_llm.analyze_with_llm(
        SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=api_key
    )


def _assert_fallback_holds(result, caplog):
    """The safety net: fallback output is schema-valid and was logged."""
    ok, reason = validate_schema(result)
    assert ok, f"fallback result failed validate_schema: {reason}"
    assert result == generate_fallback_analysis(
        SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE
    )
    assert "fallback_triggered" in caplog.text
    assert "llm_success" not in caplog.text


# --- happy paths -------------------------------------------------------------


def test_valid_llm_response_parsed_and_returned_as_is(monkeypatch, caplog):
    valid = _valid_llm_response()
    calls = _mock_api(monkeypatch, response=json.dumps(valid))
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = ai_llm.analyze_with_llm(
            SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=API_KEY
        )
    assert result == valid
    ok, reason = validate_schema(result)
    assert ok, reason
    assert len(calls) == 1
    assert calls[0]["api_key"] == API_KEY
    assert "llm_success" in caplog.text


def test_json_wrapped_in_markdown_fences_is_parsed(monkeypatch, caplog):
    valid = _valid_llm_response()
    fenced = "```json\n" + json.dumps(valid) + "\n```"
    _mock_api(monkeypatch, response=fenced)
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = ai_llm.analyze_with_llm(
            SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=API_KEY
        )
    assert result == valid
    assert "llm_success" in caplog.text


def test_plain_code_fence_without_language_tag_is_parsed(monkeypatch, caplog):
    valid = _valid_llm_response()
    fenced = "```\n" + json.dumps(valid) + "\n```"
    _mock_api(monkeypatch, response=fenced)
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = ai_llm.analyze_with_llm(
            SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=API_KEY
        )
    assert result == valid


# --- fallback paths ----------------------------------------------------------


def test_schema_invalid_severity_triggers_fallback(monkeypatch, caplog):
    broken = _valid_llm_response()
    broken["vulnerabilities"][0]["severity"] = "Severe"  # not Critical/High/Medium/Low
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = _analyze(monkeypatch, response=json.dumps(broken))
    _assert_fallback_holds(result, caplog)
    assert "schema_validation_failed" in caplog.text


def test_invalid_json_triggers_fallback(monkeypatch, caplog):
    garbage = "Sorry, here is my analysis as prose instead: { score = 35 }"
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = _analyze(monkeypatch, response=garbage)
    _assert_fallback_holds(result, caplog)
    assert "invalid_json" in caplog.text


def test_timeout_triggers_fallback(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = _analyze(monkeypatch, exc=TimeoutError("simulated 60s timeout"))
    _assert_fallback_holds(result, caplog)
    assert "timeout" in caplog.text


@pytest.mark.parametrize(
    "exc",
    [
        urllib.error.URLError(ConnectionRefusedError("connection refused")),
        ConnectionError("simulated connection reset"),
        RuntimeError("simulated unexpected API failure"),
    ],
    ids=["urlerror", "connection-error", "unexpected-error"],
)
def test_network_or_api_error_triggers_fallback(monkeypatch, caplog, exc):
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = _analyze(monkeypatch, exc=exc)
    _assert_fallback_holds(result, caplog)


# --- API key resolution --------------------------------------------------------


def test_missing_api_key_triggers_fallback_without_api_call(monkeypatch, caplog):
    monkeypatch.delenv("HYPERION_LLM_API_KEY", raising=False)
    calls = _mock_api(monkeypatch, response=json.dumps(_valid_llm_response()))
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = ai_llm.analyze_with_llm(
            SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=None
        )
    _assert_fallback_holds(result, caplog)
    assert calls == []  # never reached the network
    assert "no_api_key" in caplog.text


def test_api_key_read_from_environment(monkeypatch, caplog):
    monkeypatch.setenv("HYPERION_LLM_API_KEY", "env-provided-key")
    calls = _mock_api(monkeypatch, response=json.dumps(_valid_llm_response()))
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = ai_llm.analyze_with_llm(
            SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=None
        )
    assert "llm_success" in caplog.text
    assert calls[0]["api_key"] == "env-provided-key"
    ok, _ = validate_schema(result)
    assert ok


def test_explicit_api_key_takes_precedence_over_environment(monkeypatch):
    monkeypatch.setenv("HYPERION_LLM_API_KEY", "env-provided-key")
    calls = _mock_api(monkeypatch, response=json.dumps(_valid_llm_response()))
    ai_llm.analyze_with_llm(
        SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=API_KEY
    )
    assert calls[0]["api_key"] == API_KEY


# --- prompt construction -------------------------------------------------------


def test_prompt_is_single_batched_message_with_all_context(monkeypatch):
    calls = _mock_api(monkeypatch, response=json.dumps(_valid_llm_response()))
    ai_llm.analyze_with_llm(
        SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=API_KEY
    )
    system_prompt = calls[0]["system_prompt"]
    user_prompt = calls[0]["user_prompt"]
    # System prompt: strict JSON-only contract + safety rules.
    assert "ONLY valid JSON" in system_prompt
    assert "markdown code fences" in system_prompt
    assert "narrative and educational ONLY" in system_prompt
    assert "runnable exploit code" in system_prompt
    assert "COMPLETE corrected file" in system_prompt
    assert "ONE concise sentence" in system_prompt
    assert "AT MOST 5 steps" in system_prompt
    # User prompt: one batched message with all three inputs.
    assert "STATIC SCANNER FINDINGS" in user_prompt
    assert "DEPENDENCY VULNERABILITY FINDINGS" in user_prompt
    assert "FULL SOURCE CODE" in user_prompt
    assert SAMPLE_SOURCE in user_prompt
    assert "hardcoded_secret" in user_prompt
    assert "pyyaml" in user_prompt


# --- UI entry point ------------------------------------------------------------


def test_get_analysis_is_thin_wrapper_around_analyze_with_llm(monkeypatch):
    valid = _valid_llm_response()
    _mock_api(monkeypatch, response=json.dumps(valid))
    via_wrapper = ai_llm.get_analysis(
        SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=API_KEY
    )
    via_direct = ai_llm.analyze_with_llm(
        SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=API_KEY
    )
    assert via_wrapper == valid
    assert via_wrapper == via_direct


def test_get_analysis_falls_back_safely_too(monkeypatch, caplog):
    _mock_api(monkeypatch, exc=TimeoutError("simulated timeout"))
    with caplog.at_level(logging.WARNING, logger="hyperion.ai_llm"):
        result = ai_llm.get_analysis(
            SAMPLE_SCAN_FINDINGS, SAMPLE_DEP_FINDINGS, SAMPLE_SOURCE, api_key=API_KEY
        )
    _assert_fallback_holds(result, caplog)
