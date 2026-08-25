import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai_fallback import generate_fallback_analysis
from schema_validator import validate_schema


def make_valid_vulnerability(**overrides):
    base = {
        "id": "SCAN-001-sql_injection",
        "owasp_category": "A03:2021-Injection",
        "severity": "High",
        "cvss_score": 8.2,
        "line_number": 42,
        "file": "app/db.py",
        "description": "String-built SQL query.",
    }
    base.update(overrides)
    return base


def make_valid_payload():
    return {
        "health_score": 87,
        "vulnerabilities": [make_valid_vulnerability()],
        "graphviz_dot_script": 'digraph G {\n  "a" -> "b";\n}',
        "attack_path_poc": [{"step": 1, "narrative": "Attacker does X."}],
        "recommendations": {
            "immediate_fixes": ["Parameterize the query at app/db.py:42."],
            "architecture_hardening": ["Centralize DB access."],
            "pipeline_guardrails": ["Fail CI on High+ findings."],
        },
        "refactored_code": {
            "file": "app/db.py",
            "language": "python",
            "full_source": "def q(): ...",
        },
    }


class TestFullyValidPayload:
    def test_complete_valid_structure_passes(self):
        ok, reason = validate_schema(make_valid_payload())
        assert ok, reason

    def test_valid_with_multiple_vulnerabilities_and_steps(self):
        payload = make_valid_payload()
        payload["vulnerabilities"] = [
            make_valid_vulnerability(id="SCAN-001-x", severity="Critical", cvss_score=9.5),
            make_valid_vulnerability(id="DEP-001-y", severity="Low", cvss_score=3.1),
        ]
        payload["attack_path_poc"] = [
            {"step": 1, "narrative": "Step one."},
            {"step": 2, "narrative": "Step two."},
        ]
        ok, reason = validate_schema(payload)
        assert ok, reason


class TestMissingTopLevelKeys:
    @pytest.mark.parametrize(
        "key",
        [
            "health_score",
            "vulnerabilities",
            "graphviz_dot_script",
            "attack_path_poc",
            "recommendations",
            "refactored_code",
        ],
    )
    def test_each_missing_top_level_key_fails_naming_it(self, key):
        payload = make_valid_payload()
        del payload[key]
        ok, reason = validate_schema(payload)
        assert not ok
        assert key in reason


class TestWrongTopLevelTypes:
    def test_health_score_as_string(self):
        payload = make_valid_payload()
        payload["health_score"] = "eighty"
        ok, reason = validate_schema(payload)
        assert not ok
        assert "health_score" in reason
        assert "'eighty'" in reason

    def test_health_score_out_of_range(self):
        payload = make_valid_payload()
        payload["health_score"] = 150
        ok, reason = validate_schema(payload)
        assert not ok
        assert "health_score" in reason

    def test_health_score_bool_rejected(self):
        payload = make_valid_payload()
        payload["health_score"] = True
        ok, reason = validate_schema(payload)
        assert not ok
        assert "health_score" in reason

    def test_vulnerabilities_not_a_list(self):
        payload = make_valid_payload()
        payload["vulnerabilities"] = {"not": "a list"}
        ok, reason = validate_schema(payload)
        assert not ok
        assert "vulnerabilities" in reason

    def test_graphviz_wrong_prefix(self):
        payload = make_valid_payload()
        payload["graphviz_dot_script"] = "graph G {}"
        ok, reason = validate_schema(payload)
        assert not ok
        assert "digraph" in reason.lower()

    def test_recommendations_extra_key_rejected(self):
        payload = make_valid_payload()
        payload["recommendations"]["bonus"] = []
        ok, reason = validate_schema(payload)
        assert not ok
        assert "bonus" in reason

    def test_refactored_code_wrong_field_type(self):
        payload = make_valid_payload()
        payload["refactored_code"]["language"] = 42
        ok, reason = validate_schema(payload)
        assert not ok
        assert "refactored_code.language" in reason


class TestVulnerabilityDetails:
    def test_invalid_severity_names_index_and_value(self):
        payload = make_valid_payload()
        payload["vulnerabilities"].append(make_valid_vulnerability(severity="SEVERE"))
        ok, reason = validate_schema(payload)
        assert not ok
        assert "vulnerabilities[1].severity" in reason
        assert "SEVERE" in reason
        assert "Critical/High/Medium/Low" in reason

    def test_cvss_out_of_range(self):
        payload = make_valid_payload()
        payload["vulnerabilities"][0]["cvss_score"] = 11.5
        ok, reason = validate_schema(payload)
        assert not ok
        assert "vulnerabilities[0].cvss_score" in reason

    def test_line_number_as_string(self):
        payload = make_valid_payload()
        payload["vulnerabilities"][0]["line_number"] = "42"
        ok, reason = validate_schema(payload)
        assert not ok
        assert "vulnerabilities[0].line_number" in reason

    def test_vulnerability_entry_not_a_dict(self):
        payload = make_valid_payload()
        payload["vulnerabilities"].append("oops")
        ok, reason = validate_schema(payload)
        assert not ok
        assert "vulnerabilities[1]" in reason

    def test_vulnerability_missing_key_named(self):
        payload = make_valid_payload()
        del payload["vulnerabilities"][0]["owasp_category"]
        ok, reason = validate_schema(payload)
        assert not ok
        assert "vulnerabilities[0]" in reason
        assert "owasp_category" in reason


class TestEmptyCollectionsAreValid:
    def test_empty_vulnerabilities_passes(self):
        payload = make_valid_payload()
        payload["vulnerabilities"] = []
        ok, reason = validate_schema(payload)
        assert ok, reason

    def test_empty_attack_path_poc_passes(self):
        payload = make_valid_payload()
        payload["attack_path_poc"] = []
        ok, reason = validate_schema(payload)
        assert ok, reason

    def test_empty_recommendation_sublists_pass(self):
        payload = make_valid_payload()
        payload["recommendations"] = {
            "immediate_fixes": [],
            "architecture_hardening": [],
            "pipeline_guardrails": [],
        }
        ok, reason = validate_schema(payload)
        assert ok, reason


class TestDegenerateInputs:
    def test_none_input_fails_cleanly(self):
        ok, reason = validate_schema(None)
        assert not ok
        assert reason

    def test_empty_dict_fails_cleanly(self):
        ok, reason = validate_schema({})
        assert not ok
        assert reason

    def test_non_dict_input_fails_cleanly(self):
        for bad in ([], "string", 42, object()):
            ok, reason = validate_schema(bad)
            assert not ok
            assert reason


class TestFallbackIntegration:
    @pytest.mark.parametrize(
        "scan_findings,dep_findings,source",
        [
            ([], [], ""),
            (
                [{"pattern_type": "sql_injection", "line_number": 7, "file": "db.py", "snippet": "q=f'SELECT {x}'"}],
                [],
                "x = input()\nq=f'SELECT {x}'\n",
            ),
            (
                [{"pattern_type": "hardcoded_secret", "confidence": "low", "line_number": 3, "file": "cfg.py", "snippet": "KEY='x'"}],
                [{"package": "requests", "installed_version": "2.19.0", "vuln_id": "GHSA-123", "summary": "CVE proxy"}],
                "KEY='x'\n",
            ),
        ],
    )
    def test_fallback_output_always_validates(self, scan_findings, dep_findings, source):
        result = generate_fallback_analysis(scan_findings, dep_findings, source)
        ok, reason = validate_schema(result)
        assert ok, reason
