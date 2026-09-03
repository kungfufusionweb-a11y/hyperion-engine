import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import cve_reference
from cve_reference import CVE_REFERENCE_EXAMPLES, format_examples_for_prompt

REQUIRED_KEYS = (
    "cve_id",
    "owasp_category",
    "cvss_score",
    "severity",
    "vulnerability_class",
    "description",
    "general_remediation",
)

VALID_SEVERITIES = ("Critical", "High", "Medium", "Low")


def _expected_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def test_reference_set_is_a_non_empty_list():
    assert isinstance(CVE_REFERENCE_EXAMPLES, list)
    assert 6 <= len(CVE_REFERENCE_EXAMPLES) <= 8


def test_every_entry_has_all_required_keys():
    for entry in CVE_REFERENCE_EXAMPLES:
        missing = [key for key in REQUIRED_KEYS if key not in entry]
        assert not missing, f"entry {entry.get('cve_id', '<unknown>')} missing keys: {missing}"


def test_every_entry_values_are_well_typed():
    for entry in CVE_REFERENCE_EXAMPLES:
        assert isinstance(entry["cve_id"], str) and entry["cve_id"].startswith("CVE-")
        assert isinstance(entry["owasp_category"], str) and entry["owasp_category"]
        assert isinstance(entry["severity"], str)
        assert isinstance(entry["vulnerability_class"], str)
        assert isinstance(entry["description"], str) and entry["description"]
        assert isinstance(entry["general_remediation"], str) and entry["general_remediation"]
        assert isinstance(entry["cvss_score"], (int, float))


def test_vulnerability_class_matches_scanner_vocabulary():
    allowed = {
        "hardcoded_secret",
        "sql_injection",
        "dangerous_call",
        "insecure_deserialization",
    }
    for entry in CVE_REFERENCE_EXAMPLES:
        assert entry["vulnerability_class"] in allowed


@pytest.mark.parametrize("entry", CVE_REFERENCE_EXAMPLES, ids=lambda entry: entry["cve_id"])
def test_cvss_score_in_valid_range(entry):
    score = float(entry["cvss_score"])
    assert 0.0 <= score <= 10.0


@pytest.mark.parametrize("entry", CVE_REFERENCE_EXAMPLES, ids=lambda entry: entry["cve_id"])
def test_severity_is_one_of_allowed_values(entry):
    assert entry["severity"] in VALID_SEVERITIES


@pytest.mark.parametrize("entry", CVE_REFERENCE_EXAMPLES, ids=lambda entry: entry["cve_id"])
def test_severity_consistent_with_cvss_score(entry):
    score = float(entry["cvss_score"])
    assert entry["severity"] == _expected_severity(score)


def test_format_examples_for_prompt_returns_non_empty_string():
    output = format_examples_for_prompt()
    assert isinstance(output, str)
    assert output.strip() != ""


def test_format_examples_for_prompt_contains_every_cve_id():
    output = format_examples_for_prompt()
    for entry in CVE_REFERENCE_EXAMPLES:
        assert entry["cve_id"] in output


def test_format_examples_for_prompt_is_plain_text_not_json():
    output = format_examples_for_prompt()
    assert not output.lstrip().startswith("{")
    assert not output.lstrip().startswith("[")


def test_module_all_exports_expected_symbols():
    assert "CVE_REFERENCE_EXAMPLES" in cve_reference.__all__
    assert "format_examples_for_prompt" in cve_reference.__all__
