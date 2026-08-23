import logging
import pathlib
import sys
import urllib.request

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import dependency_check
from dependency_check import (
    check_dependencies_with_status,
    parse_requirements,
)

_OSV_PROBE_URL = "https://api.osv.dev/v1/query"
_probe_result: bool | None = None


def osv_reachable() -> bool:
    global _probe_result
    if _probe_result is None:
        try:
            request = urllib.request.Request(
                _OSV_PROBE_URL,
                data=b'{"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "version": "6.0.1"}',
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                _probe_result = response.status == 200
        except OSError:
            _probe_result = False
    return _probe_result


def write_requirements(tmp_path, content):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(content, encoding="utf-8")
    return str(req_file)


def test_parse_requirements_handles_pins_and_skips_garbage():
    text = (
        "# top comment\n"
        "pyyaml==5.3\n"
        "flask>=0.12\n"
        "requests~=2.28.0\n"
        "unpinned-package\n"
        "\n"
        "  \n"
        "garbage line here\n"
        "not-a-version===\n"
        "django==4.2 ; python_version < '3.12'\n"
    )
    pins = parse_requirements(text)
    assert ("pyyaml", "5.3") in pins
    assert ("flask", "0.12") in pins
    assert ("requests", "2.28.0") in pins
    assert ("django", "4.2") in pins
    assert all(name not in {"unpinned-package"} for name, _ in pins)
    assert len(pins) == 4


def test_known_vulnerable_package_returns_findings(tmp_path):
    if not osv_reachable():
        pytest.skip("OSV.dev unreachable; no network in test environment")
    path = write_requirements(tmp_path, "pyyaml==5.3\n")
    findings, offline_mode = check_dependencies_with_status(path)
    assert offline_mode is False
    vulnerable = [f for f in findings if f["package"] == "pyyaml"]
    assert len(vulnerable) >= 1
    for finding in vulnerable:
        assert set(finding) == {
            "package",
            "installed_version",
            "vuln_id",
            "severity",
            "summary",
            "fixed_version",
        }
        assert finding["installed_version"] == "5.3"
        assert finding["vuln_id"]
        assert finding["fixed_version"] is None or isinstance(finding["fixed_version"], str)


def test_recent_pin_has_no_false_positives(tmp_path):
    if not osv_reachable():
        pytest.skip("OSV.dev unreachable; no network in test environment")
    path = write_requirements(tmp_path, "pyyaml==6.0.1\n")
    findings, offline_mode = check_dependencies_with_status(path)
    assert offline_mode is False
    assert [f for f in findings if f["package"] == "pyyaml"] == []


def test_malformed_lines_do_not_crash(tmp_path, monkeypatch):
    def fake_query_osv(name, version):
        return []

    monkeypatch.setattr(dependency_check, "_query_osv", fake_query_osv)
    content = (
        "total garbage !!!\n"
        "broken===\n"
        "==1.0\n"
        "-e git+https://example.com/repo.git#egg=x\n"
        "--index-url https://pypi.org/simple\n"
        "pyyaml==5.3 # inline comment\n"
        "https://example.com/pkg.whl\n"
    )
    path = write_requirements(tmp_path, content)
    findings, offline_mode = check_dependencies_with_status(path)
    assert findings == []
    assert offline_mode is False


def test_total_network_failure_reports_offline_mode(tmp_path, monkeypatch):
    import urllib.error

    def failing_query_osv(name, version):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(dependency_check, "_query_osv", failing_query_osv)
    path = write_requirements(tmp_path, "pyyaml==5.3\n")
    findings, offline_mode = check_dependencies_with_status(path)
    assert findings == []
    assert offline_mode is True


def test_partial_failure_is_not_offline_mode(tmp_path, monkeypatch):
    import urllib.error

    def half_failing_query_osv(name, version):
        if name == "flask":
            raise urllib.error.URLError("timeout")
        return []

    monkeypatch.setattr(dependency_check, "_query_osv", half_failing_query_osv)
    path = write_requirements(tmp_path, "pyyaml==5.3\nflask==0.12\n")
    findings, offline_mode = check_dependencies_with_status(path)
    assert findings == []
    assert offline_mode is False


# ---------------------------------------------------------------------------
# Regression tests for the three manual-testing bugs
# ---------------------------------------------------------------------------


def test_per_package_lookup_failure_is_visible_not_silent(tmp_path, monkeypatch, caplog):
    # Previously a per-package exception (e.g. HTTPError for pyyaml) was
    # swallowed and the package silently vanished from results.
    import urllib.error

    def failing_for_pyyaml(name, version):
        if name == "pyyaml":
            raise urllib.error.HTTPError(
                url="https://api.osv.dev/v1/query",
                code=500,
                msg="Internal Server Error",
                hdrs=None,
                fp=None,
            )
        return []

    monkeypatch.setattr(dependency_check, "_query_osv", failing_for_pyyaml)
    path = write_requirements(tmp_path, "pyyaml==5.3\nrequests==2.25.0\n")

    with caplog.at_level(logging.WARNING, logger="dependency_check"):
        findings, offline_mode = check_dependencies_with_status(path)

    assert offline_mode is False  # requests succeeded, so not fully offline
    failures = [r for r in caplog.records if "pyyaml" in r.getMessage()]
    assert failures, "expected a logged warning for the failed pyyaml lookup"
    assert "lookup_failed" in failures[0].getMessage()
    # The failure must not be misreported as "everything is clean" without trace


def test_aliased_vulns_are_deduplicated_with_ghsa_preferred(tmp_path, monkeypatch):
    aliased = [
        {
            "id": "PYSEC-2020-150",
            "aliases": ["CVE-2020-1747", "GHSA-875f-wpq8-q2c7"],
            "database_specific": {"severity": "HIGH"},
            "summary": "PyYAML arbitrary code execution",
            "affected": [
                {
                    "package": {"name": "pyyaml", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "5.3.1"}]}],
                }
            ],
        },
        {
            "id": "GHSA-875f-wpq8-q2c7",
            "aliases": ["CVE-2020-1747", "PYSEC-2020-150"],
            "database_specific": {"severity": "HIGH"},
            "summary": "PyYAML arbitrary code execution",
            "affected": [
                {
                    "package": {"name": "pyyaml", "ecosystem": "PyPI"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "5.4"}]}],
                }
            ],
        },
        {
            "id": "CVE-2020-1747",
            "aliases": ["GHSA-875f-wpq8-q2c7", "PYSEC-2020-150"],
            "summary": "PyYAML arbitrary code execution",
        },
    ]

    monkeypatch.setattr(dependency_check, "_query_osv", lambda name, version: list(aliased))
    path = write_requirements(tmp_path, "pyyaml==5.3\n")
    findings, offline_mode = check_dependencies_with_status(path)

    assert offline_mode is False
    assert len(findings) == 1, f"expected one deduped finding, got {findings}"
    assert findings[0]["vuln_id"] == "GHSA-875f-wpq8-q2c7"
    assert findings[0]["severity"] == "High"


def test_dedup_falls_back_to_pysec_then_cve_when_no_ghsa(tmp_path, monkeypatch):
    no_ghsa = [
        {
            "id": "CVE-2017-18342",
            "aliases": ["PYSEC-2018-62"],
            "summary": "Flask vulnerable",
        },
        {
            "id": "PYSEC-2018-62",
            "aliases": ["CVE-2017-18342"],
            "summary": "Flask vulnerable",
        },
    ]
    monkeypatch.setattr(dependency_check, "_query_osv", lambda name, version: list(no_ghsa))
    path = write_requirements(tmp_path, "flask==0.12\n")
    findings, _ = check_dependencies_with_status(path)
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "PYSEC-2018-62"


@pytest.mark.parametrize(
    "severity_entry, expected",
    [
        (
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
            "Critical",
        ),
        (
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            "Medium",
        ),
        ({"type": "CVSS_V3", "score": "6.1"}, "Medium"),
        ({"type": "CVSS_V2", "score": "garbage"}, "Unknown"),
    ],
)
def test_severity_from_cvss_vector_is_a_level_not_the_type_string(
    tmp_path, monkeypatch, severity_entry, expected
):
    vulns = [
        {
            "id": "GHSA-test-0001",
            "severity": [severity_entry],
            "summary": "test vuln with only CVSS data",
        }
    ]
    monkeypatch.setattr(dependency_check, "_query_osv", lambda name, version: list(vulns))
    path = write_requirements(tmp_path, "pyyaml==5.3\n")
    findings, _ = check_dependencies_with_status(path)

    assert len(findings) == 1
    severity = findings[0]["severity"]
    assert severity in {"Critical", "High", "Medium", "Low", "Unknown"}
    assert not severity.upper().startswith("CVSS"), (
        f"severity must be a level, never the scoring system type; got {severity}"
    )
    if expected != "Unknown":
        assert severity == expected


def test_database_specific_severity_preferred_over_cvss_parsing(tmp_path, monkeypatch):
    vulns = [
        {
            "id": "GHSA-test-0002",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
            "database_specific": {"severity": "MODERATE"},
            "summary": "db-specific level wins",
        }
    ]
    monkeypatch.setattr(dependency_check, "_query_osv", lambda name, version: list(vulns))
    path = write_requirements(tmp_path, "pyyaml==5.3\n")
    findings, _ = check_dependencies_with_status(path)
    assert findings[0]["severity"] == "Medium"


def test_empty_summary_falls_back_to_truncated_details(tmp_path, monkeypatch):
    details_text = " ".join(["detail word"] * 60)
    vulns = [
        {"id": "GHSA-test-0003", "summary": "", "details": details_text},
        {"id": "GHSA-test-0004", "summary": None, "details": "short detail"},
        {"id": "GHSA-test-0005", "summary": "", "details": ""},
    ]
    monkeypatch.setattr(dependency_check, "_query_osv", lambda name, version: list(vulns))
    path = write_requirements(tmp_path, "pyyaml==5.3\n")
    findings, _ = check_dependencies_with_status(path)

    by_id = {f["vuln_id"]: f for f in findings}
    assert len(by_id["GHSA-test-0003"]["summary"]) <= dependency_check._SUMMARY_MAX_LENGTH
    assert by_id["GHSA-test-0003"]["summary"].startswith("detail word")
    assert by_id["GHSA-test-0004"]["summary"] == "short detail"
    assert by_id["GHSA-test-0005"]["summary"] == ""


# ---------------------------------------------------------------------------
# Regression: real pyyaml==5.3 OSV response shape (CVE-2020-1747)
# ---------------------------------------------------------------------------

_PYYAML_53_GHSA_RECORD = {
    "id": "GHSA-6757-jp84-gxfx",
    "summary": "Improper Input Validation in PyYAML",
    "details": "In PyYAML before 5.3.1, the full_load() and full_load_all() "
    "functions could execute arbitrary code.",
    "aliases": ["CVE-2020-1747", "PYSEC-2020-96"],
    "modified": "2023-01-09T05:09:53Z",
    "published": "2020-07-31T17:15:00Z",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [
        {
            "package": {"name": "pyyaml", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "5.3.1"}]}],
        }
    ],
}


def test_real_pyyaml_ghsa_id_record_is_not_lost(tmp_path, monkeypatch):
    # Exact real response shape for pyyaml==5.3: the canonical id is itself
    # a GHSA (NOT duplicated inside aliases — aliases only holds CVE+PYSEC)
    # and database_specific.severity is uppercase "CRITICAL".
    monkeypatch.setattr(
        dependency_check,
        "_query_osv",
        lambda name, version: [dict(_PYYAML_53_GHSA_RECORD)],
    )
    path = write_requirements(tmp_path, "pyyaml==5.3\n")
    findings, offline_mode = check_dependencies_with_status(path)

    assert offline_mode is False
    assert len(findings) == 1, f"expected exactly one finding, got {findings}"
    finding = findings[0]
    assert finding["package"] == "pyyaml"
    assert finding["installed_version"] == "5.3"
    assert finding["vuln_id"] == "GHSA-6757-jp84-gxfx"
    assert finding["severity"] == "Critical"
    assert finding["fixed_version"] == "5.3.1"


def test_utf8_bom_requirements_file_does_not_lose_first_pin(tmp_path, monkeypatch):
    # PowerShell writes requirements files with a leading UTF-8 BOM. The BOM
    # used to glue onto the first package name, the pin regex silently
    # skipped it, and no OSV query ever ran for that package.
    monkeypatch.setattr(
        dependency_check,
        "_query_osv",
        lambda name, version: [dict(_PYYAML_53_GHSA_RECORD)],
    )
    req_file = tmp_path / "requirements.txt"
    req_file.write_bytes(b"\xef\xbb\xbfpyyaml==5.3\r\n")
    findings, offline_mode = check_dependencies_with_status(str(req_file))

    assert offline_mode is False
    assert len(findings) == 1
    assert findings[0]["vuln_id"] == "GHSA-6757-jp84-gxfx"
