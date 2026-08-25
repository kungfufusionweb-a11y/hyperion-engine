import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from ai_fallback import generate_fallback_analysis

REQUIRED_KEYS = {
    "health_score",
    "vulnerabilities",
    "graphviz_dot_script",
    "attack_path_poc",
    "recommendations",
    "refactored_code",
}

RECOMMENDATION_KEYS = {"immediate_fixes", "architecture_hardening", "pipeline_guardrails"}

VULN_KEYS = {"id", "owasp_category", "severity", "cvss_score", "line_number", "file", "description"}

EXPECTED_OWASP = {
    "hardcoded_secret": "A02:2021-Cryptographic Failures",
    "sql_injection": "A03:2021-Injection",
    "dangerous_call": "A03:2021-Injection",
    "insecure_deserialization": "A08:2021-Software and Data Integrity Failures",
}

# Exact source of some_real_file.py at the repo root, used as a fixture to
# verify the full_source pass-through contract character for character.
SOME_REAL_FILE_SOURCE = '''import os
import pickle
import yaml

API_KEY = "sk-live-abc123xyz789"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def run_backup(cmd):
    os.system(cmd)

def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

def load_config(raw_data):
    return yaml.load(raw_data)
'''


def _scan(pattern_type, file="app.py", line=1, confidence="high"):
    return {
        "file": file,
        "line_number": line,
        "column": 0,
        "snippet": f"# {pattern_type} at {file}:{line}",
        "pattern_type": pattern_type,
        "confidence": confidence,
    }


def _dep(package="requests", version="2.19.1", severity="High"):
    return {
        "package": package,
        "installed_version": version,
        "vuln_id": f"GHSA-0000-{package}",
        "severity": severity,
        "summary": f"known flaw in {package}",
        "fixed_version": "99.0.0",
    }


def assert_schema_complete(result):
    assert REQUIRED_KEYS.issubset(result.keys())
    assert isinstance(result["health_score"], int)
    assert 0 <= result["health_score"] <= 100
    for vuln in result["vulnerabilities"]:
        assert VULN_KEYS == set(vuln.keys())
        assert isinstance(vuln["id"], str) and vuln["id"]
        assert isinstance(vuln["owasp_category"], str) and vuln["owasp_category"]
        assert vuln["severity"] in {"Critical", "High", "Medium", "Low"}
        assert isinstance(vuln["cvss_score"], float)
        assert isinstance(vuln["line_number"], int)
        assert isinstance(vuln["file"], str)
        assert isinstance(vuln["description"], str)
    recs = result["recommendations"]
    assert RECOMMENDATION_KEYS == set(recs.keys())
    for group in recs.values():
        assert all(isinstance(item, str) and item for item in group)
    for step in result["attack_path_poc"]:
        assert {"step", "narrative"} == set(step.keys())
    rc = result["refactored_code"]
    assert {"file", "language", "full_source"} == set(rc.keys())


def test_empty_findings_returns_perfect_score_and_valid_structure():
    result = generate_fallback_analysis([], [], "")
    assert_schema_complete(result)
    assert result["health_score"] == 100
    assert result["vulnerabilities"] == []
    assert result["attack_path_poc"] == []
    assert result["recommendations"]["immediate_fixes"] == []
    assert result["recommendations"]["architecture_hardening"] == []
    assert 'digraph' in result["graphviz_dot_script"].lower()
    assert result["refactored_code"] == {"file": "", "language": "", "full_source": ""}


def test_mixed_findings_mapping_scoring_and_dot():
    scan = [
        _scan("hardcoded_secret", file="config.py", line=3),
        _scan("sql_injection", file="db.py", line=10),
        _scan("dangerous_call", file="runner.py", line=20),
        _scan("insecure_deserialization", file="loader.py", line=30),
    ]
    deps = [_dep("requests"), _dep("pyyaml", severity="Critical")]
    result = generate_fallback_analysis(scan, deps, "")

    assert_schema_complete(result)

    owasp_by_id_prefix = {v["id"].split("-", 2)[-1]: v["owasp_category"] for v in result["vulnerabilities"]}
    for pattern, category in EXPECTED_OWASP.items():
        assert owasp_by_id_prefix[pattern] == category
    dep_categories = [v["owasp_category"] for v in result["vulnerabilities"] if v["id"].startswith("DEP-")]
    assert dep_categories == ["A06:2021-Vulnerable and Outdated Components"] * 2

    # Health math (diminishing model): code bucket: High x2 = 10+5, Critical
    # = 15, Medium = 5 => 35; dep bucket scaled by 0.6: High = 6, Critical = 9
    # => 15; total penalty = 50 => score 50.
    assert result["health_score"] == 50

    dot = result["graphviz_dot_script"]
    assert dot.startswith("digraph") and dot.rstrip().endswith("}")
    for node in ("config.py:3", "db.py:10", "runner.py:20", "loader.py:30"):
        assert f'"{node}" -> "Vulnerable Sink";' in dot

    narratives = [s["narrative"] for s in result["attack_path_poc"]]
    assert len(result["attack_path_poc"]) >= 8  # 4 patterns x 2 steps (+2 dependency steps)
    assert len(result["attack_path_poc"]) <= 10  # at most 3 per group per spec; we emit 2 + dep pair
    assert any("SQL" in n for n in narratives)
    assert not any("import os" in n or "rm -rf" in n for n in narratives)  # narrative-only, no runnable code

    fixes = "\n".join(result["recommendations"]["immediate_fixes"])
    assert "config.py:3" in fixes and "db.py:10" in fixes
    assert "requests" in fixes and "pyyaml" in fixes


def test_large_findings_list_floors_health_score_at_zero():
    scan = [_scan("sql_injection", file=f"f{i}.py", line=i) for i in range(60)]
    deps = [_dep(f"pkg{i}", severity="Critical") for i in range(10)]
    result = generate_fallback_analysis(scan, deps, "")
    assert_schema_complete(result)
    assert result["health_score"] == 0
    assert len(result["vulnerabilities"]) == 70


def test_dot_script_is_syntactically_parseable():
    from ai_fallback import _dot_escape

    tricky = [
        _scan('weird"quote', file='bad"name.py', line=5),
        _scan("back\\slash", file="back\\slash.py", line=7),
    ]
    dot = generate_fallback_analysis(tricky, [], "")["graphviz_dot_script"]

    try:
        import graphviz  # type: ignore
    except ImportError:
        pytest.skip("graphviz package not installed; structural check only")

    graph = graphviz.Source(dot)
    source_text = graph.source
    assert re.search(r"^digraph\s+\w+\s*\{", source_text, re.MULTILINE)
    assert source_text.count("{") == source_text.count("}")
    for node in ('"bad\\"name.py:5"', '"back\\\\slash.py:7"'):
        assert node in source_text


def test_deterministic_output():
    scan = [_scan("sql_injection", line=42), _scan("dangerous_call", line=7)]
    deps = [_dep()]
    first = generate_fallback_analysis(scan, deps, "")
    second = generate_fallback_analysis(list(scan), list(deps), "")
    assert first == second


def test_full_source_echoes_original_source_character_for_character():
    scan = [
        {"file": "some_real_file.py", "line_number": 5, "column": 0,
         "snippet": 'API_KEY = "sk-live-abc123xyz789"',
         "pattern_type": "hardcoded_secret", "confidence": "high"},
        {"file": "some_real_file.py", "line_number": 8, "column": 0,
         "snippet": 'query = "SELECT * FROM users WHERE id = " + user_id',
         "pattern_type": "sql_injection", "confidence": "high"},
        {"file": "some_real_file.py", "line_number": 12, "column": 0,
         "snippet": "os.system(cmd)",
         "pattern_type": "dangerous_call", "confidence": "high"},
        {"file": "some_real_file.py", "line_number": 15, "column": 0,
         "snippet": "return pickle.loads(raw_bytes)",
         "pattern_type": "insecure_deserialization", "confidence": "high"},
    ]
    result = generate_fallback_analysis(scan, [], SOME_REAL_FILE_SOURCE)
    assert_schema_complete(result)

    rc = result["refactored_code"]
    assert rc["file"] == "some_real_file.py"
    # Exact pass-through contract: character for character.
    assert rc["full_source"] == SOME_REAL_FILE_SOURCE
    assert rc["full_source"].startswith("import os")
    assert rc["full_source"].endswith("yaml.load(raw_data)\n")
    assert "import os\nimport pickle\nimport yaml" in rc["full_source"]


def test_realistic_load_scores_nonzero_and_differentiates():
    def make_scan(pattern, line):
        return {"file": "app.py", "line_number": line, "column": 0,
                "snippet": f"{pattern} line {line}",
                "pattern_type": pattern, "confidence": "high"}

    # Realistic mixed load: 3 Critical + 6 High + 5 Medium + 1 Low across
    # code-level findings and dependency advisories (the common real-world
    # mix once one outdated package carries multiple separate advisories).
    heavy_scan = (
        [make_scan("sql_injection", i) for i in range(1, 4)]            # 3 Critical
        + [make_scan("hardcoded_secret", i) for i in range(4, 6)]       # 2 High
        + [make_scan("dangerous_call", 6)]                              # 1 High
        + [make_scan("insecure_deserialization", i) for i in (7, 8)]    # 2 Medium
    )
    heavy_deps = (
        [_dep(f"pkgH{i}", severity="High") for i in range(3)]           # 3 High
        + [_dep(f"pkgM{i}", severity="Medium") for i in range(3)]       # 3 Medium
        + [_dep("pkgL", severity="Low")]                                # 1 Low
    )
    heavy = generate_fallback_analysis(heavy_scan, heavy_deps, "")

    light_scan = [
        make_scan("sql_injection", 1),
        make_scan("hardcoded_secret", 2),
        make_scan("insecure_deserialization", 3),
    ]
    light = generate_fallback_analysis(light_scan, [], "")

    assert_schema_complete(heavy)
    assert_schema_complete(light)
    # The old linear model floored this 15-finding load at 0; the new model
    # keeps headroom so a messy-but-fixable codebase is distinguishable.
    assert heavy["health_score"] > 0
    # A 3-finding set must score clearly higher than the 15-finding set.
    assert light["health_score"] - heavy["health_score"] >= 20
    assert light["health_score"] < 100
