# Graph Report - Hyperion Engine  (2026-08-31)

## Corpus Check
- 26 files · ~11,024 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 229 nodes · 505 edges · 17 communities (16 shown, 1 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS · INFERRED: 1 edges (avg confidence: 0.5)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `7827b116`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_generate_fallback_analysis|generate_fallback_analysis]]
- [[_COMMUNITY_validate_schema|validate_schema]]
- [[_COMMUNITY__VulnerabilityVisitor|_VulnerabilityVisitor]]
- [[_COMMUNITY_dependency_check.py|dependency_check.py]]
- [[_COMMUNITY_check_dependencies_with_status|check_dependencies_with_status]]
- [[_COMMUNITY_test_ai_llm.py|test_ai_llm.py]]
- [[_COMMUNITY_scan_source|scan_source]]
- [[_COMMUNITY_ai_llm.py|ai_llm.py]]
- [[_COMMUNITY_schema_validator.py|schema_validator.py]]
- [[_COMMUNITY_🛡️ Hyperion Engine|🛡️ Hyperion Engine]]
- [[_COMMUNITY_AGENTS|AGENTS.md]]

## God Nodes (most connected - your core abstractions)
1. `validate_schema()` - 34 edges
2. `scan_source()` - 26 edges
3. `generate_fallback_analysis()` - 25 edges
4. `check_dependencies_with_status()` - 23 edges
5. `make_valid_payload()` - 20 edges
6. `_VulnerabilityVisitor` - 17 edges
7. `write_requirements()` - 13 edges
8. `_mock_api()` - 12 edges
9. `_valid_llm_response()` - 11 edges
10. `_safe_str()` - 10 edges

## Surprising Connections (you probably didn't know these)
- `_assert_fallback_holds()` --calls--> `generate_fallback_analysis()`  [EXTRACTED]
  tests/test_ai_llm.py → ai_fallback.py
- `_fallback()` --calls--> `validate_schema()`  [EXTRACTED]
  ai_llm.py → schema_validator.py
- `_analyze_impl()` --calls--> `validate_schema()`  [EXTRACTED]
  ai_llm.py → schema_validator.py
- `test_parse_requirements_handles_pins_and_skips_garbage()` --calls--> `parse_requirements()`  [EXTRACTED]
  tests/test_dependency_check.py → dependency_check.py
- `test_utf8_bom_requirements_file_does_not_lose_first_pin()` --calls--> `check_dependencies_with_status()`  [EXTRACTED]
  tests/test_dependency_check.py → dependency_check.py

## Import Cycles
- None detected.

## Communities (17 total, 1 thin omitted)

### Community 0 - "generate_fallback_analysis"
Cohesion: 0.14
Nodes (32): _bucket_penalty(), _build_attack_path(), _build_dot_script(), _build_recommendations(), _build_refactored_code(), _dep_severity(), _dot_escape(), generate_fallback_analysis() (+24 more)

### Community 1 - "validate_schema"
Cohesion: 0.14
Nodes (11): Validate *data* against the Hyperion analysis-response contract.      Returns (T, validate_schema(), make_valid_payload(), make_valid_vulnerability(), TestDegenerateInputs, TestEmptyCollectionsAreValid, TestFallbackIntegration, TestFullyValidPayload (+3 more)

### Community 2 - "_VulnerabilityVisitor"
Cohesion: 0.16
Nodes (14): AnnAssign, arguments, Assign, AST, AsyncFunctionDef, Call, expr, FunctionDef (+6 more)

### Community 3 - "dependency_check.py"
Cohesion: 0.14
Nodes (16): _alias_keys(), check_dependencies(), _cvss_base_score(), _dedupe_vulns(), _fixed_version_of(), _level_from_score(), Any, _query_osv() (+8 more)

### Community 4 - "check_dependencies_with_status"
Cohesion: 0.23
Nodes (20): check_dependencies_with_status(), parse_requirements(), Check every pinned requirement against OSV.dev.      Returns (findings, offline_, Extract (package, version) pairs from requirements text.      Handles ==, >=, ~=, osv_reachable(), test_aliased_vulns_are_deduplicated_with_ghsa_preferred(), test_database_specific_severity_preferred_over_cvss_parsing(), test_dedup_falls_back_to_pysec_then_cve_when_no_ghsa() (+12 more)

### Community 5 - "test_ai_llm.py"
Cohesion: 0.23
Nodes (20): _analyze(), _assert_fallback_holds(), _mock_api(), Replace ai_llm._call_llm_api; record (system, user, key) per call., The safety net: fallback output is schema-valid and was logged., A complete response dict that passes validate_schema()., test_api_key_read_from_environment(), test_explicit_api_key_takes_precedence_over_environment() (+12 more)

### Community 6 - "scan_source"
Cohesion: 0.20
Nodes (18): Parse Python source with ast and return a list of findings.     Each finding is, scan_source(), test_clean_code_returns_empty(), test_dangerous_call_eval(), test_dangerous_call_os_system(), test_dangerous_call_pickle_loads(), test_dangerous_call_subprocess_shell_true(), test_hardcoded_secret_assignment() (+10 more)

### Community 7 - "ai_llm.py"
Cohesion: 0.18
Nodes (16): _analyze_impl(), analyze_with_llm(), _build_user_prompt(), _call_llm_api(), _fallback(), get_analysis(), _minimal_contract(), Hyperion Security Engine — LLM-backed analysis path.  Sits alongside ai_fallback (+8 more)

### Community 8 - "schema_validator.py"
Cohesion: 0.58
Nodes (8): _is_float(), _is_int(), _is_num(), _is_str(), Any, Hyperion Security Engine — schema validation module.  Validates analysis-respons, _validate(), _validate_vulnerabilities()

### Community 9 - "🛡️ Hyperion Engine"
Cohesion: 0.40
Nodes (4): 🏗️ Architecture, 🛡️ Hyperion Engine, ✨ Key Features, 📌 Overview

## Knowledge Gaps
- **4 isolated node(s):** `graphify`, `📌 Overview`, `✨ Key Features`, `🏗️ Architecture`
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `validate_schema()` connect `validate_schema` to `schema_validator.py`, `dependency_check.py`, `test_ai_llm.py`, `ai_llm.py`?**
  _High betweenness centrality (0.219) - this node is a cross-community bridge._
- **Why does `scan_source()` connect `scan_source` to `_VulnerabilityVisitor`, `dependency_check.py`?**
  _High betweenness centrality (0.189) - this node is a cross-community bridge._
- **Why does `generate_fallback_analysis()` connect `generate_fallback_analysis` to `validate_schema`, `dependency_check.py`, `test_ai_llm.py`?**
  _High betweenness centrality (0.173) - this node is a cross-community bridge._
- **What connects `Hyperion Security Engine — deterministic rule-based fallback analysis.  Builds a`, `Coerce to str without ever raising.`, `Coerce to int without ever raising.` to the rest of the system?**
  _36 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `generate_fallback_analysis` be split into smaller, more focused modules?**
  _Cohesion score 0.1361344537815126 - nodes in this community are weakly interconnected._
- **Should `validate_schema` be split into smaller, more focused modules?**
  _Cohesion score 0.1354723707664884 - nodes in this community are weakly interconnected._
- **Should `dependency_check.py` be split into smaller, more focused modules?**
  _Cohesion score 0.13538461538461538 - nodes in this community are weakly interconnected._