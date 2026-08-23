# Fraction 1 & 2 — AST Security Scanner and OSV.dev Dependency Vulnerability Checker

## Status

Complete. Both fractions were delivered in a single commit (`0a4454a`, "Fraction 1 & 2 complete: AST scanner (16 tests) + dependency/CVE checker via OSV.dev (17 tests), 33 total passing...") on branch `master`. The full test suite was re-run during documentation and all 33 tests pass.

Note on boundary: because both fractions share one commit, the split below is inferred from `prompt.md` (which scopes Fraction 1 to "scanner.py and its tests only"), from the commit message, and from the module layout — not from separate commits.

- **Fraction 1:** `scanner.py` — AST-based static analysis scanner for Python source.
- **Fraction 2:** `dependency_check.py` — dependency vulnerability checker backed by the live OSV.dev API.

## 1. What Was Implemented

### Fraction 1 — `scanner.py`
- Public entry point `scan_source(code: str, filename: str = "input.py") -> list[dict]` (`scanner.py`).
- Parses code with Python's built-in `ast` module and walks it using an `ast.NodeVisitor` subclass (`_VulnerabilityVisitor`).
- Detects four vulnerability classes plus parse errors:
  - **Hardcoded secrets** (`hardcoded_secret`): string literals assigned to names matching `_SECRET_NAME_PATTERN` (`api_key`, `access_key`, `secret`, `password`, `passwd`, `pwd`, `token`, case-insensitive), including annotated assignments (`visit_AnnAssign`) and function parameter defaults (`_check_param_defaults`).
  - **SQL injection** (`sql_injection`): f-strings, string concatenation, `%` formatting, or `.format()` passed into calls whose final attribute is one of `_SQL_SINK_NAMES` (`execute`, `executemany`, `raw`). Includes simple intra-function taint tracking via `_tainted_sql_vars` (variables assigned a risky SQL-building expression are flagged when later passed to a sink).
  - **Dangerous calls** (`dangerous_call`): builtin `eval`/`exec`, dotted `os.system` and `pickle.loads`, and `subprocess.*` functions called with `shell=True`.
  - **Insecure deserialization** (`insecure_deserialization`): `yaml.load(...)` without `Loader=yaml.SafeLoader`; an explicit non-SafeLoader lowers confidence to `medium`.
- Graceful syntax-error handling: unparseable code returns a single finding with `pattern_type: "parse_error"` instead of raising (`scan_source`, `except SyntaxError` branch).
- Findings are sorted by `(line_number, column)` before return.

### Fraction 2 — `dependency_check.py`
- `parse_requirements(text)` extracts `(package, version)` pins from requirements text, handling `==`, `>=`, `~=` operators, comments, blank lines, environment markers, and extras; unpinned/garbage lines are skipped via `_PIN_PATTERN`.
- `_query_osv(name, version)` POSTs JSON to `https://api.osv.dev/v1/query` (`_OSV_QUERY_URL`) with a 5-second timeout (`_REQUEST_TIMEOUT_SECONDS`), using only `urllib.request` (standard library).
- `check_dependencies(requirements_path)` returns a list of findings with keys: `package`, `installed_version`, `vuln_id`, `severity`, `summary`, `fixed_version`.
- `check_dependencies_with_status(requirements_path)` additionally returns an `offline_mode` boolean that is `True` only when *every* package lookup failed at network level — distinguishing "clean" from "API unreachable".
- Supporting logic added/extended during Fraction 2 hardening:
  - `_dedupe_vulns` / `_alias_keys` / `_vuln_id_rank`: collapse aliased advisories (GHSA/PYSEC/CVE describing one vulnerability) into one finding, preferring GHSA ids, falling back to PYSEC then CVE.
  - `_severity_of` / `_level_from_score` / `_cvss_base_score`: derive severity levels (`Critical|High|Medium|Low|Unknown`) from OSV `database_specific.severity` first, then from CVSS v3 vector strings (full base-score computation) or numeric scores.
  - `_summary_of`: falls back from empty `summary` to truncated `details` (max `_SUMMARY_MAX_LENGTH = 120` chars).
  - `_fixed_version_of`: extracts the fix version from PyPI `affected.ranges[].events[].fixed`.
  - Per-package lookup failures are logged via `logging.warning("lookup_failed: ...")` instead of being silently swallowed.
  - Requirements files are read with `encoding="utf-8-sig"` so a UTF-8 BOM (e.g., from PowerShell-written files) does not corrupt the first package name.

## 2. Why It Was Implemented

The project PRD (`hyperion-security-engine-docs.md`, Bano Qabil AI Hackathon sprint, Aug 22–27 2026) lists these as the first two MVP features:

1. "**AST + regex scanner** for Python ... detecting SQLi, hardcoded secrets, XSS, insecure deserialization" (MVP feature 1).
2. "**Dependency CVE cross-check** against `requirements.txt` / `package.json`" (MVP feature 2).

These produce the "[Structured Findings Object]" consumed by the planned AI analysis layer and Streamlit UI described in the architecture document. The CLAUDE.md output schema contract (`file`, `line_number`, `snippet`, `pattern_type`, `confidence`) matches the scanner's finding shape.

Fraction 1 was explicitly scoped by `prompt.md`: build `scan_source` with `ast.NodeVisitor`, exact finding keys, graceful parse errors, stdlib-only, plus pytest tests — "Do not build any UI, LLM integration, or CVE checking in this step."

## 3. Requirements Addressed

From `prompt.md` (all verified present in `scanner.py`):
- R1: `scan_source(code, filename)` using `ast` — implemented (`scan_source`, line 348).
- R2: Exact finding keys `{file, line_number, column, snippet, pattern_type, confidence}` — implemented in `_make_finding` (line 50).
- R3: `ast.NodeVisitor` subclassing with per-class detection methods — implemented (`_VulnerabilityVisitor`).
- R4: Syntax errors → single `"parse_error"` finding, no crash — implemented.
- R5: Single file, type-hinted, stdlib only — satisfied (`scanner.py` imports only `ast`, `re`, `typing`).
- R6: `tests/test_scanner.py` with pytest tests asserting exact `pattern_type` and `line_number` — implemented.

From the PRD MVP feature 2 (dependency CVE cross-check): implemented in `dependency_check.py`. Note: the architecture spec originally proposed a "local static CVE lookup table (bundled JSON, NOT a live API call)"; the implementation uses the live OSV.dev API instead (with offline-mode detection). This deviation from the written architecture doc is documented here rather than hidden.

## 4. Files / Modules Changed

All added in commit `0a4454a` (1818 insertions across 23 files):

Core implementation:
- `scanner.py` (372 lines) — Fraction 1 scanner.
- `dependency_check.py` (300 lines) — Fraction 2 dependency checker.

Tests:
- `tests/test_scanner.py` (173 lines, 16 test functions).
- `tests/test_dependency_check.py` (374 lines, 17 collected tests including parametrized cases).
- `run_tests.py` — standalone runner script printing pass/fail summary.

Manual verification scripts:
- `manual_test.py`, `manual_test_deps.py`, `raw_osv_check.py`, `test_pyyaml_isolated.py`.

Sample vulnerable fixtures (used for manual checks, not pytest fixtures):
- `tests/hardcoded_secret.py`, `tests/os_system_misuse.py`, `tests/pickle_loads.py`, `tests/sql_injection.py`.

Config / data:
- `pytest.ini` — sets `testpaths = tests`.
- `requirements.txt` — `pyyaml==5.3`, `flask==0.12` (deliberately vulnerable pins used as manual test input).
- `test_requirements.txt` — `pyyaml==5.3`, `requests==2.25.0`, `flask==0.12`.
- `pyyaml_only.txt` — `pyyaml==5.3`.
- `.gitignore` — excludes vendored reference repos (`bandit/`, `osv-schema/`, `osv.dev/`, `CheatSheetSeries/`) and caches.

Project docs created alongside: `hyperion-security-engine-docs.md` (PRD/architecture/schema pack), `CLAUDE.md` (output schema contract), `prompt.md` (Fraction 1 brief).

## 5. Architecture Changes

This is the initial foundation of the pipeline described in `hyperion-security-engine-docs.md`:

```
[source / requirements.txt] → [scanner.py: ast walk]      → findings dicts
                            → [dependency_check.py: OSV]  → vulnerability dicts
```

Both modules are standalone, stdlib-only, stateless layers producing structured dict findings — matching the "Static Parsing Layer" and "Structured Findings Object" stages of the architecture. No UI, LLM integration, or persistence exists yet.

One architectural deviation: dependency checking hits the live OSV.dev API rather than a bundled static CVE table, mitigated by the `offline_mode` signal and network-failure logging.

## 6. Important Technical Decisions

1. **AST over regex for Python** — mandated by `prompt.md` requirement 3; enables accurate line numbers, call-target resolution (`_dotted_name`), and keyword inspection (`shell=True`, `Loader=`).
2. **Simple taint tracking for SQLi** — `visit_Assign` records variables assigned risky SQL expressions into `_tainted_sql_vars`; taint resets at function boundaries (`visit_FunctionDef` saves/restores the set). This catches `query = "..."+user_id; cursor.execute(query)` (`test_sql_injection_tainted_variable`). It is flow-insensitive and intra-procedural only — a deliberate simplification.
3. **Confidence grading** — SQLi findings are `high` when a literal format-string is involved, `medium` otherwise (variable-built strings); yaml.load with explicit unsafe Loader drops to `medium`. Secrets and dangerous calls are always `high`.
4. **Live OSV.dev query per pin** — standard library `urllib.request` only; no HTTP client dependency.
5. **Offline vs clean distinction** — `check_dependencies_with_status()` returns `offline_mode=True` only if *all* lookups failed, preventing "empty results" from being misread as "no vulnerabilities" when the network is down.
6. **Alias-based deduplication preferring GHSA ids** — OSV often returns PYSEC/GHSA/CVE entries for the same advisory; `_dedupe_vulns` merges them and ranks ids `GHSA > PYSEC > CVE` (`_ID_PREFIX_PRIORITY`).
7. **Severity normalization** — prefers OSV `database_specific.severity`, else computes CVSS v3 base score from vector strings locally (no external CVSS library), mapping scores to Critical(≥9)/High(≥7)/Medium(≥4)/Low(>0).
8. **UTF-8 BOM tolerance** — `utf-8-sig` reading fixes PowerShell-written requirements files silently losing their first pin.
9. **Network-dependent tests skip gracefully** — `osv_reachable()` probe in `tests/test_dependency_check.py` skips live-API tests when OSV is unreachable; other dependency tests monkeypatch `dependency_check._query_osv` for determinism.

## 7. APIs / Endpoints Added

No HTTP endpoints exist yet (no server/UI has been built). The public Python APIs are:

Fraction 1 (`scanner.py`):
- `scan_source(code: str, filename: str = "input.py") -> list[dict]`

Fraction 2 (`dependency_check.py`):
- `check_dependencies(requirements_path: str) -> list[dict]`
- `check_dependencies_with_status(requirements_path: str) -> tuple[list[dict], bool]`
- `parse_requirements(text: str) -> list[tuple[str, str]]`

Outbound API consumed: `POST https://api.osv.dev/v1/query` with body `{"package": {"name": ..., "ecosystem": "PyPI"}, "version": ...}` (`_query_osv`).

Finding schema (per `CLAUDE.md` contract): `{"file", "line_number", "snippet", "pattern_type", "confidence"}` — note the runtime schema adds a `column` key (also specified in `prompt.md` requirement 2); `CLAUDE.md` shows the subset.

## 8. Database / Schema Changes

None. The project is intentionally stateless ("Why No Traditional ERD" section of `hyperion-security-engine-docs.md`); no migrations or database files exist.

## 9. Tests Added

`tests/test_scanner.py` — 16 tests (Fraction 1):
- Secrets: `test_hardcoded_secret_assignment`, `test_hardcoded_secret_function_default`.
- SQLi: `test_sql_injection_fstring_in_execute`, `test_sql_injection_string_concat_in_execute`, `test_sql_injection_percent_format_in_raw`, `test_sql_injection_str_format_in_execute`, `test_sql_injection_tainted_variable`.
- Dangerous calls: `test_dangerous_call_eval`, `test_dangerous_call_os_system`, `test_dangerous_call_subprocess_shell_true`, `test_dangerous_call_pickle_loads`.
- Deserialization: `test_insecure_deserialization_yaml_load_no_loader`, `test_insecure_deserialization_yaml_load_unsafe_loader`, `test_insecure_deserialization_yaml_load_safe_loader_skipped`.
- Robustness: `test_parse_error_returns_finding`, `test_clean_code_returns_empty`.

`tests/test_dependency_check.py` — 17 collected tests (Fraction 2):
- Parsing: `test_parse_requirements_handles_pins_and_skips_garbage`.
- Live OSV (network-gated): `test_known_vulnerable_package_returns_findings` (pyyaml==5.3), `test_recent_pin_has_no_false_positives` (pyyaml==6.0.1).
- Failure modes: `test_malformed_lines_do_not_crash`, `test_total_network_failure_reports_offline_mode`, `test_partial_failure_is_not_offline_mode`, `test_per_package_lookup_failure_is_visible_not_silent`.
- Dedup/severity regressions: `test_aliased_vulns_are_deduplicated_with_ghsa_preferred`, `test_dedup_falls_back_to_pysec_then_cve_when_no_ghsa`, `test_severity_from_cvss_vector_is_a_level_not_the_type_string` (4 parametrized cases), `test_database_specific_severity_preferred_over_cvss_parsing`, `test_empty_summary_falls_back_to_truncated_details`, `test_real_pyyaml_ghsa_id_record_is_not_lost`, `test_utf8_bom_requirements_file_does_not_lose_first_pin`.

## 10. How It Was Verified

- Full suite re-run during this documentation session: `python -m pytest -v` with `pytest.ini` (`testpaths = tests`) → **33 passed in 2.47s** on Python 3.12.0 / pytest 9.1.1, including the two network-gated live OSV tests (OSV.dev reachable at run time).
- Commit message records the same result: "16 tests + 17 tests, 33 total passing."
- Standalone runners exist for repeatable manual verification: `run_tests.py` (programmatic summary) and `manual_test.py` (3 scenario checks incl. false-positive resistance on safe-looking code).
- Manual scripts for Fraction 2 debugging: `manual_test_deps.py`, `raw_osv_check.py` (raw OSV response inspection), `test_pyyaml_isolated.py`, plus fixture files `requirements.txt`, `test_requirements.txt`, `pyyaml_only.txt`.
- Sample vulnerable fixtures under `tests/` (`sql_injection.py`, etc.) support ad-hoc scanner runs. Their automated execution is not asserted by any test file — manual use only.

## 11. Problems Encountered

Evidence-backed problems, each fixed and covered by named regression tests in `tests/test_dependency_check.py`:

1. **Silent loss of per-package lookup failures** — a per-package exception (e.g. HTTPError) was swallowed and the package vanished from results. Fixed with warning logging; covered by `test_per_package_lookup_failure_is_visible_not_silent`.
2. **Duplicate findings for aliased advisories** — OSV returned GHSA/PYSEC/CVE entries for one vulnerability as separate findings. Fixed with alias-grouped dedup preferring GHSA; covered by `test_aliased_vulns_are_deduplicated_with_ghsa_preferred` and `test_dedup_falls_back_to_pysec_then_cve_when_no_ghsa`.
3. **Severity reported as scoring-system string** — severity could surface as e.g. "CVSS_V3" instead of a level. Fixed with local CVSS v3 base-score computation and level mapping; covered by `test_severity_from_cvss_vector_is_a_level_not_the_type_string` and `test_database_specific_severity_preferred_over_cvss_parsing`.
4. **UTF-8 BOM corrupted first requirements line** — PowerShell-written files carry a BOM that glued onto the first package name, causing its pin (and any vulnerabilities) to be silently skipped. Fixed by reading with `encoding="utf-8-sig"`; covered by `test_utf8_bom_requirements_file_does_not_lose_first_pin`.
5. **SQLi taint gap** — variable-built queries reaching `execute()` needed taint tracking (commit message: "Includes SQLi taint-tracking fix"); covered by `test_sql_injection_tainted_variable`.

No implementation blocker remains identified from the available repository evidence.

## 12. How Problems Were Solved

Each problem above was solved inside `dependency_check.py`/`scanner.py` and pinned by a regression test named after the failure mode (see §9/§11). The debugging workflow visible in the repo: raw-response inspection scripts (`raw_osv_check.py`, `test_pyyaml_isolated.py`) captured real OSV response shapes, which were then encoded verbatim into tests (e.g., `_PYYAML_53_GHSA_RECORD` mirrors the actual pyyaml==5.3 response where the canonical id is itself a GHSA not repeated in aliases). The BOM fix comment in `check_dependencies_with_status` documents the root cause inline.

## 13. Dependencies Introduced

Runtime dependencies: **none** — both modules are standard-library only (`ast`, `re`, `json`, `logging`, `math`, `urllib.request`, `urllib.error`, `typing`).

Dev/test tooling observed in the environment: `pytest` (and transitive `pluggy`, `anyio`) — installed in the system Python; no project-level dev requirements file pins them. `requirements.txt` in the repo is deliberately vulnerable *test input* (pyyaml==5.3, flask==0.12), not a runtime dependency list.

Vendored reference material (gitignored, not imported): `bandit/`, `osv-schema/`, `osv.dev/`, `CheatSheetSeries/`.

External service dependency: OSV.dev API availability (handled via timeouts, error logging, and `offline_mode`).

## 14. Security Considerations

- The tool itself is defensive security tooling; it detects but never executes detected payloads.
- Outbound HTTPS POST to OSV.dev sends only package name/version — no source code or secrets leave the machine during dependency checks.
- No secrets, credentials, or keys are stored in the repository (the "secrets" in test files are synthetic examples like `"sk-live-1234567890"` and `"hunter2"`).
- Network calls have an explicit 5-second timeout; broad-but-bounded exception handling (`URLError, TimeoutError, OSError, ValueError`) prevents crashes on malformed responses while logging details.
- Offline-mode flag prevents a false sense of security ("clean scan") when the vulnerability database is unreachable.
- Limitations acknowledged by design: taint tracking is intra-procedural only (inter-file/inter-function flows are missed); non-Python languages are out of scope for this fraction (PRD defers them to regex "lite mode").

## 15. Before → After

**Before (pre-commit `0a4454a`):** repository contained only planning artifacts (`hyperion-security-engine-docs.md`, `prompt.md`, `CLAUDE.md`) and gitignored reference clones. No executable code, no tests.

**After:** two working stdlib-only modules with 33 passing tests:
- Any Python snippet can be scanned: `scan_source(code)` → typed findings with exact line numbers for secrets, SQLi (including tainted variables), dangerous calls, unsafe yaml.load, and parse errors.
- A requirements file can be checked: `check_dependencies("requirements.txt")` → deduplicated, severity-leveled OSV findings with fix versions, or an explicit offline signal.

Example verified end-to-end: `pyyaml==5.3` yields a `Critical` finding `GHSA-6757-jp84-gxfx` with `fixed_version == "5.3.1"` (asserted by `test_real_pyyaml_ghsa_id_record_is_not_lost`); `pyyaml==6.0.1` yields zero findings.

## 16. Screenshots / Evidence

No screenshot evidence was found in the repository. Textual evidence available:
- Commit `0a4454a` (full diff, message quoting test counts).
- Test run output reproduced in §10 (`33 passed in 2.47s`).
- Inline regression-test comments documenting each bug's original behavior (e.g., the BOM comment at `dependency_check.py` lines 253–256).

## 17. Current Project State

- Branch `master`, HEAD at `0a4454a`. Working tree has only unstaged edits to `.opencode/agents/fraction-documenter.md` and `.opencode/commands/document-fraction.md` (documentation-agent config, not application code).
- Implemented: SAST scanning (Python) and dependency CVE checking. All 33 tests green.
- Not yet implemented (per PRD roadmap): LLM threat modeling, recommendations engine, Graphviz attack-flow diagrams, code diff view, PDF export, Streamlit UI, demo mode, JS/Go lite scanning.

## 18. What the Next Fraction Should Build On

Based solely on what exists now, the next fraction can safely build on:
- `scan_source()` as a stable, tested findings producer whose dict schema matches the `CLAUDE.md` contract (plus `column`), ready to feed the planned LLM analysis layer.
- `check_dependencies_with_status()` as the dependency layer, including its `offline_mode` signal which the future UI can surface honestly.
- The pytest harness (`pytest.ini`, `tests/`) and the pattern of encoding real API response shapes into regression tests.
- The JSON output schema in `hyperion-security-engine-docs.md` Document 3 as the target contract for the next pipeline stage.

No requirements beyond the existing PRD are asserted here.

## 19. Verification / Evidence Summary

| Claim | Evidence |
|---|---|
| Scanner implements 4 vuln classes + parse_error | `scanner.py` `_VulnerabilityVisitor`, `scan_source` |
| 16 scanner tests | `tests/test_scanner.py` (counted), pytest output |
| 17 dependency tests | `tests/test_dependency_check.py` (collected), pytest output |
| 33 tests pass | Re-run: `python -m pytest -v` → "33 passed in 2.47s"; commit message concurs |
| OSV.dev integration | `_query_osv` posting to `https://api.osv.dev/v1/query`; live tests passed |
| Dedup/severity/BOM/logging fixes | Functions `_dedupe_vulns`, `_severity_of`, `_cvss_base_score`, `utf-8-sig` open, `logger.warning`; regression tests named accordingly |
| Stdlib-only runtime | Import lists of both modules |
| Single-commit delivery | `git log`/`git show --stat 0a4454a` |

Not verified from repository evidence: exact per-fraction commit boundaries (both fractions share one commit); execution transcripts of `run_tests.py`/`manual_test*.py` outputs (scripts exist; their past run results are attested only by the commit message).
