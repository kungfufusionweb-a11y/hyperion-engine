


HYPERION SECURITY ENGINE — FULL PROJECT STATE (for continuation in a new chat) Project identity Name: Hyperion Security Engine. What it is: an AI-powered DevSecOps SAST + threat-modeling platform. Scans Python code (snippet, uploaded file, or full GitHub repo) for vulnerabilities via AST pattern ma

pasted


How can I help you today?




Pasted content
23.79 KB •156 lines
•
Formatting may be inconsistent from source

HYPERION SECURITY ENGINE — FULL PROJECT STATE (for continuation in a new chat)
Project identity

Name: Hyperion Security Engine. What it is: an AI-powered DevSecOps SAST + threat-modeling platform. Scans Python code (snippet, uploaded file, or full GitHub repo) for vulnerabilities via AST pattern matching, cross-references dependencies against real CVE data (OSV.dev), then runs an LLM analysis layer (with a guaranteed deterministic fallback) to produce OWASP-mapped findings, attack-path narratives, hardening recommendations, and AI-suggested code fixes — all rendered in a styled Streamlit dashboard.

Context: Bano Qabil AI Hackathon, Open Innovation track. Original sprint Aug 22–27, 2026; deadline extended to Sep 4, 2026. User's stated goal throughout: make this "legendary," not just working — has consistently pushed for real bug-fixing over cosmetic passes, and for professional (not "AI slop") visual design.

Environment: Windows, PowerShell, project folder E:\Hyperion Engine. GitHub repo: https://github.com/kungfufusionweb-a11y/hyperion-engine (public, pushed). Implementation tool: opencode CLI (not Claude Code — user corrected this explicitly partway through). Git initialized; commits made per-fraction, only after manual verification, with descriptive messages documenting bugs found/fixed.

Working method established and expected to continue: fractional build — one component at a time, pytest first, then manual verification against real data (not just mocks), fix any real bugs found, commit, then move to next fraction. This method has caught numerous real bugs (detailed below) that automated tests alone missed. The user values this discipline highly — don't skip the manual-verification step even under time pressure, though scope can be trimmed.

Key ongoing directive: NO "AI slop" design patterns. Specifically banned: warm cream+terracotta backgrounds, near-black+single-neon-accent, boxed identical SaaS-cards with soft shadows, ALL-CAPS tracked eyebrow labels, "→" on buttons, generic centered hero layouts. User wants a genuinely distinctive, professional DevSecOps instrument-panel aesthetic. Streamlit's inherent limitations (no native shadcn/Tailwind support without a full custom React rewrite, which is out of scope for remaining time) have been explained to and accepted by the user as a hard constraint.

Repository structure (as of last known state)
E:\Hyperion Engine\
├── scanner.py                  (Fraction 1 — AST vulnerability scanner)
├── dependency_check.py         (Fraction 2 — OSV.dev CVE checker)
├── ai_fallback.py               (Fraction 3A — deterministic fallback analysis)
├── schema_validator.py         (Fraction 3B — strict JSON schema validator)
├── ai_llm.py                    (Fraction 3C — real LLM integration + fallback wiring)
├── cve_reference.py             (Fraction 5A — curated real CVE few-shot grounding)
├── repo_scanner.py             (Fraction 4A — full GitHub repo scanning)
├── app.py                       (Fraction 4B/5B/5C — Streamlit UI, currently has an
                                   active syntax-error investigation in progress)
├── pytest.ini                   (testpaths = tests, ASCII encoding to avoid BOM issue)
├── .env                         (HYPERION_LLM_API_KEY, HYPERION_LLM_API_URL,
                                   HYPERION_LLM_MODEL — gitignored)
├── .env.example                 (safe placeholder version, committed)
├── .gitignore                   (excludes: bandit/, osv-schema/, osv.dev/,
                                   CheatSheetSeries/, __pycache__/, .pytest_cache/,
                                   *.pyc, .env, dev-tools/, graphify-out/, .agents/,
                                   .claude/, .opencode/, docs/, CLAUDE.md, prompt.md)
├── tests/
│   ├── test_scanner.py          (16+ tests)
│   ├── test_dependency_check.py (17 tests)
│   ├── test_ai_fallback.py      (7 tests)
│   ├── test_schema_validator.py (29 tests)
│   ├── test_ai_llm.py           (mocked, no real network calls)
│   ├── test_repo_scanner.py     (28 tests, 1 network-skip)
│   ├── test_cve_reference.py    (13 tests)
│   ├── hardcoded_secret.py      (deliberately vulnerable demo fixture)
│   ├── os_system_misuse.py      (deliberately vulnerable demo fixture)
│   ├── pickle_loads.py          (deliberately vulnerable demo fixture)
│   └── sql_injection.py         (deliberately vulnerable demo fixture)
├── dev-tools/                   (gitignored — disposable manual test scripts:
                                   manual_test.py, manual_test_deps.py,
                                   raw_osv_check.py, test_pyyaml_isolated.py,
                                   timing_probe.py, raw_llm_check.py,
                                   test_llm_manual.py, test_repo_scanner_manual.py,
                                   test_validator_manual.py, test_fallback_manual.py)
└── some_real_file.py            (standard multi-vuln test file used throughout:
                                   hardcoded secret, SQLi via tainted variable,
                                   os.system, pickle.loads, unsafe yaml.load)

Last known good full-suite pytest count: 143 passed, 1 skipped (before the current in-progress app.py syntax-error investigation).

FRACTION-BY-FRACTION DETAIL (all bugs found matter — they're evidence of real engineering for the presentation)
Fraction 1 — scanner.py (AST-based static scanner)

scan_source(code: str, filename: str) -> list[dict]. Uses ast.NodeVisitor. Detects:

hardcoded_secret — assignments/defaults where variable name matches api_key/secret/password/token pattern
sql_injection — string concat/f-string/.format() passed to execute()/raw(), including intra-function taint tracking (variable built on one line, executed on another — a real gap found and fixed)
dangerous_call — eval/exec/os.system/subprocess(shell=True)/pickle.loads
insecure_deserialization — yaml.load() without explicit SafeLoader

Output contract per finding: {file, line_number, column, snippet, pattern_type, confidence}. Parse errors return a parse_error finding instead of raising.

Real bugs found & fixed:

SQL injection taint-tracking gap — query = "..." + x; cursor.execute(query) was missed because only direct-argument concatenation was checked. Fixed with intra-function-scope variable taint tracking (untaints on safe reassignment).
False positives: _ENV_API_KEY = "HYPERION_LLM_API_KEY" (an env-var-name reference, not a real secret) and API_KEY = "test-api-key-not-real" (test fixture) were both flagged at high confidence. Fixed: values matching ^[A-Z][A-Z0-9_]+$ (8+ chars) are now excluded entirely; values containing test/mock markers (fake/dummy/not-real/example/placeholder) are downgraded to low confidence, not excluded. Applied consistently to plain assignments, tuple assignments, positional defaults, AND keyword-only defaults (had to verify control flow carefully — some loops needed continue instead of return to avoid skipping sibling targets in multi-target assignments).
Fraction 2 — dependency_check.py (OSV.dev CVE checker)

check_dependencies(requirements_path) -> list[dict], check_dependencies_with_status() also returns offline_mode bool (true only if ALL package lookups fail at network level, not just one). Stdlib urllib only. Parses ==/>=/~= pins, skips comments/markers/URLs/unpinned lines. Per-package failure isolation with WARNING-level logging of lookup_failed: <reason>.

Output contract: {package, installed_version, vuln_id, severity, summary, fixed_version}.

Real bugs found & fixed:

Duplicate findings — OSV returns multiple aliases (GHSA/PYSEC/CVE) per real advisory; fixed with alias-based grouping (including the record's own id as part of the match set), GHSA preferred as canonical.
Broken severity — was returning the literal string "CVSS_V3" (the scoring system name) instead of an actual severity level. Fixed: prefer database_specific.severity (case-normalized), fall back to CVSS base-score parsing.
Major bug: pyyaml==5.3 (a known-vulnerable test package) consistently returned ZERO findings with no error/warning anywhere. Root cause found via rigorous elimination (raw API call proved OSV had the data; instrumented tracing proved dedup/severity logic worked correctly in isolation; tracing the live _query_osv call showed it was never even invoked) — the requirements.txt file had a UTF-8 BOM (\xef\xbb\xbf, an artifact of Set-Content -Encoding UTF8 in PowerShell) glued onto the first line, silently failing the pin-parsing regex before any network call was made. Fixed: encoding="utf-8-sig" instead of "utf-8". This BOM issue recurred multiple times throughout the project whenever new .txt/.py files were created via PowerShell Set-Content -Encoding UTF8 — the fix is to use -Encoding ASCII for plain text config files, or ensure code reading them uses utf-8-sig.
Fraction 3 — AI Analysis Layer (3 sub-parts, built in order: fallback → validator → real LLM)

3A — ai_fallback.py: generate_fallback_analysis(scan_findings, dep_findings, source_code) -> dict. Zero external calls, never raises, always produces complete schema-valid output. Health score formula: diminishing-returns per severity bucket, code findings and dependency findings weighted/scaled separately (dependency findings at 0.6x weight) so realistic finding loads don't all floor at 0. Maps scanner pattern_types to plausible OWASP categories. Template-based (non-LLM) attack narratives and recommendations. refactored_code.full_source must echo the TRUE original source verbatim (not reconstructed from snippets — this was a bug, fixed by adding a source_code parameter).

Real bugs found & fixed:

refactored_code.full_source was reconstructing broken pseudo-code from flagged line snippets instead of returning the real original file — fixed by passing actual source through.
Original linear health-score penalty formula floored almost any realistic finding mix (e.g. 3 Critical + 6 High + 5 Medium + 1 Low) straight to 0 — meaningless as a signal. Redesigned with diminishing per-severity penalties and separate code/dependency weighting; verified a "heavy" load scores ~25 and a "light" load scores ~70+ (meaningfully differentiated).

3B — schema_validator.py: validate_schema(data: dict) -> tuple[bool, str]. Strict, gives specific per-field error paths (e.g. "vulnerabilities[1].severity must be one of Critical/High/Medium/Low, got 'SEVERE'"). Explicitly rejects bool for numeric fields (Python's isinstance(True, int) == True gotcha). Empty lists valid. Never raises. 29 tests including confirming the real fallback output always validates.

3C — ai_llm.py: get_analysis(scan_findings, dep_findings, source_code, api_key=None) -> dict (single entry point for UI). Uses stdlib urllib (no requests dependency). Single batched prompt (system prompt + scanner findings + dependency findings + full source, all at once — not per-finding calls). Strips markdown code fences before json.loads(). On ANY failure (missing key, timeout, network error, invalid JSON, schema validation failure) — falls back to ai_fallback.generate_fallback_analysis(), re-validates that output too (paranoia layer with a _minimal_contract() last resort). Logs llm_success or fallback_triggered: <reason> at WARNING level. API config (key/URL/model) read from env vars via .env + python-dotenv, never hardcoded (a real API key WAS accidentally pasted into this chat early on during debugging and should be treated as compromised — confirm rotation happened).

System prompt safety rules (verified via prompt-content assertions in tests): must return ONLY valid JSON, no markdown fences; attack_path_poc must be narrative/educational ONLY, never runnable exploit code/payloads; refactored_code.full_source must be the COMPLETE corrected file, never a fragment; brevity constraints added later (one-sentence descriptions, max 5 attack-path steps grouped rather than one-per-finding, one-sentence recommendation items) — cut real-world generation time roughly 46s→32s.

Real bugs found & fixed:

Original 8-second timeout was far too short for real responses (~30-90s typical for this schema's output size) — raised progressively: 8s → 25s → 60s → (most recently) 30s again, after discovering the 60s value wasn't being respected in one incident (see "Active/unresolved issues" below).
Critical incident: one real call hung 302 seconds before failing with KeyError: 'choices' despite a 60s timeout supposedly being set — this was being actively investigated in the most recent messages of this conversation (status: partially addressed, see below).
Timing is genuinely variable on the current third-party provider (router.bynara.id, model deepseek-v4-flash) — observed real range across many runs: as fast as 3.47s (trivial prompt), typically 30-50s for real analysis prompts, one anomalous 88s, one anomalous 302s-then-fail. This variance is a known, accepted characteristic of the provider, not something fully fixable from the client side — mitigated by the fallback design and by planning to pre-cache demo samples (see Recommendations below).

5A addition — cve_reference.py: 7 real, NVD-verified CVEs used as few-shot grounding, appended to the end of _SYSTEM_PROMPT: CVE-2020-1747 (PyYAML), CVE-2021-44228 (Log4Shell), CVE-2018-1335 (Apache Tika), CVE-2014-3704 (Drupal SQLi, CVSS v2.0 only — no v3 score exists on NVD for this older CVE, this is factually correct and acceptable), CVE-2015-7755 (Juniper ScreenOS backdoor), CVE-2014-6271 (Shellshock), CVE-2017-5638 (Struts2/Equifax). Each entry validated at import time (raises if malformed). format_examples_for_prompt() renders as compact plain text, not JSON. This was explicitly chosen as a safe, legitimate substitute for actual model fine-tuning (user initially asked about training on HuggingFace/Kaggle datasets; this was talked out of scope as too risky/time-consuming given the deadline — few-shot grounding with real CVEs was the agreed middle ground).

Fraction 4 — Full repo scanning + Streamlit shell

4A — repo_scanner.py: scan_repository(github_url) -> dict returning {scan_findings, dep_findings, files_scanned, repo_url, error, notes}. Validates URL looks like GitHub. Shallow clones (git clone --depth 1) to a tempfile-managed temp dir. Walks all .py files (skips venv/, __pycache__/, .git/, node_modules/ — does NOT skip test files, since real vulnerabilities can hide there). Runs scan_source() per file, check_dependencies() on any found requirements.txt. Limits: 1MB max file size, 500 max files, 30s clone timeout. Always cleans up temp dir (try/finally).

Real bug found & fixed (major): temp directories were leaking on the successful scan path specifically (confirmed via careful before/after %TEMP% inspection with a cleared baseline — failure path was clean, success path leaked). Root cause: Windows-specific — git clone leaves read-only file attributes on files inside .git/objects, and shutil.rmtree() raises PermissionError on those without help. Fixed with an onerror/onexc (version-aware, Python 3.12 deprecated onerror in favor of onexc) handler that clears the read-only bit and retries deletion.

4B/5B/5C — app.py: Streamlit UI. Currently structured as:

Custom CSS injected via inject_custom_css() — dark theme tokens (--bg:#12141A, --panel:#1B1E27, --border:#2C2F3A, --text-primary:#E4E6EB, --text-muted:#8B8FA3, --accent:#5B8DEF, severity colors --critical:#E5484D --high:#F0883E --medium:#E8C547 --low:#6FCF97), Space Grotesk (headings/UI) + JetBrains Mono (code/data) fonts via Google Fonts link
Sidebar removed per explicit user request (was causing visual overlap/mismatch) — all inputs moved into a main-panel render_input_panel() with a top accent-bar treatment, horizontal radio mode selector styled as segmented pills
Custom topbar/brand strip added (H// mark + "Hyperion Security Engine" + tagline) replacing plain st.title()
5 tabs: Dashboard (built), Threat Modeling & Attack Paths (built), Recommendations & Hardening (placeholder — but the data already exists in analysis["recommendations"], just needs rendering), Code Refactoring (placeholder — this is essentially Fraction 7, the diff viewer), Export Report (placeholder — Fraction 8, PDF export)
Dashboard tab: health-score gauge (Plotly go.Indicator), severity donut (Plotly px.pie, hole=0.6), OWASP category horizontal bar — all reading from analysis["vulnerabilities"] when available (snippet/upload mode), falling back to scan_findings's pattern_type field for repo-URL mode (which has no analysis key, by design — repo scans don't call get_analysis() since there's no single coherent source file)
Threat Modeling tab: renders analysis["graphviz_dot_script"] via st.graphviz_chart(), analysis["attack_path_poc"] as numbered steps
Terminal timing instrumentation added throughout: [Hyperion] Scan completed in X.XXs, [Hyperion] Dependency check completed in X.XXs, [Hyperion] AI analysis completed in X.XXs, [Hyperion] Repo scan completed in X.XXs (N files), plus llm_success in X.XXs / fallback_triggered: <reason> (after X.XXs) logger lines

Multiple real UI bugs found and fixed across several rounds:

render_severity_donut/render_owasp_bar color-map used uppercase keys ("CRITICAL") but actual data uses Title Case ("Critical") — colors silently fell back to Plotly defaults. Fixed.
Charts were fed scan_findings (raw AST output, has NO severity/owasp_category fields) instead of analysis["vulnerabilities"] — would have rendered empty/wrong. Fixed: branches correctly based on whether analysis is present.
Global CSS panel styling applied to .element-container blanket-wide — boxed everything uniformly (the exact "SaaS-card-kit" anti-pattern), flattening all hierarchy including the intended-signature health gauge. Fixed: scoped to specific .hyperion-panel/.health-gauge-container/.stat-strip classes only.
Global font-family !important override on [class*="css"] wildcard broke Streamlit's Material Symbols icon font (sidebar-collapse icon rendered as literal text "keyboard_double_arrow_left"). Fixed: scoped font override to explicit text-bearing element list, added explicit exclusion for icon-font testids/classes.
st.text_area/st.text_input never actually got dark-theme styling (Streamlit's native widgets keep their own white background by default unless explicitly targeted) — text was low-contrast/hard to read. Fixed with explicit dark backgrounds on textarea, [data-baseweb="input"] input, etc.

Active/unresolved issues at time of writing this summary:

app.py currently has (or very recently had) a reported IndentationError: unexpected indent at line 647, from a use_container_width=True → width="stretch" deprecation-fix rename. Opencode's own re-check found the file parses cleanly on disk — leading theory is stale in-memory Streamlit server bytecode (file edited while server was running). Next step in progress: kill both Streamlit processes, restart fresh, confirm error is gone or get a fresh accurate traceback. This must be resolved before the app can be considered working again.
File uploader "Browse"/"Upload" button shows overlapping text ("uploadUpload") — NOT a white-space: nowrap truncation issue (that's already correctly applied); more likely two text nodes/elements rendering at the same coordinates due to a flex/layout collapse, or a selector mismatch (Streamlit's actual DOM structure/testids for this component weren't confirmed via live DevTools inspection — opencode proposed a defensive multi-selector CSS fix covering several possible real selectors plus explicit display:flex on the dropzone container, pending application and visual verification).
Timeout/reliability: after the 302-second hang incident (see Fraction 3C notes), _API_TIMEOUT_SECONDS was lowered to 30s and two subsequent real calls correctly timed out and fell back at ~30.2-30.3s — appears fixed, but the root cause of why 60s wasn't enforced during the 302s incident was not fully diagnosed (possible causes discussed: retry wrapping, DNS/connect-phase not covered by read-timeout, or the response being an error page lacking the expected choices key entirely). Worth continued monitoring; not necessarily fully understood, just mitigated by the lower timeout.
User's standing complaint: UI is "still too simple" / wants shadcn/Tailwind-level polish. This has been explained as infeasible in Streamlit without a full custom React component rewrite (out of scope for remaining time) — the realistic ceiling is well-executed custom CSS on Streamlit's native widgets, which is what's been built. This is a judgment call the user may want to revisit, but further CSS iteration has diminishing returns at this point.
Remaining fractions (not started, or partially covered)
Fraction 6 (Graphviz attack-flow tab): Substantially already done as part of the Threat Modeling tab in 5B/5C (graph + attack path steps render there). Likely just needs final polish/verification, not a fresh build — do not rebuild from scratch, just verify what exists.
Fraction 7 (Diff viewer + download button): NOT started. Data already exists (analysis["refactored_code"] has file, language, full_source) — needs a side-by-side or unified diff view (original source vs. full_source, likely using Python's difflib) plus a download button for the refactored file. This should populate the "Code Refactoring" tab (currently a placeholder).
Fraction 8 (PDF export): NOT started. Explicitly deprioritized/cut candidate — user and assistant agreed a working 4-5 tab Streamlit app with no PDF export is still a complete, demoable product; build this LAST only if time remains.
"Recommendations & Hardening" tab: currently a placeholder but the data (analysis["recommendations"] with immediate_fixes/architecture_hardening/pipeline_guardrails lists) already exists from Fraction 3 — this should be quick to build, just needs rendering (e.g., three grouped, priority-ranked checklists).
Time context (as of this message)

Original deadline Aug 27, extended to Sep 4, 2026. At the last explicit check-in, approximately 1.5 days remained before submission portal closure — likely less now depending on when the new chat picks this up. Recommended priority order for remaining time:

Fix the two active app.py bugs (syntax error, uploader overlap) — blocking.
Quick build: Recommendations & Hardening tab (data already exists, low effort).
Build Fraction 7 (diff viewer) if time allows — high visual value, uses existing data.
Skip Fraction 8 (PDF) unless significant time remains.
Reserve real time (several hours minimum) for: pre-caching 2-3 rehearsed demo scans (so live judging never waits on a real 30-90s LLM call — a static/cached JSON result loaded instantly for the sidebar demo samples was discussed early on as important and has NOT yet been implemented), a full run-through of every input mode, finalizing the PRD/README/submission form (a Google Form draft answer for "delivery plan" was already written earlier in this conversation — worth reusing), and confirming the GitHub repo link is clean and public.
Other important facts
User's GitHub repo: https://github.com/kungfufusionweb-a11y/hyperion-engine
A real API key was pasted into this chat early on during LLM-provider debugging — should be confirmed rotated/revoked if not already done.
Current LLM provider: router.bynara.id (OpenAI-compatible proxy), model deepseek-v4-flash — known to have real latency variance; user has considered but not committed to trying an alternate provider (OpenRouter was suggested as a more stable option early on, not pursued further).
PowerShell + BOM encoding is a recurring gotcha in this project — any new .txt/config file created via Set-Content -Encoding UTF8 will have a BOM; use -Encoding ASCII for plain configs, or ensure Python code reading such files uses utf-8-sig.
Reference repos (bandit, osv-schema, osv.dev, OWASP CheatSheetSeries) are cloned locally for pattern reference only, properly gitignored, never imported as dependencies — safe to re-clone if needed but not required for continued work.
