# Hyperion Security Engine — Sprint Documentation Pack
**Bano Qabil AI Hackathon — Open Innovation Track | Aug 22–27, 2026**

---

## Document 1: 1-Page Master PRD & Scope Spec

### Problem Statement
AI-assisted coding has accelerated feature velocity but outpaced security review. Vulnerable code, hardcoded secrets, and outdated dependencies now reach production faster than teams can catch them. Fixing a vulnerability post-deployment costs up to 100x more than catching it locally. Enterprise SAST tools (Snyk, Checkmarx, Veracode) are priced for large orgs, leaving freelancers, startups, and regional software agencies — who often lose international contracts over failed security audits — without an accessible option.

### Core User Persona
- **Primary:** Solo developers and small-team leads at freelance/agency shops shipping to international clients, who need a fast pre-delivery security pass without hiring a security engineer.
- **Secondary:** Hackathon/student developers and DevSecOps-curious engineers who want an educational, visual way to understand *why* code is vulnerable, not just that it is.

### Must-Have MVP Features (5-Day Sprint)
1. **AST + regex scanner** for Python (extendable stub for JS/Go) detecting SQLi, hardcoded secrets, XSS, insecure deserialization
2. **Dependency CVE cross-check** against `requirements.txt` / `package.json`
3. **LLM-driven threat modeling**: OWASP mapping, CVSS estimate, plain-English PoC attack narrative (non-executing, descriptive only)
4. **Recommendations engine**: immediate fixes / architecture hardening / CI-CD guardrails, priority-ranked
5. **Graphviz attack-flow diagram**: input → sink visualization
6. **Side-by-side diff**: vulnerable vs. AI-refactored code, with download
7. **PDF export**: 2-page executive report with health score + charts
8. **Sidebar demo mode**: pre-loaded vulnerable code samples for judge demos (critical — never rely on live typing during judging)

### Explicit Non-Goals (Scope Guardrails)
- ❌ No real exploit execution or live PoC running (safety + liability)
- ❌ No multi-user auth, persistent database, or account system
- ❌ No full multi-language parser depth (JS/Go/C++ get lightweight pattern-matching, not full AST, in v1)
- ❌ No live GitHub OAuth app scanning at scale — repo URL → clone → scan is sufficient
- ❌ No IDE plugin / CI bot integration (mention as roadmap only)
- ❌ No fine-tuned custom model — prompt-engineered wrapper around an existing LLM is sufficient

### Success Metrics (for judging)
- End-to-end demo completes in <60 seconds per sample
- At least 3 vulnerability classes correctly flagged with accurate line numbers
- PDF report generates without manual intervention
- Zero crashes across all 5 tabs during a live walkthrough

---

## Document 2: System Architecture & Tech Stack Spec

### Data Flow Pipeline
```
[Input: file upload / GitHub URL / pasted snippet]
        │
        ▼
[Ingestion Layer]
  - If GitHub URL → shallow clone → walk file tree, filter by extension
  - If upload/snippet → load directly into memory
        │
        ▼
[Static Parsing Layer]
  - Python: `ast` module walk → detect risky calls (eval, os.system, subprocess w/ shell=True,
    pickle.loads, string-formatted SQL queries, cursor.execute with % or f-string)
  - Other languages: regex/pattern-matcher fallback (documented as "lite mode" in UI)
  - Dependency files: parse requirements.txt/package.json → match against a local
    static CVE lookup table (bundled JSON, NOT a live API call — avoids rate limits/latency
    during judging)
        │
        ▼
[Structured Findings Object] — intermediate Python dict/list, NOT yet AI-processed
  { file, line_number, snippet, pattern_type, confidence }
        │
        ▼
[AI Analysis Engine] (single batched LLM call per scan, not per-finding)
  - Input: structured findings + surrounding code context
  - Output: strict JSON (see Document 3 schema)
  - Fallback: if API fails/times out → rule-based JSON template with generic
    OWASP mappings, so the demo NEVER shows a blank screen
        │
        ▼
[Streamlit Rendering Layer]
  - Tab 1 Dashboard: Plotly donut (severity) + radar (OWASP distribution) fed from JSON
  - Tab 2 Threat Modeling: Graphviz DOT string rendered via st.graphviz_chart
  - Tab 3 Recommendations: JSON → grouped expandable checklist
  - Tab 4 Code Diff: st.columns() side-by-side, red/green diff via difflib + custom styling
  - Tab 5 Export: ReportLab/FPDF assembles findings + charts (as static images) into PDF
```

### Library Roles
| Layer | Library | Role |
|---|---|---|
| UI | Streamlit | Single-page multi-tab app |
| Parsing | `ast`, `re` | Python AST walk, regex fallback for other languages |
| Charts | Plotly Express | Donut + radar charts |
| Diagrams | Graphviz | DOT-language attack-flow rendering |
| AI | OpenAI/OpenRouter SDK (or `requests`) | Single structured-JSON completion call |
| Diff | `difflib` | Unified diff generation before display |
| PDF | ReportLab (preferred) or FPDF | Static 2-page export |

### Performance & Reliability Strategy for Judging
- **Single batched LLM call**, not one call per vulnerability — cuts latency and cost
- **Local static findings first, AI enrichment second** — the scanner still shows results even if the LLM call fails or is slow
- **Hard timeout (~8s) with fallback JSON** — never let the UI spin indefinitely in front of judges
- **Pre-cached demo results** for the sidebar sample snippets — first-run judged demo should feel instant, live LLM calls reserved for custom/uploaded code
- **Stateless design** — no session persistence needed; every scan is self-contained in `st.session_state` for the current session only

### Why No Traditional ERD
This is a stateless single-session prototype — no persistent multi-user data model exists. The JSON Output Schema (Document 3) *is* the data contract the entire pipeline depends on, replacing what an ERD would do in a database-backed system. If Hyperion continues past the hackathon, the natural next step is a `scans`, `findings`, and `users` relational schema for history/auth — worth flagging as roadmap, not for this sprint.

---

## Document 3: AI Engine Prompt & JSON Output Schema

### System Prompt (for the LLM wrapper)
```
You are a senior application security analyst. You will receive a code snippet and a list
of statically-detected candidate issues. Your job is to analyze, classify, and explain —
you do NOT execute code, generate working exploit payloads, or produce anything that could
be run against a live system. All "attack paths" are descriptive, educational narratives
of how a vulnerability class is commonly exploited in general — not tailored, runnable
exploit code.

Return ONLY valid JSON matching the schema below. No markdown fences, no prose outside
the JSON object, no explanations before or after.
```

### JSON Output Schema
```json
{
  "health_score": 0,
  "vulnerabilities": [
    {
      "id": "string",
      "owasp_category": "string (e.g. A03:2021-Injection)",
      "severity": "Critical | High | Medium | Low",
      "cvss_score": 0.0,
      "line_number": 0,
      "file": "string",
      "description": "string — plain-English explanation of the flaw"
    }
  ],
  "graphviz_dot_script": "string — valid DOT language, input-to-sink flow",
  "attack_path_poc": [
    {
      "step": 1,
      "narrative": "string — general educational description of exploitation technique, no working payloads"
    }
  ],
  "recommendations": {
    "immediate_fixes": ["string"],
    "architecture_hardening": ["string"],
    "pipeline_guardrails": ["string"]
  },
  "refactored_code": {
    "file": "string",
    "language": "string",
    "full_source": "string — complete corrected file content"
  }
}
```

### Notes for Implementation
- Validate the JSON on receipt (`json.loads` in a try/except) — malformed output falls back to the rule-based template, never crashes the UI
- Keep `attack_path_poc` narrative-only by instruction and by post-processing check (e.g., reject/flag if the response contains runnable shell/SQL payloads) — this protects both the demo and you from producing actual exploit code
- `refactored_code.full_source` should be the complete file, not a fragment, so the diff view and download button work directly off it
