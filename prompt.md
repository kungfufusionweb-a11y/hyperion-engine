Act as a senior Python security engineer. Build `scanner.py` for a SAST tool called
Hyperion Security Engine.

Requirements:
1. A function `scan_source(code: str, filename: str = "input.py") -> list[dict]` that
   parses the code with Python's `ast` module (not just regex) and walks the tree to detect:
   - Hardcoded secrets: string literals assigned to variables/params with names matching
     patterns like api_key, secret, password, token, access_key (case-insensitive)
   - SQL Injection risk: string concatenation or f-strings/`.format()`/`%` passed into
     calls like `execute(`, `cursor.execute(`, `raw(` 
   - Dangerous calls: `eval(`, `exec(`, `os.system(`, `subprocess.*(shell=True`, `pickle.loads(`
   - Insecure deserialization: `yaml.load(` without `Loader=yaml.SafeLoader`

2. Each finding returned as a dict with exactly these keys:
   {"file": str, "line_number": int, "column": int, "snippet": str (the actual source line,
   stripped), "pattern_type": str (one of: "hardcoded_secret", "sql_injection",
   "dangerous_call", "insecure_deserialization"), "confidence": str ("high"|"medium"|"low")}

3. Use `ast.NodeVisitor` subclassing, not manual tree recursion — keep each vulnerability
   class as its own visit_* method or clearly separated block so it's easy to extend later.

4. Handle syntax errors gracefully — if the code doesn't parse, return a single finding
   with pattern_type "parse_error" and the error message in snippet, don't crash.

5. Write this in a single file, fully typed with type hints, no external dependencies
   beyond the standard library.

6. Also write `tests/test_scanner.py` using pytest with one test function per vulnerability
   class above, each using a small inline code string (not a fixture file) with an assert
   on the exact pattern_type and line_number expected.

Do not build any UI, LLM integration, or CVE checking in this step — scanner.py and its
tests only. Show me the full file contents before running anything.