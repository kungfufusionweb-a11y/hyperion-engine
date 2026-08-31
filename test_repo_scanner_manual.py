from repo_scanner import scan_repository
import json

result = scan_repository("https://github.com/kungfufusionweb-a11y/hyperion-engine.git")
print("Files scanned:", result["files_scanned"])
print("Scan findings:", len(result["scan_findings"]))
print("Dep findings:", len(result["dep_findings"]))
print("Error:", result["error"])
