from scanner import scan_source
from dependency_check import check_dependencies
from ai_fallback import generate_fallback_analysis
import json

source = open("some_real_file.py").read()
scan_findings = scan_source(source, "some_real_file.py")
dep_findings = check_dependencies("test_requirements.txt")

result = generate_fallback_analysis(scan_findings, dep_findings, source)
print(json.dumps(result, indent=2))
