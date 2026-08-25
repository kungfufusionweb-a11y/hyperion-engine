import json
from ai_fallback import generate_fallback_analysis
from schema_validator import validate_schema

source = open("some_real_file.py").read()
from scanner import scan_source
from dependency_check import check_dependencies
scan_findings = scan_source(source, "some_real_file.py")
dep_findings = check_dependencies("test_requirements.txt")

result = generate_fallback_analysis(scan_findings, dep_findings, source)

# Sanity: real fallback output should pass
ok, reason = validate_schema(result)
print("Fallback output valid:", ok, reason)

# Now deliberately break it and confirm the validator catches it
broken = dict(result)
broken["health_score"] = "not a number"
ok2, reason2 = validate_schema(broken)
print("Broken output valid:", ok2, "| reason:", reason2)

broken2 = dict(result)
del broken2["graphviz_dot_script"]
ok3, reason3 = validate_schema(broken2)
print("Missing key valid:", ok3, "| reason:", reason3)
