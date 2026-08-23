from dependency_check import check_dependencies
import json

result = check_dependencies("pyyaml_only.txt")
print("Findings for pyyaml:", len(result))
print(json.dumps(result, indent=2))
