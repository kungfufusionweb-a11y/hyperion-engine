from dependency_check import check_dependencies
import json

result = check_dependencies("test_requirements.txt")
print(json.dumps(result, indent=2))

print()
print("Total findings:", len(result))
print("Packages flagged:", {f["package"] for f in result})
