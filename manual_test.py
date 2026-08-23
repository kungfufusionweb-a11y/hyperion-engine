from scanner import scan_source
import json

# Test: yaml.load without SafeLoader — should be flagged
yaml_vuln_code = '''
import yaml

def load_config(raw_data):
    return yaml.load(raw_data)
'''

result = scan_source(yaml_vuln_code, "yaml_test.py")
print(json.dumps(result, indent=2))
print("insecure_deserialization caught:", any(f["pattern_type"] == "insecure_deserialization" for f in result))
# Test: yaml.load WITH SafeLoader — should NOT be flagged (safe usage)
yaml_safe_code = '''
import yaml

def load_config(raw_data):
    return yaml.load(raw_data, Loader=yaml.SafeLoader)
'''

result_safe = scan_source(yaml_safe_code, "yaml_safe_test.py")
print(json.dumps(result_safe, indent=2))
print("False positive on safe yaml.load:", any(f["pattern_type"] == "insecure_deserialization" for f in result_safe))


result_safe = scan_source(yaml_safe_code, "yaml_safe_test.py")
print(json.dumps(result_safe, indent=2))
print("False positive on safe yaml.load:", any(f["pattern_type"] == "insecure_deserialization" for f in result_safe))
