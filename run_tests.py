import json
from scanner import scan_source

# ==========================================
# TEST 1: Clean Code (Should find NOTHING)
# ==========================================
clean_code = """
def add_numbers(a, b):
    return a + b

def greet(name):
    message = f"Hello, {name}!"
    print(message)

class Calculator:
    def multiply(self, x, y):
        return x * y
"""

# ==========================================
# TEST 2: Bad Code (Should find 4 vulnerabilities)
# ==========================================
multi_vuln_code = """
import os
import pickle

API_KEY = "sk-live-abc123xyz789"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def run_backup(cmd):
    os.system(cmd)

def load_data(raw_bytes):
    return pickle.loads(raw_bytes)
"""

# ==========================================
# TEST 3: Safe Code (Should find NOTHING)
# ==========================================
safe_looking_code = """
def login(password):
    verify(password)

def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

password = input("Enter your password: ")
"""

print("--- RUNNING MANUAL TESTS ---")

# Execute Test 1
res1 = scan_source(clean_code, "clean_test.py")
print("\nTest 1 Result:")
if res1 == []:
    print("✅ PASS: Clean file returned no errors.")
else:
    print(f"❌ FAIL: Found false positives:\n{json.dumps(res1, indent=2)}")

# Execute Test 2
res2 = scan_source(multi_vuln_code, "multi_test.py")
print("\nTest 2 Result:")
found_types = {f["pattern_type"] for f in res2}
expected_types = {"hardcoded_secret", "sql_injection", "dangerous_call", "insecure_deserialization"}
missing = expected_types - found_types
if not missing:
    print("✅ PASS: All 4 vulnerabilities caught successfully.")
else:
    print(f"❌ FAIL: Missing these bugs: {missing}")
    print(f"Scanner output:\n{json.dumps(res2, indent=2)}")

# Execute Test 3
res3 = scan_source(safe_looking_code, "near_miss_test.py")
print("\nTest 3 Result:")
if res3 == []:
    print("✅ PASS: Safe code was not flagged.")
else:
    print(f"❌ FAIL: Tricked by safe code:\n{json.dumps(res3, indent=2)}")
