from scanner import scan_source
from dependency_check import check_dependencies
import json
import os
import time
import urllib.request

os.environ["HYPERION_LLM_API_KEY"] = "sk-nry-QKzniuONmQnP-nIbwAWmCcK6mWBkaRPiwo65v0zPCl8"

source = open("some_real_file.py").read()
scan_findings = scan_source(source, "some_real_file.py")
dep_findings = check_dependencies("test_requirements.txt")

# Build the same payload ai_llm.py would build
prompt = "Analyze and return JSON.\n\nSCANNER:\n" + json.dumps(scan_findings) + "\n\nDEPS:\n" + json.dumps(dep_findings) + "\n\nSOURCE:\n" + source

payload = {
    "model": "deepseek-v4-flash",
    "messages": [{"role": "user", "content": prompt}],
    "temperature": 0
}

req = urllib.request.Request(
    "https://router.bynara.id/v1/chat/completions",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Authorization": f"Bearer {os.environ['HYPERION_LLM_API_KEY']}", "Content-Type": "application/json"},
    method="POST"
)

start = time.time()
try:
    with urllib.request.urlopen(req, timeout=90) as resp:
        elapsed = time.time() - start
        body = json.loads(resp.read().decode("utf-8"))
        print(f"SUCCESS in {elapsed:.1f}s")
        print("Output tokens:", body.get("usage", {}).get("completion_tokens"))
except Exception as e:
    print(f"FAILED after {time.time()-start:.1f}s:", type(e).__name__, e)
