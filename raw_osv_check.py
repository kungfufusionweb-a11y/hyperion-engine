import urllib.request
import json

payload = {
    "package": {"name": "pyyaml", "ecosystem": "PyPI"},
    "version": "5.3"
}

req = urllib.request.Request(
    "https://api.osv.dev/v1/query",
    data=json.dumps(payload).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)

with urllib.request.urlopen(req, timeout=10) as resp:
    body = resp.read().decode("utf-8")
    print("Status:", resp.status)
    print(json.dumps(json.loads(body), indent=2)[:2000])
