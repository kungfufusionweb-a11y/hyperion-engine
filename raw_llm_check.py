import urllib.request
import json
import time

payload = {
    "model": "deepseek-v4-flash",
    "messages": [{"role": "user", "content": "Say hello in one word."}],
    "temperature": 0
}

req = urllib.request.Request(
    "https://router.bynara.id/v1/chat/completions",
    data=json.dumps(payload).encode("utf-8"),
    headers={
        "Authorization": "Bearer sk-nry-BDEA57eMfVcVvG3WMyuEe0uh4eproDKpiYD9_pB3sRU",
        "Content-Type": "application/json"
    },
    method="POST"
)

start = time.time()
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        print("Status:", resp.status)
        print("Elapsed:", round(time.time() - start, 2), "seconds")
        print(resp.read().decode("utf-8")[:500])
except Exception as e:
    print("FAILED after", round(time.time() - start, 2), "seconds:", type(e).__name__, e)
