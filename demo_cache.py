import json
import os

CACHE_DIR = os.path.join(os.path.dirname(__file__), ".demo_cache")


def save_cache(key: str, data: dict) -> None:
    os.makedirs(CACHE_DIR, exist_ok=True)
    path = os.path.join(CACHE_DIR, f"{key}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_cache(key: str) -> dict | None:
    path = os.path.join(CACHE_DIR, f"{key}.json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def list_cache() -> list[str]:
    if not os.path.isdir(CACHE_DIR):
        return []
    return [f[:-5] for f in os.listdir(CACHE_DIR) if f.endswith(".json")]