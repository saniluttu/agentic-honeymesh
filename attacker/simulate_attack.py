import requests
import time
import random
import json

BASE_URL = "http://127.0.0.1:5000"

ATTACK_STEPS = [
    {"path": "/", "method": "GET", "desc": "Recon: checking homepage"},
    {"path": "/login", "method": "POST", "data": {"username": "admin", "password": "admin123"}, "desc": "Credential probing attempt 1"},
    {"path": "/login", "method": "POST", "data": {"username": "admin", "password": "password"}, "desc": "Credential probing attempt 2"},
    {"path": "/login", "method": "POST", "data": {"username": "root", "password": "toor"}, "desc": "Credential probing attempt 3"},
    {"path": "/admin", "method": "GET", "desc": "Attacker finds and accesses fake admin panel (CANARY)"},
    {"path": "/internal/api/keys", "method": "GET", "desc": "Attacker exfiltrates fake API keys (CANARY)"},
    {"path": "/backup/download", "method": "GET", "desc": "Attacker attempts backup exfiltration (CANARY)"},
]


def get_latest_canary_endpoint():
    """Reads the deployed canaries file to find the most recent fake endpoint,
    simulating an attacker who discovered a planted trap."""
    try:
        with open("logs/deployed_canaries.json", "r") as f:
            canaries = json.load(f)
        if canaries:
            return canaries[-1].get("payload", {}).get("fake_endpoint")
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return None


def run_attack():
    print(f"[ATTACKER SIM] Starting attack sequence against {BASE_URL}\n")

    for step in ATTACK_STEPS:
        time.sleep(random.uniform(0.5, 1.5))
        url = BASE_URL + step["path"]

        try:
            if step["method"] == "GET":
                resp = requests.get(url, timeout=3)
            else:
                resp = requests.post(url, data=step.get("data", {}), timeout=3)

            print(f"[{step['method']}] {step['path']} -> {resp.status_code} | {step['desc']}")

        except requests.exceptions.ConnectionError:
            print(f"ERROR: Could not connect to {url}. Is mock_target.py running?")
            return

    # Simulate the attacker finding and hitting a dynamically deployed canary
    time.sleep(1)
    canary_endpoint = get_latest_canary_endpoint()
    if canary_endpoint:
        url = BASE_URL + canary_endpoint
        try:
            resp = requests.get(url, timeout=3)
            print(f"[GET] {canary_endpoint} -> {resp.status_code} | Attacker discovered and accessed DYNAMIC canary trap")
        except requests.exceptions.ConnectionError:
            print(f"ERROR: Could not connect to {url}")
    else:
        print("[ATTACKER SIM] No dynamic canary deployed yet to test against.")

    print("\n[ATTACKER SIM] Attack sequence complete. Check logs/access.log")


if __name__ == "__main__":
    run_attack()