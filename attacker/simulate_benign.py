import requests
import time
import random

BASE_URL = "http://127.0.0.1:5000"

# Normal user behavior - no canary hits, no credential stuffing
BENIGN_STEPS = [
    {"path": "/", "method": "GET", "desc": "Normal user visits homepage"},
    {"path": "/", "method": "GET", "desc": "Normal user refreshes homepage"},
    {"path": "/login", "method": "POST", "data": {"username": "sanika", "password": "correct_password_probably"}, "desc": "Single legitimate-looking login attempt"},
]


def run_benign_traffic():
    print(f"[BENIGN SIM] Starting normal user traffic against {BASE_URL}\n")

    for step in BENIGN_STEPS:
        time.sleep(random.uniform(1.0, 2.0))
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

    print("\n[BENIGN SIM] Normal traffic complete. No canaries hit, no exploitation.")


if __name__ == "__main__":
    run_benign_traffic()