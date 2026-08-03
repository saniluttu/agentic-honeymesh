import json
import os
import random
import string
from datetime import datetime

DEPLOYED_CANARIES_FILE = "logs/deployed_canaries.json"


def _load_deployed():
    if not os.path.exists(DEPLOYED_CANARIES_FILE):
        return []
    with open(DEPLOYED_CANARIES_FILE, "r") as f:
        return json.load(f)


def _save_deployed(canaries):
    with open(DEPLOYED_CANARIES_FILE, "w") as f:
        json.dump(canaries, f, indent=2)


def _random_token(length=24):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


def deploy_canary(trigger_reason, canary_type="fake_credential"):
    """
    Dynamically generates and 'deploys' a new deception asset in response
    to detected suspicious activity. In a real system this would write
    into an actual config/env the attacker could reach; here we simulate
    the deployment and record it so we can detect if it gets touched.
    """
    canary_id = f"canary_{_random_token(8)}"
    timestamp = datetime.utcnow().isoformat()

    if canary_type == "fake_credential":
        payload = {
            "type": "fake_credential",
            "fake_api_key": f"sk-decoy-{_random_token(32)}",
            "fake_endpoint": f"/internal/vault_{_random_token(6)}"
        }
    elif canary_type == "fake_endpoint":
        payload = {
            "type": "fake_endpoint",
            "fake_endpoint": f"/api/v2/admin_{_random_token(6)}/export"
        }
    else:
        payload = {"type": "unknown", "note": "unrecognized canary_type, defaulted"}

    canary_record = {
        "canary_id": canary_id,
        "deployed_at": timestamp,
        "trigger_reason": trigger_reason,
        "payload": payload,
        "hit": False,
        "hit_at": None
    }

    canaries = _load_deployed()
    canaries.append(canary_record)
    _save_deployed(canaries)

    return {
        "status": "deployed",
        "canary_id": canary_id,
        "details": canary_record
    }


def check_canary_hits():
    """
    Checks whether any previously-deployed canary has been touched.
    For the hackathon demo, 'touched' is simulated by the attacker
    script referencing a canary_id (see Step 5.3 below).
    """
    canaries = _load_deployed()
    hits = [c for c in canaries if c["hit"]]
    pending = [c for c in canaries if not c["hit"]]

    return {
        "total_deployed": len(canaries),
        "hits": hits,
        "pending": pending
    }


def mark_canary_hit(canary_id):
    """Marks a specific canary as triggered — called when a hit is detected."""
    canaries = _load_deployed()
    for c in canaries:
        if c["canary_id"] == canary_id:
            c["hit"] = True
            c["hit_at"] = datetime.utcnow().isoformat()
    _save_deployed(canaries)
    return {"canary_id": canary_id, "status": "marked_as_hit"}


if __name__ == "__main__":
    print("Deploying a test canary:")
    result = deploy_canary(trigger_reason="Repeated failed login attempts detected", canary_type="fake_credential")
    print(json.dumps(result, indent=2))

    print("\nChecking canary status:")
    print(json.dumps(check_canary_hits(), indent=2))