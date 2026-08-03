import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")


def parse_logs(log_path="logs/access.log", last_n=20):
    """
    Reads the last N entries from the access log and returns them as
    structured events. This is how the agent 'sees' what happened.
    """
    if not os.path.exists(log_path):
        return {"error": f"Log file not found at {log_path}"}

    with open(log_path, "r") as f:
        lines = f.readlines()

    events = []
    for line in lines[-last_n:]:
        try:
            # log format: "timestamp | {json}"
            json_part = line.split("| ", 1)[1].strip()
            event = json.loads(json_part)
            events.append(event)
        except (IndexError, json.JSONDecodeError):
            continue

    canary_hits = [e for e in events if e.get("event_type") == "CANARY_HIT"]
    login_attempts = [e for e in events if e.get("event_type") == "login_attempt"]

    return {
        "total_events": len(events),
        "canary_hits": canary_hits,
        "login_attempts": login_attempts,
        "unique_ips": list(set(e.get("ip") for e in events if e.get("ip"))),
        "all_events": events
    }


def check_ip_reputation(ip_address):
    """
    Queries AbuseIPDB for threat intel on a given IP.
    Real external tool call, not simulated.
    """
    if ip_address in ("127.0.0.1", "localhost", "::1"):
        # Local testing IP - return a mock "known local" response so
        # the demo still works without a real malicious IP
        return {
            "ip": ip_address,
            "abuse_score": 0,
            "is_local_test": True,
            "note": "Local/loopback address - treating as simulated attacker for demo purposes"
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)
        data = resp.json().get("data", {})
        return {
            "ip": ip_address,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports", 0),
            "is_local_test": False
        }
    except Exception as e:
        return {"ip": ip_address, "error": str(e)}


if __name__ == "__main__":
    # Quick manual test
    print("Testing parse_logs():")
    print(json.dumps(parse_logs(), indent=2))

    print("\nTesting check_ip_reputation() on localhost:")
    print(json.dumps(check_ip_reputation("127.0.0.1"), indent=2))