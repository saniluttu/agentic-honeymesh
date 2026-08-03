import json
import os
import requests
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY")


def parse_logs(log_path="logs/access.log", last_n=20):
    """
    Reads the last N entries from the access log and returns them as
    structured events. Skips malformed lines instead of crashing,
    and reports how many were skipped for transparency.
    """
    if not os.path.exists(log_path):
        return {"error": f"Log file not found at {log_path}", "total_events": 0}

    with open(log_path, "r") as f:
        lines = f.readlines()

    events = []
    skipped = 0
    for line in lines[-last_n:]:
        try:
            json_part = line.split("| ", 1)[1].strip()
            event = json.loads(json_part)
            events.append(event)
        except (IndexError, json.JSONDecodeError):
            skipped += 1
            continue

    canary_hits = [e for e in events if e.get("event_type") in ("CANARY_HIT", "DYNAMIC_CANARY_HIT")]
    login_attempts = [e for e in events if e.get("event_type") == "login_attempt"]

    return {
        "total_events": len(events),
        "skipped_malformed_lines": skipped,
        "canary_hits": canary_hits,
        "login_attempts": login_attempts,
        "unique_ips": list(set(e.get("ip") for e in events if e.get("ip"))),
        "all_events": events
    }


def check_ip_reputation(ip_address):
    """
    Queries AbuseIPDB for threat intel on a given IP.
    Real external tool call, not simulated. Handles missing keys,
    rate limits, and network failures gracefully so the agent
    always gets a usable result instead of crashing.
    """
    if ip_address in ("127.0.0.1", "localhost", "::1"):
        return {
            "ip": ip_address,
            "abuse_score": 0,
            "is_local_test": True,
            "note": "Local/loopback address - treating as simulated attacker for demo purposes"
        }

    if not ABUSEIPDB_KEY:
        return {
            "ip": ip_address,
            "error": "ABUSEIPDB_API_KEY not configured",
            "abuse_score": None,
            "is_local_test": False
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=5)

        if resp.status_code == 429:
            return {
                "ip": ip_address,
                "error": "Rate limited by AbuseIPDB (429). Try again later.",
                "abuse_score": None,
                "is_local_test": False
            }

        if resp.status_code != 200:
            return {
                "ip": ip_address,
                "error": f"AbuseIPDB returned status {resp.status_code}",
                "abuse_score": None,
                "is_local_test": False
            }

        data = resp.json().get("data", {})
        return {
            "ip": ip_address,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "total_reports": data.get("totalReports", 0),
            "is_local_test": False
        }

    except requests.exceptions.Timeout:
        return {"ip": ip_address, "error": "Request to AbuseIPDB timed out", "abuse_score": None}
    except requests.exceptions.ConnectionError:
        return {"ip": ip_address, "error": "Could not connect to AbuseIPDB (network issue)", "abuse_score": None}
    except Exception as e:
        return {"ip": ip_address, "error": str(e), "abuse_score": None}


if __name__ == "__main__":
    print("Testing parse_logs():")
    print(json.dumps(parse_logs(), indent=2))

    print("\nTesting check_ip_reputation() on localhost:")
    print(json.dumps(check_ip_reputation("127.0.0.1"), indent=2))