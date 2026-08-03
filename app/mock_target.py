from flask import Flask, request, jsonify
import json
import logging
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

logging.basicConfig(
    filename="logs/access.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

with open("app/canary_config.json") as f:
    CANARY_CONFIG = json.load(f)

DEPLOYED_CANARIES_FILE = "logs/deployed_canaries.json"


def log_event(event_type, details):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event_type": event_type,
        "ip": request.remote_addr,
        "path": request.path,
        "method": request.method,
        "details": details
    }
    logging.info(json.dumps(entry))
    return entry


def _get_active_canary_endpoints():
    """Reads deployed canaries and returns a map of {fake_endpoint: canary_id}."""
    if not os.path.exists(DEPLOYED_CANARIES_FILE):
        return {}
    with open(DEPLOYED_CANARIES_FILE, "r") as f:
        canaries = json.load(f)
    active = {}
    for c in canaries:
        endpoint = c.get("payload", {}).get("fake_endpoint")
        if endpoint:
            active[endpoint] = c["canary_id"]
    return active


def _mark_canary_hit(canary_id):
    with open(DEPLOYED_CANARIES_FILE, "r") as f:
        canaries = json.load(f)
    for c in canaries:
        if c["canary_id"] == canary_id:
            c["hit"] = True
            c["hit_at"] = datetime.utcnow().isoformat()
    with open(DEPLOYED_CANARIES_FILE, "w") as f:
        json.dump(canaries, f, indent=2)


# --- Static routes (must be defined BEFORE the catch-all route below) ---

@app.route("/")
def home():
    log_event("normal_access", "Homepage visited")
    return "Welcome to MockCorp Internal Portal"


@app.route("/admin")
def admin_panel():
    log_event("CANARY_HIT", "Attacker accessed fake admin panel")
    return jsonify({"status": "Access granted", "message": "Welcome, admin"}), 200


@app.route("/internal/api/keys")
def fake_api_keys():
    log_event("CANARY_HIT", "Attacker retrieved fake API keys")
    return jsonify({
        "aws_secret_key": os.getenv("FAKE_AWS_SECRET_KEY"),
        "admin_password": os.getenv("ADMIN_PASSWORD")
    }), 200


@app.route("/backup/download")
def fake_backup():
    log_event("CANARY_HIT", "Attacker attempted backup download")
    return jsonify({"file": "backup_2026.zip", "size": "512MB"}), 200


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log_event("login_attempt", f"username={username}")
    return jsonify({"error": "Invalid credentials"}), 401


# --- Catch-all route for DYNAMICALLY deployed canaries ---
# This MUST be the last route defined so it doesn't shadow the routes above.

@app.route("/<path:dynamic_path>")
def catch_dynamic_canary(dynamic_path):
    full_path = "/" + dynamic_path
    active_canaries = _get_active_canary_endpoints()

    if full_path in active_canaries:
        canary_id = active_canaries[full_path]
        log_event("DYNAMIC_CANARY_HIT", f"Attacker accessed dynamically deployed canary: {canary_id}")
        _mark_canary_hit(canary_id)
        return jsonify({"status": "success", "data": "sensitive_vault_contents_here"}), 200

    log_event("normal_404", f"Unknown path accessed: {full_path}")
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    app.run(debug=True, port=5000)