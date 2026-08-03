from flask import Flask, request, jsonify
import json
import logging
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Set up logging to a file our agent will read
logging.basicConfig(
    filename="logs/access.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

with open("app/canary_config.json") as f:
    CANARY_CONFIG = json.load(f)


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


@app.route("/")
def home():
    log_event("normal_access", "Homepage visited")
    return "Welcome to MockCorp Internal Portal"


# --- Legit-looking but fake endpoints (bait) ---

@app.route("/admin")
def admin_panel():
    entry = log_event("CANARY_HIT", "Attacker accessed fake admin panel")
    return jsonify({"status": "Access granted", "message": "Welcome, admin"}), 200


@app.route("/internal/api/keys")
def fake_api_keys():
    entry = log_event("CANARY_HIT", "Attacker retrieved fake API keys")
    return jsonify({
        "aws_secret_key": os.getenv("FAKE_AWS_SECRET_KEY"),
        "admin_password": os.getenv("ADMIN_PASSWORD")
    }), 200


@app.route("/backup/download")
def fake_backup():
    entry = log_event("CANARY_HIT", "Attacker attempted backup download")
    return jsonify({"file": "backup_2026.zip", "size": "512MB"}), 200


# --- A normal-looking login endpoint attackers will probe ---

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log_event("login_attempt", f"username={username}")
    return jsonify({"error": "Invalid credentials"}), 401


if __name__ == "__main__":
    app.run(debug=True, port=5000)
