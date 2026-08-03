import json
import os
from datetime import datetime

CONTAINMENT_LOG_FILE = "logs/containment_actions.json"


def _load_actions():
    if not os.path.exists(CONTAINMENT_LOG_FILE):
        return []
    with open(CONTAINMENT_LOG_FILE, "r") as f:
        return json.load(f)


def _save_actions(actions):
    with open(CONTAINMENT_LOG_FILE, "w") as f:
        json.dump(actions, f, indent=2)


def generate_containment_plan(ip_address, severity, evidence_summary):
    """
    Generates concrete, ready-to-review containment commands for a human
    analyst to approve and execute. Does NOT execute anything automatically —
    containment actions always require human sign-off in this design.
    """
    timestamp = datetime.utcnow().isoformat()

    iptables_rule = f"iptables -A INPUT -s {ip_address} -j DROP"
    aws_sg_rule = (
        f"aws ec2 revoke-security-group-ingress "
        f"--group-id <SECURITY_GROUP_ID> "
        f"--protocol tcp --port 0-65535 --cidr {ip_address}/32"
    )

    patch_recommendations = []
    if severity == "active_exploitation":
        patch_recommendations = [
            "Rotate all credentials exposed via the compromised endpoint(s) immediately.",
            "Review access logs for this IP across all environments, not just this one.",
            "Add this IP to a persistent blocklist, not just an ephemeral rule.",
            "If the admin panel or key endpoint is real (not a canary) in production, patch/remove public exposure."
        ]
    elif severity == "recon":
        patch_recommendations = [
            "Monitor this IP for escalation before blocking, to gather more attacker TTP data.",
            "Consider rate-limiting instead of a hard block if this may be a false positive."
        ]

    plan = {
        "generated_at": timestamp,
        "target_ip": ip_address,
        "severity": severity,
        "evidence_summary": evidence_summary,
        "commands": {
            "iptables": iptables_rule,
            "aws_security_group": aws_sg_rule
        },
        "patch_recommendations": patch_recommendations,
        "requires_human_approval": True,
        "status": "pending_review"
    }

    actions = _load_actions()
    actions.append(plan)
    _save_actions(actions)

    return plan


if __name__ == "__main__":
    test_plan = generate_containment_plan(
        ip_address="203.0.113.42",
        severity="active_exploitation",
        evidence_summary="Multiple canary hits confirmed, IP flagged in AbuseIPDB with high confidence score."
    )
    print(json.dumps(test_plan, indent=2))