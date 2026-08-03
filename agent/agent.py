import json
import os
from datetime import datetime
from groq import Groq
from dotenv import load_dotenv

from .tools import parse_logs, check_ip_reputation
from .deception import deploy_canary, check_canary_hits
from .containment import generate_containment_plan

load_dotenv()

if not os.getenv("GROQ_API_KEY"):
    raise EnvironmentError(
        "GROQ_API_KEY is not set. Add it to your .env file before running the agent."
    )

client = Groq(api_key=os.getenv("GROQ_API_KEY"))

MODEL = "llama-3.3-70b-versatile"

TOOL_FUNCTIONS = {
    "parse_logs": lambda **kwargs: parse_logs(last_n=kwargs.get("last_n", 20)),
    "check_ip_reputation": lambda **kwargs: check_ip_reputation(kwargs["ip_address"]),
    "deploy_canary": lambda **kwargs: deploy_canary(
        trigger_reason=kwargs["trigger_reason"],
        canary_type=kwargs.get("canary_type", "fake_credential")
    ),
    "check_canary_hits": lambda **kwargs: check_canary_hits(),
    "generate_containment_plan": lambda **kwargs: generate_containment_plan(
        ip_address=kwargs["ip_address"],
        severity=kwargs["severity"],
        evidence_summary=kwargs["evidence_summary"]
    ),
}

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "parse_logs",
            "description": "Reads recent access log entries to see what activity has occurred, including canary hits and login attempts.",
            "parameters": {
                "type": "object",
                "properties": {
                    "last_n": {"type": "integer", "description": "Number of recent log entries to read"}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_ip_reputation",
            "description": "Looks up threat intelligence on a given IP address using AbuseIPDB to determine if it's a known malicious source.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "The IP address to investigate"}
                },
                "required": ["ip_address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "deploy_canary",
            "description": "Dynamically deploys a new fake credential or endpoint as a deception trap, in response to detected suspicious activity. Use this when recon or probing behavior is detected but you want more evidence before escalating.",
            "parameters": {
                "type": "object",
                "properties": {
                    "trigger_reason": {"type": "string", "description": "Why this canary is being deployed"},
                    "canary_type": {"type": "string", "enum": ["fake_credential", "fake_endpoint"]}
                },
                "required": ["trigger_reason"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_canary_hits",
            "description": "Checks whether any previously deployed canary traps have been triggered by an attacker.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "generate_containment_plan",
            "description": "Generates concrete firewall block commands (iptables, AWS Security Group) and patch recommendations for a confirmed malicious IP. Use this only after you have enough evidence to justify containment (e.g., confirmed canary hits plus suspicious IP reputation).",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_address": {"type": "string", "description": "The IP address to contain"},
                    "severity": {"type": "string", "enum": ["recon", "active_exploitation"]},
                    "evidence_summary": {"type": "string", "description": "Brief summary of why containment is justified"}
                },
                "required": ["ip_address", "severity", "evidence_summary"]
            }
        }
    },
]

SYSTEM_PROMPT = """You are HoneyMesh, an autonomous security triage agent monitoring a corporate web application.

Your job: investigate suspicious activity end-to-end and produce a triage decision. You have tools to:
- read logs
- check IP reputation
- deploy deception traps (canaries) to gather more evidence on uncertain threats
- check if any deployed canaries have been triggered
- generate a containment plan (firewall block commands + patch recommendations) once exploitation is confirmed

You must reason step by step and decide WHICH tools to call and WHEN, based on what you learn from each tool result. Do not call every tool blindly — call only what the evidence justifies.

If you find credential-stuffing/recon activity but aren't sure of intent, deploying a canary is a reasonable investigative step.
If you find canary hits and a malicious IP reputation, that confirms active exploitation, not just recon.

If the verdict is "active_exploitation" with reasonable confidence, call generate_containment_plan before writing your final report, so the report can reference concrete containment steps.

STOP calling tools once you have enough evidence and, where justified, a containment plan. Then produce a final structured report with:
- verdict: "benign" | "recon" | "active_exploitation"
- confidence: 0-100
- evidence_summary: what you found and from which tools
- recommended_action: what a human analyst should do next (e.g., block IP, rotate credentials, escalate to IR team)

Be concise but thorough. This is a real triage report, not a chatbot answer."""


def _safe_parse_args(raw_args):
    """
    Groq sometimes sends None, empty string, or the literal string 'null'
    for tools that take no arguments. Normalize all of these to {}.
    """
    if not raw_args:
        return {}
    try:
        parsed = json.loads(raw_args)
    except (json.JSONDecodeError, TypeError):
        return {}
    if parsed is None:
        return {}
    return parsed


def run_agent(user_prompt="Investigate the current activity on the mock target application and produce a triage report."):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]
    investigation_log = []

    print("=" * 60)
    print("HONEYMESH AGENT — Investigation Starting")
    print("=" * 60)

    for turn in range(8):
        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            max_tokens=2000
        )

        choice = response.choices[0]
        msg = choice.message

        if msg.content:
            print(f"\n[AGENT REASONING]: {msg.content.strip()}")
            investigation_log.append({"type": "reasoning", "content": msg.content.strip()})

        messages.append({
            "role": "assistant",
            "content": msg.content,
            "tool_calls": msg.tool_calls
        })

        if not msg.tool_calls:
            final_text = msg.content or ""
            print("\n--- FINAL TRIAGE REPORT ---\n")
            print(final_text)
            investigation_log.append({"type": "final_report", "content": final_text})
            _save_report(investigation_log, final_text)
            return final_text

        for tool_call in msg.tool_calls:
            tool_name = tool_call.function.name
            tool_input = _safe_parse_args(tool_call.function.arguments)

            print(f"[TOOL CALL] {tool_name}({tool_input})")

            try:
                result = TOOL_FUNCTIONS[tool_name](**tool_input)
            except Exception as e:
                result = {"error": f"Tool execution failed: {str(e)}"}

            print(f"[TOOL RESULT] {json.dumps(result, indent=2)[:500]}")

            investigation_log.append({
                "type": "tool_call",
                "tool": tool_name,
                "input": tool_input,
                "result": result
            })

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result)
            })

    print("Reached max reasoning turns without a final report.")
    return None


def _save_report(investigation_log, final_report):
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/triage_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump({
            "investigation_log": investigation_log,
            "final_report": final_report
        }, f, indent=2)
    print(f"\nFull investigation log saved to {filename}")


if __name__ == "__main__":
    run_agent()