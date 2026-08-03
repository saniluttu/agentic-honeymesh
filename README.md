# 🍯 Agentic-HoneyMesh

**Autonomous Deception & Threat Response Engine**

Built by **Sanika K** for the Oblivion Works AI Hackathon (Cybersecurity Track)

---

## The Problem

Security teams are flooded with low-context alerts every day — failed logins, endpoint probes, scanner traffic — and most of it is noise. A human analyst has to manually triage each one: is this a bot? A curious script kiddie? Someone actively trying to get in? By the time a human gets to it, the attacker may already be gone, or worse, already inside.

Passive logging and static alerting don't solve this. They tell you *something happened*, but they don't investigate, they don't gather more evidence when the picture is unclear, and they definitely don't do anything to slow an attacker down while a human catches up.

**Agentic-HoneyMesh** is an autonomous agent that closes that gap: it detects suspicious activity, actively deploys deception traps to gather more evidence when intent is unclear, cross-references real threat intelligence, and — when evidence justifies it — generates concrete containment commands for a human to approve. It behaves like a junior SOC analyst who never sleeps and never gets bored of checking the fifth similar-looking IP.

## Why I Chose This Problem

The hackathon brief explicitly asked for agents that go beyond "read logs, flag anomaly, ask the user what to do." That passive pattern is the most common submission for a cybersecurity AI challenge, so I wanted to build something that takes *action* — not by executing live changes against real infrastructure (which would be reckless in a hackathon-scale project), but by actively shaping the attacker's experience through deception while a human stays in the loop for anything destructive. Deception technology (honeypots, canary tokens) is a real, respected area of commercial security engineering — companies like Thinkst Canary build entire products around this idea — so I wanted to explore it with an LLM agent driving the decisions instead of static rules.

## How It Works

1. **Detection** — the agent reads structured access logs from a mock vulnerable web application, looking for patterns like credential-stuffing attempts and access to sensitive-looking endpoints.
2. **Threat Intelligence** — for any IP involved, it queries AbuseIPDB for real-world reputation data (abuse confidence score, report history).
3. **Deception** — if the evidence is suggestive but not conclusive, the agent can dynamically generate a brand-new fake credential and a corresponding fake endpoint, and the mock application will actually serve that endpoint. If the attacker takes the bait, that's a strong, unambiguous signal of malicious intent.
4. **Containment** — once evidence crosses the threshold into confirmed exploitation, the agent generates concrete `iptables` and AWS Security Group block commands, plus patch recommendations. These are **generated for human review, never auto-executed** — a deliberate safety design choice, not a limitation (see below).
5. **Triage Report** — the agent produces a structured final verdict: `benign` / `recon` / `active_exploitation`, a confidence score, an evidence summary, and a recommended next action.

Critically, the agent decides **which** of these stages to run and in what order, based on what it learns at each step — it is not a fixed if/else pipeline. Running the exact same agent against a genuinely benign traffic pattern produces a different verdict path (no canary deployed, no containment generated) than running it against the attack simulation (canary deployed and triggered, containment plan generated). Both scenarios are included in this repo so this can be verified directly.

## Architecture

```
┌───────────────────────┐
│   Mock Target App      │  Flask app with intentionally "vulnerable"
│  (app/mock_target.py)  │  endpoints + dynamic canary serving
└───────────┬─────────────┘
            │ writes structured JSON logs
            ▼
┌───────────────────────┐
│   logs/access.log       │
│   logs/deployed_        │
│        canaries.json    │
└───────────┬─────────────┘
            │ read by tools
            ▼
┌─────────────────────────────────────────────────┐
│              HoneyMesh Agent Loop                  │
│           (agent/agent.py, LLM-driven)             │
│                                                     │
│  Tools available to the LLM:                       │
│   • parse_logs()                — Detection          │
│   • check_ip_reputation()       — Threat Intel        │
│   • deploy_canary()             — Deception            │
│   • check_canary_hits()         — Deception            │
│   • generate_containment_plan() — Containment          │
│                                                     │
│  The LLM (via Groq) reasons step-by-step, calling  │
│  tools based on prior results, until it has enough │
│  evidence to produce a final structured verdict.   │
└───────────┬─────────────────────────────────────────┘
            │
            ▼
┌───────────────────────┐
│   Streamlit Dashboard   │  Live visual timeline of the
│     (dashboard.py)      │  investigation, canary status,
│                         │  and final triage report
└───────────────────────┘
```

Two attacker simulation scripts (`attacker/simulate_attack.py` and `attacker/simulate_benign.py`) generate realistic log data for a malicious scenario and a benign scenario respectively, so the agent's differentiated reasoning can be demonstrated directly.

## Technologies, Frameworks, and Models Used

- **Python 3.10**
- **Flask** — mock vulnerable target application
- **Groq API** (Llama 3.3 70B) — the LLM powering the agent's reasoning and tool-use loop
- **AbuseIPDB API** — real-world IP threat intelligence
- **Streamlit** — live investigation dashboard
- **python-dotenv** — environment/secret management
- **unittest** — test suite for core tools

## Setup and Run Instructions

**1. Clone and set up the environment:**
```bash
git clone https://github.com/saniluttu/agentic-honeymesh.git
cd agentic-honeymesh
python -m venv venv
venv\Scripts\Activate.ps1      # Windows
source venv/bin/activate       # Mac/Linux
pip install -r requirements.txt
```

**2. Configure API keys** — create a `.env` file in the project root:
```
GROQ_API_KEY=your_groq_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
FAKE_AWS_SECRET_KEY=AKIA_FAKE_HONEYPOT_KEY_DO_NOT_USE
ADMIN_PASSWORD=SuperSecret123!
```
- Groq API key (free tier): https://console.groq.com
- AbuseIPDB API key (free tier): https://abuseipdb.com

**3. Start the mock target application** (leave running in its own terminal):
```bash
python app/mock_target.py
```

**4. Generate demo traffic** — in a second terminal, run either scenario:
```bash
python attacker/simulate_attack.py     # malicious scenario
python attacker/simulate_benign.py     # benign scenario
```
To reset state between scenarios (stop `mock_target.py` first):
```bash
python reset_demo_state.py
```

**5. Run the agent directly (CLI):**
```bash
python -m agent.agent
```

**6. Or launch the visual dashboard:**
```bash
streamlit run dashboard.py
```
Then click "Run Investigation" in the browser.

**7. Run the test suite:**
```bash
python -m unittest tests.test_tools -v
```

## Assumptions, Limitations, and Future Improvements

**Assumptions:**
- The mock target application simulates a vulnerable web app; it is not a production system, and its "vulnerabilities" are intentional bait, not real security flaws.
- `127.0.0.1` (localhost) is treated as a stand-in "attacker" IP for demo purposes, since all traffic in this hackathon build originates locally.

**Limitations:**
- Containment commands (`iptables`/AWS Security Group rules) are **generated, not executed**. This is a deliberate safety design choice: a hackathon-scale agent should never have unsupervised authority to modify real firewall or cloud infrastructure. A production version of this system would integrate with a human-approval workflow (e.g., a Slack approval step) before any command is actually run.
- Threat intelligence is currently limited to AbuseIPDB; a production system would cross-reference multiple sources (VirusTotal, Shodan, internal threat feeds).
- The deception system currently generates fake credentials/endpoints; it does not yet simulate more advanced honeypot behaviors like fake file systems or interactive fake shells.
- The agent runs as a single on-demand investigation rather than a continuously running monitor; a production version would run on a schedule or be triggered by real-time log streaming.

**Future improvements:**
- Multi-source threat intelligence aggregation
- A human-in-the-loop approval UI for containment actions directly in the dashboard
- Persistent, continuously-running monitoring instead of on-demand runs
- More sophisticated deception assets (fake file trees, interactive fake services)
- Model-agnostic tool-calling layer (currently coupled to Groq's function-calling format)

## Development Note

This project was built end-to-end in a single day for the hackathon, with the agent's core reasoning loop, the deception system, containment generation, and the dashboard all iterated and tested incrementally (see commit history).
