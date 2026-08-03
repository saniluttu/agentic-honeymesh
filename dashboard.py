import streamlit as st
import json
import sys
import os
from io import StringIO
import contextlib

sys.path.insert(0, os.path.dirname(__file__))

from agent.agent import run_agent

st.set_page_config(page_title="Agentic-HoneyMesh", page_icon="🬢", layout="wide")

# --- Dark professional theme, inspired by Oblivion Works' site ---
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background-color: #0a0a0a;
    color: #e5e5e5;
}

section[data-testid="stSidebar"] {
    background-color: #0f0f0f;
}

/* Hero header */
.hero-title {
    font-size: 2.6rem;
    font-weight: 800;
    color: #ffffff;
    margin-bottom: 0;
    letter-spacing: -0.02em;
}
.hero-subtitle {
    color: #999999;
    font-size: 1.05rem;
    margin-top: 4px;
    margin-bottom: 28px;
}

/* Section labels */
.section-label {
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-size: 0.75rem;
    color: #666666;
    font-weight: 600;
    margin-bottom: 10px;
}

/* Cards */
.card {
    background-color: #141414;
    border: 1px solid #262626;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 14px;
}

/* Pipeline stage boxes */
.stage-box {
    background-color: #141414;
    border: 1px solid #262626;
    border-left: 3px solid #444444;
    padding: 14px 18px;
    border-radius: 8px;
    margin-bottom: 10px;
}
.stage-box.tool-call {
    border-left-color: #5b9dff;
}
.stage-box.reasoning {
    border-left-color: #666666;
    font-style: italic;
    color: #b3b3b3;
}
.stage-label {
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #888888;
    font-weight: 600;
    margin-bottom: 4px;
}
.stage-code {
    font-family: 'JetBrains Mono', monospace;
    color: #e5e5e5;
    font-size: 0.88rem;
}

/* Verdict badges */
.verdict-badge {
    display: inline-block;
    padding: 6px 16px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}
.verdict-benign { background-color: rgba(0,200,120,0.15); color: #00c878; border: 1px solid rgba(0,200,120,0.3); }
.verdict-recon { background-color: rgba(255,170,0,0.15); color: #ffaa00; border: 1px solid rgba(255,170,0,0.3); }
.verdict-active { background-color: rgba(255,60,60,0.15); color: #ff3c3c; border: 1px solid rgba(255,60,60,0.3); }

/* Buttons */
.stButton > button {
    background-color: #ffffff;
    color: #0a0a0a;
    font-weight: 600;
    border-radius: 8px;
    border: none;
    padding: 0.6rem 1.2rem;
}
.stButton > button:hover {
    background-color: #e5e5e5;
    color: #0a0a0a;
}

/* Metric styling */
[data-testid="stMetricValue"] {
    color: #ffffff;
}

hr {
    border-color: #262626;
}
</style>
""", unsafe_allow_html=True)

TOOL_STAGE_MAP = {
    "parse_logs": "DETECTION",
    "check_ip_reputation": "THREAT INTEL",
    "deploy_canary": "DECEPTION",
    "check_canary_hits": "DECEPTION",
    "generate_containment_plan": "CONTAINMENT",
}

# --- Header ---
st.markdown('<div class="hero-title">Agentic-HoneyMesh</div>', unsafe_allow_html=True)
st.markdown('<div class="hero-subtitle">Autonomous deception & threat response engine — detects, deceives, investigates, and contains, without a fixed script.</div>', unsafe_allow_html=True)

col1, col2 = st.columns([1, 2], gap="large")

with col1:
    st.markdown('<div class="section-label">Control Panel</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="card">
    <b>Pipeline stages</b><br><br>
    🔍 Detection — reads live logs<br>
    🌐 Threat Intel — checks IP reputation<br>
    🪤 Deception — deploys / checks canary traps<br>
    🛡️ Containment — generates block commands<br><br>
    <span style="color:#777; font-size:0.85rem;">The agent decides which stages to run and in what order — nothing here is a fixed script.</span>
    </div>
    """, unsafe_allow_html=True)

    run_button = st.button("Run Investigation", type="primary", use_container_width=True)

    st.markdown('<div class="section-label" style="margin-top:24px;">Deployed Canaries</div>', unsafe_allow_html=True)
    canary_file = "logs/deployed_canaries.json"
    if os.path.exists(canary_file):
        with open(canary_file) as f:
            canaries = json.load(f)
        hit_count = sum(1 for c in canaries if c.get("hit"))
        c1, c2 = st.columns(2)
        c1.metric("Deployed", len(canaries))
        c2.metric("Triggered", hit_count)
        for c in canaries[-3:]:
            status = "🔴 Triggered" if c["hit"] else "⚪ Pending"
            with st.expander(f"{status} — {c['canary_id']}"):
                st.json(c)
    else:
        st.caption("No canaries deployed yet.")

with col2:
    st.markdown('<div class="section-label">Live Investigation Timeline</div>', unsafe_allow_html=True)

    if run_button:
        captured_output = StringIO()
        with st.spinner("Agent investigating..."):
            with contextlib.redirect_stdout(captured_output):
                final_report = run_agent()

        output_text = captured_output.getvalue()
        lines = output_text.split("\n")
        stages_seen = []
        i = 0
        while i < len(lines):
            line = lines[i]

            if line.startswith("[TOOL CALL]"):
                tool_name = line.split("]")[1].strip().split("(")[0]
                stage = TOOL_STAGE_MAP.get(tool_name, "PROCESSING")
                if stage not in stages_seen:
                    stages_seen.append(stage)
                st.markdown(f"""
                <div class="stage-box tool-call">
                <div class="stage-label">{stage}</div>
                <div class="stage-code">{line.replace("[TOOL CALL] ", "")}</div>
                </div>
                """, unsafe_allow_html=True)
                i += 1

            elif line.startswith("[TOOL RESULT]"):
                result_lines = [line.replace("[TOOL RESULT] ", "")]
                i += 1
                while (
                    i < len(lines)
                    and not lines[i].startswith("[TOOL CALL]")
                    and not lines[i].startswith("[AGENT REASONING]")
                    and "FINAL TRIAGE REPORT" not in lines[i]
                ):
                    result_lines.append(lines[i])
                    i += 1
                with st.expander("View tool result"):
                    st.code("\n".join(result_lines), language="json")

            elif line.startswith("[AGENT REASONING]"):
                st.markdown(f"""
                <div class="stage-box reasoning">
                {line.replace("[AGENT REASONING]: ", "")}
                </div>
                """, unsafe_allow_html=True)
                i += 1
            else:
                i += 1

        st.markdown('<div class="section-label" style="margin-top:20px;">Pipeline Stages Executed</div>', unsafe_allow_html=True)
        all_stages = ["DETECTION", "THREAT INTEL", "DECEPTION", "CONTAINMENT"]
        cols = st.columns(len(all_stages))
        for idx, stage in enumerate(all_stages):
            with cols[idx]:
                if stage in stages_seen:
                    st.success(stage)
                else:
                    st.caption(f"⬜ {stage}")
        st.caption("Greyed-out stages were skipped — the agent only escalates when evidence justifies it.")

        st.markdown('<div class="section-label" style="margin-top:24px;">Final Triage Report</div>', unsafe_allow_html=True)

        badge_class = "verdict-benign"
        if "active_exploitation" in final_report.lower():
            badge_class = "verdict-active"
        elif "recon" in final_report.lower():
            badge_class = "verdict-recon"

        st.markdown(final_report)
    else:
        st.caption("Click 'Run Investigation' to start the agent.")

st.markdown("---")
st.markdown('<div class="section-label">Past Triage Reports</div>', unsafe_allow_html=True)
reports_dir = "reports"
if os.path.exists(reports_dir):
    report_files = sorted(os.listdir(reports_dir), reverse=True)
    if report_files:
        selected = st.selectbox("Select a past report", report_files)
        if selected:
            with open(os.path.join(reports_dir, selected)) as f:
                data = json.load(f)
            st.caption(f"Generated: {selected.replace('triage_', '').replace('.json', '')}")
            st.markdown(data.get("final_report", "No report content."))
    else:
        st.caption("No past reports yet.")