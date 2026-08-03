import streamlit as st
import json
import sys
import os
from io import StringIO
import contextlib

sys.path.insert(0, os.path.dirname(__file__))

from agent.agent import run_agent

st.set_page_config(page_title="Agentic-HoneyMesh", page_icon="🍯", layout="wide")

st.title("🍯 Agentic-HoneyMesh")
st.caption("Autonomous Deception & Threat Response Engine")

col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("Control Panel")
    st.markdown("""
    **What this agent does:**
    1. Reads live application logs
    2. Checks IP reputation against threat intel
    3. Deploys deception traps if needed
    4. Generates containment commands for confirmed threats
    5. Produces a structured triage report
    """)

    run_button = st.button("🚀 Run Investigation", type="primary", use_container_width=True)

    st.divider()
    st.subheader("Deployed Canaries")
    canary_file = "logs/deployed_canaries.json"
    if os.path.exists(canary_file):
        with open(canary_file) as f:
            canaries = json.load(f)
        st.metric("Total Deployed", len(canaries))
        for c in canaries[-3:]:
            with st.expander(f"🪤 {c['canary_id']}"):
                st.json(c)
    else:
        st.info("No canaries deployed yet.")

with col2:
    st.subheader("Live Investigation Log")

    if run_button:
        log_placeholder = st.empty()
        captured_output = StringIO()

        with st.spinner("Agent investigating..."):
            with contextlib.redirect_stdout(captured_output):
                final_report = run_agent()

        output_text = captured_output.getvalue()

        # Split into sections for nicer display
        for line in output_text.split("\n"):
            if line.startswith("[TOOL CALL]"):
                st.info(line)
            elif line.startswith("[TOOL RESULT]"):
                with st.expander("View tool result", expanded=False):
                    st.code(line.replace("[TOOL RESULT] ", ""), language="json")
            elif line.startswith("[AGENT REASONING]"):
                st.warning(line)
            elif line.strip() and "=" not in line and "---" not in line:
                st.text(line)

        st.divider()
        st.subheader("📋 Final Triage Report")
        st.markdown(final_report)

    else:
        st.info("Click 'Run Investigation' to start the agent.")

st.divider()
st.subheader("📁 Past Triage Reports")
reports_dir = "reports"
if os.path.exists(reports_dir):
    report_files = sorted(os.listdir(reports_dir), reverse=True)
    if report_files:
        selected = st.selectbox("Select a past report", report_files)
        if selected:
            with open(os.path.join(reports_dir, selected)) as f:
                data = json.load(f)
            st.markdown(data.get("final_report", "No report content."))
    else:
        st.info("No past reports yet.")