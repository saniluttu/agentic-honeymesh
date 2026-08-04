import streamlit as st
import json
import sys
import os
import re
from io import StringIO
from datetime import datetime
import contextlib
from fpdf import FPDF

sys.path.insert(0, os.path.dirname(__file__))

from agent.agent import run_agent

st.set_page_config(page_title="Agentic-HoneyMesh", page_icon="🍯", layout="wide")

# --- Dark professional theme ---
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

.section-label {
    text-transform: uppercase;
    letter-spacing: 0.08em;
    font-size: 0.75rem;
    color: #666666;
    font-weight: 600;
    margin-bottom: 10px;
}

.card {
    background-color: #141414;
    border: 1px solid #262626;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 14px;
}

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

.verdict-badge {
    display: inline-block;
    padding: 8px 20px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.95rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 12px;
}
.verdict-benign { background-color: rgba(0,200,120,0.15); color: #00c878; border: 1px solid rgba(0,200,120,0.3); }
.verdict-recon { background-color: rgba(255,170,0,0.15); color: #ffaa00; border: 1px solid rgba(255,170,0,0.3); }
.verdict-active { background-color: rgba(255,60,60,0.15); color: #ff3c3c; border: 1px solid rgba(255,60,60,0.3); }

.gauge-wrap {
    background-color: #141414;
    border: 1px solid #262626;
    border-radius: 10px;
    padding: 18px 22px;
    margin-bottom: 16px;
}
.gauge-track {
    width: 100%;
    height: 14px;
    border-radius: 7px;
    background-color: #262626;
    overflow: hidden;
    margin-top: 8px;
    margin-bottom: 6px;
}
.gauge-fill {
    height: 100%;
    border-radius: 7px;
}
.gauge-label {
    display: flex;
    justify-content: space-between;
    font-size: 0.78rem;
    color: #888888;
}

.stButton > button, .stDownloadButton > button {
    background-color: #ffffff;
    color: #0a0a0a;
    font-weight: 600;
    border-radius: 8px;
    border: none;
    padding: 0.6rem 1.2rem;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    background-color: #e5e5e5;
    color: #0a0a0a;
}

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


def extract_verdict_and_confidence(report_text):
    """Pulls a verdict label and confidence number out of the agent's
    free-text final report, so we can render a badge and a gauge."""
    verdict = "unknown"
    if re.search(r"active[_\s]?exploitation", report_text, re.IGNORECASE):
        verdict = "active_exploitation"
    elif re.search(r"\brecon\b", report_text, re.IGNORECASE):
        verdict = "recon"
    elif re.search(r"\bbenign\b", report_text, re.IGNORECASE):
        verdict = "benign"

    confidence = None
    match = re.search(r"confidence[:\s\*]*([0-9]{1,3})", report_text, re.IGNORECASE)
    if match:
        confidence = min(int(match.group(1)), 100)

    return verdict, confidence


def render_verdict_badge(verdict):
    badge_class = {
        "active_exploitation": "verdict-active",
        "recon": "verdict-recon",
        "benign": "verdict-benign",
    }.get(verdict, "verdict-recon")
    label = verdict.replace("_", " ").upper() if verdict != "unknown" else "REVIEW NEEDED"
    st.markdown(f'<span class="verdict-badge {badge_class}">{label}</span>', unsafe_allow_html=True)


def render_risk_gauge(confidence, verdict):
    if confidence is None:
        return
    if verdict == "active_exploitation":
        color = "#ff3c3c"
    elif verdict == "recon":
        color = "#ffaa00"
    else:
        color = "#00c878"

    st.markdown(f"""
    <div class="gauge-wrap">
        <div class="section-label" style="margin-bottom:2px;">Confidence Score</div>
        <div class="gauge-track">
            <div class="gauge-fill" style="width:{confidence}%; background-color:{color};"></div>
        </div>
        <div class="gauge-label">
            <span>0</span>
            <span style="color:{color}; font-weight:700;">{confidence}/100</span>
            <span>100</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def generate_pdf_report(final_report, verdict, confidence, generated_at, containment=None):
    """Builds a downloadable PDF version of the triage report."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "HoneyMesh Triage Report", ln=True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Generated: {generated_at}", ln=True)
    pdf.cell(0, 8, f"Verdict: {verdict}", ln=True)
    pdf.cell(0, 8, f"Confidence: {confidence if confidence is not None else 'N/A'}", ln=True)
    pdf.ln(4)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Full Report", ln=True)
    pdf.set_font("Helvetica", "", 10)

    safe_text = (final_report or "").encode("latin-1", "ignore").decode("latin-1")
    pdf.multi_cell(0, 6, safe_text)

    if containment:
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Containment Commands (requires human approval)", ln=True)
        pdf.set_font("Courier", "", 9)

        cmds = containment.get("commands", {})
        pdf.multi_cell(0, 6, f"iptables:\n{cmds.get('iptables', 'N/A')}")
        pdf.ln(2)
        pdf.multi_cell(0, 6, f"AWS Security Group:\n{cmds.get('aws_security_group', 'N/A')}")

        patches = containment.get("patch_recommendations", [])
        if patches:
            pdf.ln(2)
            pdf.set_font("Helvetica", "", 9)
            safe_patches = "\n".join(f"- {p}" for p in patches).encode("latin-1", "ignore").decode("latin-1")
            pdf.multi_cell(0, 6, "Patch Recommendations:\n" + safe_patches)

    return bytes(pdf.output())


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
        captured_containment = None
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
                result_blob = "\n".join(result_lines)
                with st.expander("View tool result"):
                    st.code(result_blob, language="json")

                if "iptables" in result_blob and "aws_security_group" in result_blob:
                    try:
                        captured_containment = json.loads(result_blob)
                    except json.JSONDecodeError:
                        pass

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

        verdict, confidence = extract_verdict_and_confidence(final_report or "")

        st.markdown('<div class="section-label" style="margin-top:24px;">Final Triage Report</div>', unsafe_allow_html=True)
        render_verdict_badge(verdict)
        render_risk_gauge(confidence, verdict)
        st.markdown(final_report)

        if captured_containment:
            st.markdown('<div class="section-label" style="margin-top:16px;">Containment Commands</div>', unsafe_allow_html=True)
            st.code(captured_containment.get("commands", {}).get("iptables", ""), language="bash")
            st.code(captured_containment.get("commands", {}).get("aws_security_group", ""), language="bash")

        generated_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        containment_section = ""
        if captured_containment:
            cmds = captured_containment.get("commands", {})
            patches = captured_containment.get("patch_recommendations", [])
            containment_section = f"""

---

## Containment Commands (generated — requires human approval before execution)

**Target IP:** {captured_containment.get('target_ip', 'N/A')}

**iptables (Linux firewall):**
```
{cmds.get('iptables', 'N/A')}
```

**AWS Security Group:**
```
{cmds.get('aws_security_group', 'N/A')}
```

**Patch Recommendations:**
{chr(10).join(f"- {p}" for p in patches)}
"""

        report_markdown = f"""# HoneyMesh Triage Report

Generated: {generated_at}
Verdict: {verdict}
Confidence: {confidence if confidence is not None else 'N/A'}

---

{final_report}
{containment_section}
"""

        report_json = json.dumps({
            "generated_at": generated_at,
            "verdict": verdict,
            "confidence": confidence,
            "final_report": final_report,
            "containment_plan": captured_containment
        }, indent=2)

        dl1, dl2, dl3 = st.columns(3)
        with dl1:
            st.download_button(
                label="📄 Markdown",
                data=report_markdown,
                file_name=f"honeymesh_triage_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                use_container_width=True
            )
        with dl2:
            st.download_button(
                label="📥 JSON",
                data=report_json,
                file_name=f"honeymesh_triage_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )
        with dl3:
            try:
                pdf_bytes = generate_pdf_report(final_report, verdict, confidence, generated_at, captured_containment)
                st.download_button(
                    label="🖨️ PDF",
                    data=pdf_bytes,
                    file_name=f"honeymesh_triage_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            except Exception as e:
                st.caption(f"PDF generation unavailable: {e}")

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
            past_report = data.get("final_report", "No report content.")
            past_verdict, past_confidence = extract_verdict_and_confidence(past_report)
            past_generated_at = selected.replace("triage_", "").replace(".json", "")

            st.caption(f"Generated: {past_generated_at}")
            render_verdict_badge(past_verdict)
            render_risk_gauge(past_confidence, past_verdict)
            st.markdown(past_report)

            dlp1, dlp2 = st.columns(2)
            with dlp1:
                st.download_button(
                    label="📄 Download Markdown",
                    data=past_report,
                    file_name=selected.replace(".json", ".md"),
                    mime="text/markdown",
                    use_container_width=True
                )
            with dlp2:
                try:
                    past_pdf = generate_pdf_report(past_report, past_verdict, past_confidence, past_generated_at)
                    st.download_button(
                        label="🖨️ Download PDF",
                        data=past_pdf,
                        file_name=selected.replace(".json", ".pdf"),
                        mime="application/pdf",
                        use_container_width=True
                    )
                except Exception as e:
                    st.caption(f"PDF generation unavailable: {e}")
    else:
        st.caption("No past reports yet.")