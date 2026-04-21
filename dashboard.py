import streamlit as st
import json
import time
from pathlib import Path

st.set_page_config(
    page_title="Project Chimera — Analyst Dashboard",
    page_icon="🕸️",
    layout="wide",
)

st.markdown("""
<style>
.mitre-tag {
    background: #1a1a2e;
    color: #e94560;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-family: monospace;
    margin: 2px;
    display: inline-block;
}
.cmd-line {
    font-family: monospace;
    font-size: 13px;
    padding: 4px 8px;
    background: #0f0f0f;
    color: #00ff41;
    border-radius: 4px;
    margin: 2px 0;
}
.canary-alert {
    background: #ff4444;
    color: white;
    padding: 8px 12px;
    border-radius: 6px;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

st.markdown("## 🕸️ Project Chimera — Live Analyst Dashboard")
st.caption("AI-Powered Honeypot | Real-time threat intelligence")

refresh = st.sidebar.slider("Auto-refresh (seconds)", 1, 10, 2)
st.sidebar.markdown("---")
st.sidebar.markdown("**About**")
st.sidebar.markdown("Project Chimera uses an LLM to simulate a Linux server, trapping attackers in a hallucinated environment while mapping their behavior to MITRE ATT&CK.")

_live = Path(__file__).parent / "data" / "live_sessions.json"
placeholder = st.empty()

while True:
    try:
        sessions = list(json.loads(_live.read_text(encoding="utf-8")).values()) if _live.exists() else []
    except Exception:
        sessions = []

    with placeholder.container():
        if not sessions:
            st.info("Waiting for connections...\n\nssh admin@localhost -p 2222 (any password)")
        else:
            total_commands = sum(s["command_count"] for s in sessions)
            total_canaries = sum(len(s["files_read"]) for s in sessions)
            all_tags = []
            for s in sessions:
                for cmd in s["command_log"]:
                    all_tags.extend(cmd.get("mitre_tags", []))

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Active Sessions", len(sessions))
            col2.metric("Total Commands", total_commands)
            col3.metric("MITRE Tags Fired", len(all_tags))
            col4.metric("Canary Tokens Accessed", total_canaries)
            st.markdown("---")

            for session in sessions:
                sid = session["session_id"]
                priv = session["privilege_level"]
                priv_color = "ROOT" if priv == "root" else "USER"

                with st.expander(
                    f"[{priv_color}] Session {sid} | user: {session['user']} | cwd: {session['cwd']} | {session['command_count']} commands",
                    expanded=True
                ):
                    left, right = st.columns([3, 2])

                    with left:
                        st.markdown("**Command Stream**")
                        for entry in reversed(session["command_log"][-20:]):
                            tags_html = ""
                            for tag in entry.get("mitre_tags", []):
                                tags_html += f'<span class="mitre-tag">{tag["id"]} {tag["name"]}</span>'
                            st.markdown(
                                f'<div class="cmd-line">'
                                f'<span style="color:#888">{entry["time"]}</span> '
                                f'<span style="color:#00ff41">$ {entry["command"]}</span>'
                                f'</div>{tags_html}',
                                unsafe_allow_html=True
                            )

                    with right:
                        st.markdown("**MITRE ATT&CK Heatmap**")
                        tactic_counts = {}
                        for entry in session["command_log"]:
                            for tag in entry.get("mitre_tags", []):
                                key = f"{tag['id']} - {tag['name']}"
                                tactic_counts[key] = tactic_counts.get(key, 0) + 1

                        if tactic_counts:
                            for tactic, count in sorted(tactic_counts.items(), key=lambda x: -x[1]):
                                bar = "X" * min(count * 3, 20)
                                st.markdown(f"`{tactic}` **{count}x** `{bar}`")
                        else:
                            st.caption("No tactics detected yet")

                        st.markdown("---")
                        st.markdown("**Attacker Profile**")
                        tactic_ids = set()
                        for entry in session["command_log"]:
                            for tag in entry.get("mitre_tags", []):
                                tactic_ids.add(tag["id"])

                        cmds = [e["command"] for e in session["command_log"]]
                        cmd_text = " ".join(cmds).lower()

                        if "t1548" in tactic_ids and "t1003" in tactic_ids and len(cmds) > 10:
                            profile = "APT / Advanced Pentester"
                        elif any(x in cmd_text for x in ["nmap", "masscan", "nikto"]):
                            profile = "Script Kiddie / Recon Tool"
                        elif len(cmds) < 5:
                            profile = "Unknown - gathering data"
                        elif "t1548" in tactic_ids:
                            profile = "Intermediate - Privilege Focus"
                        else:
                            profile = "Low Skill - Basic Recon"

                        st.markdown(f"**{profile}**")

                        if session["files_read"]:
                            st.markdown("---")
                            st.markdown("**CANARY TOKEN ALERTS**")
                            for f in session["files_read"]:
                                st.error(f"ACCESSED: {f}")

    time.sleep(refresh)