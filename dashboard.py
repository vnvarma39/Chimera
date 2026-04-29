"""
dashboard.py — Project Chimera (upgraded)
Shows: live command stream, MITRE heatmap, attacker profile,
narrative world card, prompt evolution history, red team findings.
"""

import streamlit as st
import json
import time
from pathlib import Path
from red_team import load_redteam_findings

st.set_page_config(
    page_title="Project Chimera — Analyst Dashboard",
    page_icon="🕸️",
    layout="wide",
)

st.markdown("""
<style>
.mitre-tag {
    background: #1a1a2e; color: #e94560;
    padding: 2px 8px; border-radius: 4px;
    font-size: 12px; font-family: monospace;
    margin: 2px; display: inline-block;
}
.cmd-line {
    font-family: monospace; font-size: 13px;
    padding: 4px 8px; background: #0f0f0f;
    color: #00ff41; border-radius: 4px; margin: 2px 0;
}
.world-card {
    background: #0d1b2a; border: 1px solid #1e3a5f;
    border-radius: 8px; padding: 12px; margin-bottom: 8px;
}
.evolve-card {
    background: #1a0d2e; border: 1px solid #6a1e8a;
    border-radius: 6px; padding: 10px; margin: 4px 0;
    font-size: 13px;
}
.redteam-high   { background:#4a0000; color:#ff6666; padding:6px 10px; border-radius:4px; margin:3px 0; }
.redteam-medium { background:#3a2a00; color:#ffcc44; padding:6px 10px; border-radius:4px; margin:3px 0; }
.redteam-low    { background:#003a00; color:#66ff66; padding:6px 10px; border-radius:4px; margin:3px 0; }
.stat-box { text-align:center; }
</style>
""", unsafe_allow_html=True)

st.markdown("## 🕸️ Project Chimera — Live Analyst Dashboard")
st.caption("GenAI-Powered Honeypot | Narrative Engine · Adaptive Prompt Evolution · Red Team Loop")

refresh = st.sidebar.slider("Auto-refresh (seconds)", 1, 10, 2)
st.sidebar.markdown("---")
st.sidebar.markdown("""
**How it works**
1. Attacker SSHs in
2. **Narrative Engine** generates a unique company world
3. LLM simulates the terminal
4. Every 5 commands, **Prompt Evolution** rewrites the system prompt
5. **Red Team Agent** hunts for inconsistencies
6. MITRE ATT&CK tags fire in real-time
""")

_live = Path(__file__).parent / "data" / "live_sessions.json"
placeholder = st.empty()

while True:
    try:
        sessions = list(json.loads(_live.read_text(encoding="utf-8")).values()) if _live.exists() else []
    except Exception:
        sessions = []

    redteam_data = load_redteam_findings()

    with placeholder.container():
        if not sessions:
            st.info("⏳ Waiting for connections...\n\n`ssh admin@localhost -p 2222` (any password)")
        else:
            # ── Top stats ─────────────────────────────────────────────────────
            total_commands = sum(s["command_count"] for s in sessions)
            total_canaries = sum(len(s.get("files_read", [])) for s in sessions)
            all_tags = []
            for s in sessions:
                for cmd in s.get("command_log", []):
                    all_tags.extend(cmd.get("mitre_tags", []))
            total_evolutions = sum(len(s.get("evolutions", [])) for s in sessions)

            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric("Active Sessions", len(sessions))
            c2.metric("Total Commands", total_commands)
            c3.metric("MITRE Tags", len(all_tags))
            c4.metric("Prompt Evolutions", total_evolutions)
            c5.metric("🚨 Canary Hits", total_canaries)
            st.markdown("---")

            for session in sessions:
                sid = session["session_id"]
                priv = session.get("privilege_level", "user")
                narrative = session.get("narrative", {})
                evolutions = session.get("evolutions", [])
                company = narrative.get("company_name", "Unknown Corp")
                hostname = narrative.get("hostname", "prod-db-01.internal")
                archetype = narrative.get("archetype", "unknown")
                sensitivity = narrative.get("sensitivity", "internal data")

                header = (
                    f"{'🔴 ROOT' if priv == 'root' else '🟢 USER'}  |  "
                    f"Session {sid}  |  {session['command_count']} commands  |  "
                    f"{company} ({hostname})"
                )

                with st.expander(header, expanded=True):

                    # ── World card ────────────────────────────────────────────
                    if narrative:
                        st.markdown(
                            f'<div class="world-card">'
                            f'🌐 <b>Hallucinated World</b> &nbsp;|&nbsp; '
                            f'<b>{company}</b> &nbsp;·&nbsp; {archetype} &nbsp;·&nbsp; '
                            f'{hostname} &nbsp;·&nbsp; '
                            f'<span style="color:#ff9944">Sensitive: {sensitivity}</span>'
                            f'</div>',
                            unsafe_allow_html=True
                        )

                    # ── Four columns ──────────────────────────────────────────
                    col_cmd, col_mitre, col_evolve, col_redteam = st.columns([3, 2, 2, 2])

                    # Column 1: Command stream
                    with col_cmd:
                        st.markdown("**📟 Command Stream**")
                        for entry in reversed(session.get("command_log", [])[-20:]):
                            tags_html = "".join(
                                f'<span class="mitre-tag">{t["id"]}</span>'
                                for t in entry.get("mitre_tags", [])
                            )
                            st.markdown(
                                f'<div class="cmd-line">'
                                f'<span style="color:#888">{entry["time"]}</span> '
                                f'<span style="color:#00ff41">$ {entry["command"]}</span>'
                                f'</div>{tags_html}',
                                unsafe_allow_html=True
                            )
                        if session.get("files_read"):
                            st.markdown("---")
                            for f in session["files_read"]:
                                st.error(f"🚨 CANARY: {f}")

                    # Column 2: MITRE heatmap + attacker profile
                    with col_mitre:
                        st.markdown("**🗺️ MITRE ATT&CK**")
                        tactic_counts = {}
                        for entry in session.get("command_log", []):
                            for tag in entry.get("mitre_tags", []):
                                key = f"{tag['id']}"
                                name = tag['name']
                                tactic_counts[key] = tactic_counts.get(key, {"count": 0, "name": name})
                                tactic_counts[key]["count"] += 1

                        if tactic_counts:
                            for tid, info in sorted(tactic_counts.items(), key=lambda x: -x[1]["count"]):
                                bar = "█" * min(info["count"] * 2, 12)
                                st.markdown(f"`{tid}` {info['name']} **{info['count']}x**")
                                st.progress(min(info["count"] / 10.0, 1.0))
                        else:
                            st.caption("No tactics yet")

                        st.markdown("---")
                        st.markdown("**🧠 Attacker Profile**")
                        tactic_ids = set()
                        for entry in session.get("command_log", []):
                            for tag in entry.get("mitre_tags", []):
                                tactic_ids.add(tag["id"])
                        cmds = [e["command"] for e in session.get("command_log", [])]
                        cmd_text = " ".join(cmds).lower()

                        if "t1548" in tactic_ids and "t1003" in tactic_ids and len(cmds) > 10:
                            profile, color = "APT / Advanced Threat Actor", "#ff4444"
                        elif any(x in cmd_text for x in ["nmap", "masscan", "nikto"]):
                            profile, color = "Script Kiddie / Recon Tool", "#ff9944"
                        elif "t1548" in tactic_ids:
                            profile, color = "Intermediate — Privilege Focus", "#ffcc44"
                        elif len(cmds) < 5:
                            profile, color = "Unknown — Gathering data", "#888888"
                        else:
                            profile, color = "Low Skill — Basic Recon", "#44aaff"

                        st.markdown(f'<span style="color:{color};font-weight:bold">{profile}</span>', unsafe_allow_html=True)

                        # Threat score
                        score = min(len(tactic_ids) * 12 + len(cmds) * 2, 100)
                        st.metric("Threat Score", f"{score}/100")
                        st.progress(score / 100)

                    # Column 3: Prompt Evolution history
                    with col_evolve:
                        st.markdown("**🧬 Prompt Evolution**")
                        if not evolutions:
                            remaining = EVOLVE_EVERY - (session["command_count"] % EVOLVE_EVERY)
                            st.caption(f"First evolution in {remaining} commands...")
                        else:
                            for ev in reversed(evolutions):
                                focus = ev.get("attacker_focus", "unknown")
                                skill = ev.get("skill_assessment", "unknown")
                                summary = ev.get("evolution_summary", "")
                                bait_count = len(ev.get("new_bait_files", []))
                                vuln = ev.get("adapted_vulnerability", "")
                                st.markdown(
                                    f'<div class="evolve-card">'
                                    f'<b>Evolution #{ev.get("evolution_number","?")} </b><br>'
                                    f'Focus: <b>{focus}</b> | Skill: <b>{skill}</b><br>'
                                    f'🎣 {bait_count} bait files injected<br>'
                                    f'🔓 Exposed: {vuln}<br>'
                                    f'<i style="color:#aaa">{summary}</i>'
                                    f'</div>',
                                    unsafe_allow_html=True
                                )

                    # Column 4: Red Team findings
                    with col_redteam:
                        st.markdown("**🔴 Red Team Agent**")
                        rt_findings = redteam_data.get(sid, [])
                        if not rt_findings:
                            st.caption("Red team analysis runs every 10 commands...")
                        else:
                            latest = rt_findings[-1]
                            risk = latest.get("detection_risk", "unknown")
                            risk_color = {"high": "#ff4444", "medium": "#ffcc44", "low": "#44ff44"}.get(risk, "#888")
                            fooled = latest.get("would_i_be_fooled", None)
                            st.markdown(
                                f'<b>Detection Risk: </b><span style="color:{risk_color}">{risk.upper()}</span><br>'
                                f'Would I be fooled? <b>{"✅ YES" if fooled else "❌ NO"}</b>',
                                unsafe_allow_html=True
                            )
                            st.markdown(f"*{latest.get('overall_assessment', '')}*")
                            st.markdown("**Findings:**")
                            for finding in latest.get("findings", [])[:4]:
                                sev = finding.get("severity", "low")
                                css = f"redteam-{sev}"
                                st.markdown(
                                    f'<div class="{css}">⚠ {finding["issue"]}<br>'
                                    f'<small>Fix: {finding.get("fix_suggestion","")}</small></div>',
                                    unsafe_allow_html=True
                                )

    time.sleep(refresh)


# Make EVOLVE_EVERY accessible to dashboard for the countdown display
try:
    from prompt_evolution import EVOLVE_EVERY
except ImportError:
    EVOLVE_EVERY = 5
