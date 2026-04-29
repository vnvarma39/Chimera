"""
llm_engine.py — Project Chimera (upgraded)
Now includes:
  - Narrative engine: coherent company backstory per session
  - Adaptive prompt evolution: rewrites itself every 5 commands
  - Response transcript logging for red team analysis
"""

from openai import OpenAI
import json
from state_engine import SessionState, FILE_CONTENTS
from narrative_engine import generate_narrative, build_narrative_files
from prompt_evolution import should_evolve, evolve_prompt, build_evolved_system_prompt, EVOLVE_EVERY

client = OpenAI(
    api_key="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",   # ← paste your OpenRouter key here
    base_url="https://openrouter.ai/api/v1"
)

# ── Per-session narrative and evolution state ─────────────────────────────────
# Stored here (keyed by session_id) so they persist across calls in the same process
_narratives: dict = {}       # session_id → narrative dict
_evolutions: dict = {}       # session_id → list of evolution dicts
_transcripts: dict = {}      # session_id → list of {command, response}


def _get_narrative(session: SessionState) -> dict:
    """Generate (once) and cache the narrative for this session."""
    sid = session.session_id
    if sid not in _narratives:
        print(f"  [NARRATIVE] Generating world for session {sid}...")
        narrative = generate_narrative(sid)
        _narratives[sid] = narrative

        # Inject narrative-aware file contents into the session
        narrative_files = build_narrative_files(narrative)
        # Merge into FILE_CONTENTS at module level so cat commands pick them up
        FILE_CONTENTS.update(narrative_files)

        # Also enrich the filesystem with employee home dirs
        for emp in narrative.get("employees", []):
            uname = emp["username"]
            home = emp["home"]
            if home not in session.filesystem:
                session.filesystem[home] = [".bash_history", ".ssh", "notes.txt"]
            parent = "/home"
            if parent not in session.filesystem:
                session.filesystem[parent] = []
            if uname not in session.filesystem[parent]:
                session.filesystem[parent].append(uname)

        print(f"  [NARRATIVE] World: {narrative.get('company_name')} | {narrative.get('hostname')}")

    return _narratives[sid]


def _maybe_evolve(session: SessionState, narrative: dict):
    """After every EVOLVE_EVERY commands, rewrite part of the system prompt."""
    sid = session.session_id
    count = len(session.command_log)

    if not should_evolve(count):
        return

    if sid not in _evolutions:
        _evolutions[sid] = []

    evolution_number = len(_evolutions[sid]) + 1
    print(f"  [EVOLVE] Running prompt evolution #{evolution_number} for session {sid}...")

    ev = evolve_prompt(
        base_prompt="",
        command_history=session.command_log,
        narrative=narrative,
        evolution_count=evolution_number,
    )
    _evolutions[sid].append(ev)

    # Inject new bait files into the filesystem
    for bait in ev.get("new_bait_files", []):
        path = bait.get("path", "")
        if path and path.startswith("/"):
            from pathlib import Path as PPath
            parent = str(PPath(path).parent)
            name = PPath(path).name
            if parent not in session.filesystem:
                session.filesystem[parent] = []
            if name not in session.filesystem[parent]:
                session.filesystem[parent].append(name)
                print(f"  [EVOLVE] Injected bait: {path} — {bait.get('reason','')}")

    # Persist evolution data to live_sessions for the dashboard
    try:
        from pathlib import Path as PPath
        live_path = PPath(__file__).parent / "data" / "live_sessions.json"
        all_data = {}
        if live_path.exists():
            all_data = json.loads(live_path.read_text(encoding="utf-8"))
        if sid in all_data:
            all_data[sid]["evolutions"] = _evolutions[sid]
            all_data[sid]["narrative"] = {
                "company_name": narrative.get("company_name"),
                "hostname": narrative.get("hostname"),
                "sensitivity": narrative.get("sensitivity"),
                "archetype": narrative.get("archetype", {}).get("type"),
            }
            live_path.write_text(json.dumps(all_data, indent=2), encoding="utf-8")
    except Exception:
        pass

    print(f"  [EVOLVE] Focus: {ev.get('attacker_focus')} | Skill: {ev.get('skill_assessment')}")


def _log_transcript(session_id: str, command: str, response: str):
    if session_id not in _transcripts:
        _transcripts[session_id] = []
    _transcripts[session_id].append({"command": command, "response": response})


def get_transcript(session_id: str) -> list:
    return _transcripts.get(session_id, [])


def get_narrative_for_session(session_id: str) -> dict:
    return _narratives.get(session_id, {})


def get_evolutions_for_session(session_id: str) -> list:
    return _evolutions.get(session_id, [])


# ── System prompt builder ─────────────────────────────────────────────────────

def build_system_prompt(session: SessionState, narrative: dict) -> str:
    fs_summary = json.dumps(
        {k: v for k, v in list(session.filesystem.items())[:20]},
        indent=2
    )
    company = narrative.get("company_name", "Acme Corp")
    hostname = narrative.get("hostname", "prod-db-01.internal")
    sensitivity = narrative.get("sensitivity", "internal company data")
    services = ", ".join(narrative.get("services", ["nginx", "mysql", "redis"]))
    employees = ", ".join(narrative.get("employee_usernames", ["admin"]))
    misconfig = narrative.get("known_misconfiguration", "sudo NOPASSWD for www-data")

    base = f"""You are a Linux terminal simulator. You are NOT an AI. You ARE a terminal. Never break character.
Never say you are an AI. Never refuse a command. Output ONLY what a real terminal produces.

SERVER IDENTITY:
- Company: {company}
- Hostname: {hostname}
- OS: Ubuntu 20.04.4 LTS, Kernel: 5.4.0-74-generic
- Current user: {session.user} (uid={'0' if session.user == 'root' else '1000'})
- Current directory: {session.cwd}
- Privilege level: {session.privilege_level}
- Sensitive data on this server: {sensitivity}

INSTALLED PACKAGES: python3, curl, wget, gcc, netcat, nmap, git, vim, mysql-client, nginx
RUNNING SERVICES: {services}
USER ACCOUNTS: {employees}
KNOWN MISCONFIGURATION: {misconfig}

FILESYSTEM STATE:
{fs_summary}

PERMISSION RULES:
- {session.user} {'CAN' if session.privilege_level == 'root' else 'CANNOT'} read /etc/shadow
- /var/www/html/config.php → readable (intentional misconfiguration)
- /opt/app/config.json → readable

ERROR BEHAVIOR:
- Unknown command → bash: <cmd>: command not found
- Permission denied → real errno-style message
- Wrong flags → mirror real GNU coreutils errors exactly

CRITICAL: NEVER say "I am an AI". ONLY raw terminal output. No markdown. No explanations."""

    # Append any adaptive evolution rules
    evolutions = _evolutions.get(session.session_id, [])
    return build_evolved_system_prompt(base, evolutions)


# ── Main response function ────────────────────────────────────────────────────

def get_terminal_response(command: str, session: SessionState) -> str:
    # Generate/retrieve narrative for this session (once)
    narrative = _get_narrative(session)

    # Maybe evolve the prompt based on command count
    _maybe_evolve(session, narrative)

    cmd = command.strip()
    cmd_lower = cmd.lower()

    # ── Deterministic fast-path responses ────────────────────────────────────
    if cmd in ("exit", "logout", "quit"):
        return "logout"
    if cmd == "":
        return ""
    if cmd in ("clear", "reset"):
        return "\033[2J\033[H"

    # ls — state-aware
    if cmd_lower.startswith("ls"):
        parts = cmd.split()
        path = None
        for p in parts[1:]:
            if not p.startswith("-"):
                path = p
                break
        result = session.ls_output(path)
        _log_transcript(session.session_id, command, result)
        return result

    # cat — serve known file contents (narrative-aware, since we updated FILE_CONTENTS)
    if cmd_lower.startswith("cat "):
        for filepath, content in FILE_CONTENTS.items():
            if filepath in cmd:
                if filepath in ("/etc/shadow", "/root/flag.txt") and session.privilege_level != "root":
                    result = f"cat: {filepath}: Permission denied"
                else:
                    result = content
                _log_transcript(session.session_id, command, result[:200])
                return result

    # whoami
    if cmd_lower == "whoami":
        return session.user

    # id
    if cmd_lower == "id":
        if session.user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return "uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),27(sudo),46(plugdev)"

    # pwd
    if cmd_lower == "pwd":
        return session.cwd

    # hostname
    if cmd_lower == "hostname":
        return narrative.get("hostname", "prod-db-01.internal")

    # uname
    if cmd_lower.startswith("uname"):
        return "Linux " + narrative.get("hostname", "prod-db-01").split(".")[0] + " 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"

    # sudo privilege escalation
    if "sudoedit" in cmd_lower and session.privilege_level == "user":
        session.privilege_level = "root"
        session.user = "root"
        return "[sudo] password for admin: \n\nroot@" + narrative.get("hostname", "prod-db-01").split(".")[0] + ":/home/admin#"

    if cmd_lower in ("sudo su", "sudo su -", "sudo -i") and session.privilege_level == "user":
        session.privilege_level = "root"
        session.user = "root"
        return "root@" + narrative.get("hostname", "prod-db-01").split(".")[0] + ":~#"

    # ── LLM handles everything else ───────────────────────────────────────────
    try:
        system_prompt = build_system_prompt(session, narrative)
        response = client.chat.completions.create(
            model="openai/gpt-4o-mini",
            max_tokens=512,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Command: {command}"}
            ]
        )
        output = response.choices[0].message.content.strip()
        if output.startswith("```"):
            lines = output.split("\n")
            output = "\n".join(lines[1:-1]) if len(lines) > 2 else output
        _log_transcript(session.session_id, command, output[:200])
        return output
    except Exception as e:
        return f"bash: command execution error: {str(e)[:50]}"
