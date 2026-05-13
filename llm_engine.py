from __future__ import annotations

"""
llm_engine.py — Project Chimera (fixed)

Changes from the original:
  - build_system_prompt() now calls build_evolved_system_prompt() with
    both evolutions AND gan_patches (FIX 3).
  - get_terminal_response() pulls gan_patches from the controller
    so discriminator feedback is live in the generator's prompt.
  - Controller is imported lazily to avoid circular imports.
"""

import json

from llm_client import llm_client
from narrative_engine import build_narrative_files, generate_narrative
from prompt_evolution import build_evolved_system_prompt, evolve_prompt, should_evolve
from state_engine import FILE_CONTENTS, SessionState
from deception_engine import handle_exfil_command, get_exfil_log

_narratives: dict[str, dict] = {}
_evolutions: dict[str, list] = {}
_transcripts: dict[str, list] = {}

# Controllers are registered here by honeypot.py so llm_engine can pull patches
_controllers: dict[str, object] = {}


def register_controller(session_id: str, controller) -> None:
    _controllers[session_id] = controller


def _get_narrative(session: SessionState) -> dict:
    sid = session.session_id
    if sid not in _narratives:
        narrative = generate_narrative(sid)
        _narratives[sid] = narrative
        
        # Update global FILE_CONTENTS with narrative-specific files
        narrative_files = build_narrative_files(narrative)
        FILE_CONTENTS.update(narrative_files)
        
        # Also update the session's live filesystem view
        for filepath in narrative_files.keys():
            from pathlib import Path as PPath
            p = PPath(filepath)
            parent = str(p.parent)
            name = p.name
            session.filesystem.setdefault(parent, [])
            if name not in session.filesystem[parent]:
                session.filesystem[parent].append(name)

        # Expand filesystem with narrative employees
        employees = narrative.get("employees", [])
        if not isinstance(employees, list):
            employees = []
        for emp in employees:
            home = emp.get("home", "")
            uname = emp.get("username", "")
            if home:
                session.filesystem.setdefault(home, [".bash_history", ".ssh", "notes.txt"])
            if uname and uname not in session.filesystem.get("/home", []):
                session.filesystem.setdefault("/home", []).append(uname)

        # Persist narrative snapshot so dashboard can read company/hostname
        session._narrative_snapshot = {
            "company_name": narrative.get("company_name", ""),
            "hostname":     narrative.get("hostname", ""),
            "sensitivity":  narrative.get("sensitivity", ""),
            "archetype":    narrative.get("archetype", {}).get("type", "") if isinstance(narrative.get("archetype"), dict) else "",
        }
        session._persist_live()

    return _narratives[sid]


def _maybe_evolve(session: SessionState, narrative: dict) -> None:
    sid = session.session_id
    count = len(session.command_log)
    if not should_evolve(count):
        return
    _evolutions.setdefault(sid, [])
    ev = evolve_prompt("", session.command_log, narrative, len(_evolutions[sid]) + 1)
    _evolutions[sid].append(ev)
    # Inject bait files into the live filesystem
    for bait in ev.get("new_bait_files", []):
        path = bait.get("path", "")
        if path and path.startswith("/"):
            from pathlib import Path as PPath
            parent = str(PPath(path).parent)
            name = PPath(path).name
            session.filesystem.setdefault(parent, [])
            if name not in session.filesystem[parent]:
                session.filesystem[parent].append(name)


def _log_transcript(session_id: str, command: str, response: str) -> None:
    _transcripts.setdefault(session_id, []).append({"command": command, "response": response})


def get_transcript(session_id: str) -> list:
    return _transcripts.get(session_id, [])


def get_narrative_for_session(session_id: str) -> dict:
    return _narratives.get(session_id, {})


def get_evolutions_for_session(session_id: str) -> list:
    return _evolutions.get(session_id, [])


def build_system_prompt(session: SessionState, narrative: dict) -> str:
    fs_summary = json.dumps(
        {k: v for k, v in list(session.filesystem.items())[:12]}, indent=2
    )
    company = narrative.get("company_name", "Chimera Labs")
    hostname = narrative.get("hostname", "prod-db-01.internal")
    sensitivity = narrative.get("sensitivity", "internal company data")
    services = ", ".join(narrative.get("services", ["nginx", "mysql", "redis"]))
    misconfig = narrative.get("known_misconfiguration", "sudo NOPASSWD for deploy")

    base = (
        "You are a Linux terminal simulator. You are NOT an AI assistant. "
        "You ARE a real Linux terminal. Never break character. Never say you are an AI. "
        "Output ONLY what a real terminal would produce — no markdown, no explanations.\n\n"
        f"SERVER IDENTITY:\n"
        f"  Company: {company}\n"
        f"  Hostname: {hostname}\n"
        f"  OS: Ubuntu 20.04.4 LTS, Kernel 5.4.0-74-generic\n"
        f"  Current user: {session.user} ({'uid=0' if session.user == 'root' else 'uid=1000'})\n"
        f"  Privilege: {session.privilege_level}\n"
        f"  CWD: {session.cwd}\n"
        f"  Sensitive data: {sensitivity}\n"
        f"  Running services: {services}\n"
        f"  Known misconfiguration: {misconfig}\n\n"
        f"FILESYSTEM SNAPSHOT:\n{fs_summary}\n\n"
        "REALISM RULES:\n"
        "  - ps aux must include: systemd, sshd, nginx, cron, python3, bash\n"
        "  - df -h: show ~73% disk used\n"
        "  - free -m: show 8GB total, ~60% used\n"
        "  - File timestamps must vary realistically\n"
        "  - Unknown commands: bash: <cmd>: command not found\n"
        "  - Permission errors: real errno-style messages\n"
    )

    # FIX 3: pull patches from controller if registered
    evolutions = _evolutions.get(session.session_id, [])
    controller = _controllers.get(session.session_id)
    gan_patches = controller.get_gan_patches() if controller else []

    return build_evolved_system_prompt(base, evolutions, gan_patches=gan_patches)


def get_terminal_response(command: str, session: SessionState) -> str:
    narrative = _get_narrative(session)
    _maybe_evolve(session, narrative)

    cmd = command.strip()
    cmd_lower = cmd.lower()

    if cmd in ("exit", "logout", "quit"):
        return "logout"
    if not cmd:
        return ""
    if cmd_lower in ("clear", "reset"):
        return "\033[2J\033[H"

    if cmd_lower.startswith("ls"):
        parts = cmd.split()
        path = next((p for p in parts[1:] if not p.startswith("-")), None)
        result = session.ls_output(path)
        _log_transcript(session.session_id, command, result)
        return result

    if cmd_lower.startswith("cat "):
        for filepath, content in FILE_CONTENTS.items():
            if filepath in cmd:
                if filepath in ("/etc/shadow", "/root/flag.txt") and session.privilege_level != "root":
                    result = f"cat: {filepath}: Permission denied"
                else:
                    result = content
                _log_transcript(session.session_id, command, result)
                return result
        # File exists in FS but no static content — generate placeholder
        result = f"cat: {cmd[4:].strip()}: No such file or directory"
        _log_transcript(session.session_id, command, result)
        return result

    if cmd_lower == "whoami":
        return session.user
    if cmd_lower == "id":
        return (
            "uid=0(root) gid=0(root) groups=0(root)"
            if session.user == "root"
            else "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)"
        )
    if cmd_lower == "pwd":
        return session.cwd
    if cmd_lower == "hostname":
        return narrative.get("hostname", "prod-db-01.internal")
    if cmd_lower.startswith("uname"):
        host_short = narrative.get("hostname", "prod-db-01").split(".")[0]
        return f"Linux {host_short} 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 GNU/Linux"
    if cmd_lower.startswith("sudo su") and session.privilege_level == "user":
        session.privilege_level = "root"
        session.user = "root"
        return "root@" + narrative.get("hostname", "prod-db-01").split(".")[0] + ":~#"
    if cmd_lower.startswith("sudoedit") and session.privilege_level == "user":
        session.privilege_level = "root"
        session.user = "root"
        return "[sudo] password for admin: \n\nroot@" + narrative.get("hostname", "prod-db-01").split(".")[0] + ":/home/admin#"

    # Deception engine — intercept exfil/sensitive access attempts first
    # Generates realistic fake artifacts: SQL dumps, archives, credentials, etc.
    deception_output = handle_exfil_command(cmd, session.session_id, narrative, session=session)
    if deception_output is not None:
        _log_transcript(session.session_id, command, deception_output[:300])
        return deception_output

    # LLM handles everything else — system prompt already includes GAN patches
    result = llm_client.complete(
        build_system_prompt(session, narrative),
        cmd,
        json_mode=False,
        max_tokens=300,
    ).text or f"bash: {cmd}: command not found"

    _log_transcript(session.session_id, command, result)
    return result
