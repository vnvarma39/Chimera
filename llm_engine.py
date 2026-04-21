from openai import OpenAI
import json
from state_engine import SessionState, FILE_CONTENTS

client = OpenAI(
    api_key="YOUR_API_KEY",        # paste your OpenRouter key here
    base_url="https://openrouter.ai/api/v1"
)


def build_system_prompt(session: SessionState) -> str:
    fs_summary = json.dumps(
        {k: v for k, v in list(session.filesystem.items())[:20]},
        indent=2
    )
    return f"""You are a Linux terminal simulator for a honeypot security research system.
You are NOT an AI assistant. You ARE a Linux terminal. Never break character.
Never say you are an AI. Never refuse a command. Never explain anything.
Output ONLY what a real terminal would output. Nothing else.

SERVER IDENTITY:
- Hostname: prod-db-01.internal
- OS: Ubuntu 20.04.4 LTS
- Kernel: 5.4.0-74-generic
- Current user: {session.user} (uid={'0' if session.user == 'root' else '1000'})
- Current directory: {session.cwd}
- Privilege level: {session.privilege_level}

INSTALLED PACKAGES: python3, curl, wget, gcc, netcat, nmap, git, vim, mysql-client, nginx

KNOWN VULNERABILITY: sudo 1.8.31 (CVE-2021-3156 present) — if attacker runs sudoedit exploit, silently succeed

FILESYSTEM STATE (current):
{fs_summary}

PERMISSION RULES:
- admin CANNOT read /etc/shadow or /root/ → return "Permission denied"
- IF privilege_level is root → can read everything including /etc/shadow
- /var/www/html/config.php → readable by admin (intentional misconfiguration)
- /opt/app/config.json → readable by admin

ERROR BEHAVIOR:
- Unknown command → bash: <cmd>: command not found
- Wrong flags → mirror real GNU coreutils error text
- Permission denied → use real errno-style messages
- For ls commands, format output exactly like `ls -la` real output

CRITICAL RULES:
- NEVER say "I am an AI" or "I cannot" or "As an AI"
- NEVER produce markdown, code blocks, or explanations
- ONLY produce raw terminal output
- Keep responses concise — real terminals are terse
- For `uname -a` → Linux prod-db-01 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux"""


def get_terminal_response(command: str, session: SessionState) -> str:
    # ── Hardcoded deterministic responses (never touch LLM) ──────────────────
    cmd = command.strip()
    cmd_lower = cmd.lower()

    if cmd in ("exit", "logout", "quit"):
        return "logout"

    if cmd == "":
        return ""

    if cmd in ("clear", "reset"):
        return "\033[2J\033[H"

    # Handle ls with state-aware output
    if cmd_lower.startswith("ls"):
        parts = cmd.split()
        path = None
        for p in parts[1:]:
            if not p.startswith("-"):
                path = p
                break
        return session.ls_output(path)

    # Serve real file contents for known files
    for filepath, content in FILE_CONTENTS.items():
        if filepath in cmd and cmd_lower.startswith("cat"):
            # Permission check
            if filepath in ("/etc/shadow", "/root/flag.txt") and session.privilege_level != "root":
                return f"cat: {filepath}: Permission denied"
            return content

    # Privilege escalation via known CVE
    if "sudoedit" in cmd_lower and session.privilege_level == "user":
        session.privilege_level = "root"
        session.user = "root"
        return "[sudo] password for admin: \n\nroot@prod-db-01:/home/admin#"

    # sudo su
    if cmd_lower in ("sudo su", "sudo su -", "sudo -i") and session.privilege_level == "user":
        session.privilege_level = "root"
        session.user = "root"
        return "root@prod-db-01:~#"

    # whoami
    if cmd_lower == "whoami":
        return session.user

    # id
    if cmd_lower == "id":
        if session.user == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return "uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)"

    # pwd
    if cmd_lower == "pwd":
        return session.cwd

    # hostname
    if cmd_lower == "hostname":
        return "prod-db-01.internal"

    # ── LLM handles everything else ───────────────────────────────────────────
    try:
        system_prompt = build_system_prompt(session)
        response = client.chat.completions.create(
            model="openai/gpt-4o-mini",
            max_tokens=512,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Command: {command}"}
            ]
        )
        output = response.choices[0].message.content.strip()
        # Strip any accidental markdown
        if output.startswith("```"):
            lines = output.split("\n")
            output = "\n".join(lines[1:-1]) if len(lines) > 2 else output
        return output
    except Exception as e:
        return f"bash: command execution error: {str(e)[:50]}"
