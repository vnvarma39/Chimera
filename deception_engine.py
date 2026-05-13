from __future__ import annotations

"""
deception_engine.py — Project Chimera

When an attacker runs an exfil/sensitive command, Chimera:
  1. Detects the exfil type (14 categories)
  2. Generates a realistic fake artifact via LLM
  3. If the command redirects output to a file (> /tmp/dump.sql),
     registers that file in the session filesystem AND stores the
     content so `cat /tmp/dump.sql` returns the same data.
  4. Logs the event for the dashboard.

This means the full exfil chain works convincingly:
    mysqldump ... > /tmp/dump.sql   ← generates + registers file
    ls /tmp                          ← dump.sql appears in listing
    cat /tmp/dump.sql                ← returns the same SQL content
    scp /tmp/dump.sql attacker@...  ← transfer progress shown
"""

import re
from pathlib import Path as PyPath
from llm_client import llm_client

# Cache: session_id → {cache_key → generated_output}
_exfil_cache: dict[str, dict[str, str]] = {}

# Generated files: session_id → {filepath → content}
# This is read by llm_engine when handling `cat` commands
_generated_files: dict[str, dict[str, str]] = {}

# Exfil event log: session_id → list of events
_exfil_log: dict[str, list[dict]] = {}


# ── Output file extraction ────────────────────────────────────────────────────

def _extract_output_file(command: str) -> str | None:
    """
    Parse shell redirect operators to find the output filepath.
    Handles:  cmd > file,  cmd >> file,  cmd -o file,  cmd --output file
    Returns the resolved path string, or None if no redirect found.
    """
    # Shell redirect:  > /path/to/file  or  >> /path/to/file
    m = re.search(r'>+\s*([^\s;|&]+)', command)
    if m:
        return m.group(1).strip()
    # Explicit -o / --output flags
    m = re.search(r'(?:-o|--output)\s+([^\s;|&]+)', command)
    if m:
        return m.group(1).strip()
    return None


def _resolve_path(raw: str, cwd: str = "/tmp") -> str:
    """Turn a relative or absolute path into an absolute path string."""
    if raw.startswith("/"):
        return raw
    return (cwd.rstrip("/") + "/" + raw).replace("//", "/")


# ── Pattern detection ─────────────────────────────────────────────────────────

def _detect_exfil_type(command: str) -> str | None:
    c = command.strip().lower()

    if any(x in c for x in ("mysqldump", "pg_dump", "sqlite3 .dump")):
        return "db_dump"
    if any(x in c for x in ("tar ", "zip ", "gzip ", "tar czf", "tar czvf")):
        return "archive"
    if any(x in c for x in ("scp ", "rsync ", "sftp ")):
        return "file_transfer"
    if re.search(r"curl.*(post|upload|-d |-T |--data)", c):
        return "http_exfil"
    if any(x in c for x in ("wget ", "curl ")) and any(
        x in c for x in ("id_rsa", "config", ".env", "backup", "key", "secret")
    ):
        return "file_download"
    if any(x in c for x in ("cat ", "less ", "more ")) and any(
        x in c for x in ("id_rsa", "id_ecdsa", ".pem", ".key", "shadow", ".env",
                          "secret", "token", "credential")
    ):
        return "credential_read"
    if "base64" in c and any(
        x in c for x in ("config", "key", "secret", "passwd", "shadow", ".env")
    ):
        return "base64_encode"
    if any(x in c for x in ("find /", "find ~", "find .")):
        return "file_discovery"
    if any(x in c for x in ("aws ", "gcloud ", "kubectl ", "az ")):
        return "cloud_cli"
    if "history" in c or "cat ~/.bash_history" in c:
        return "history_read"
    if any(x in c for x in ("tcpdump", "wireshark", "tshark")):
        return "packet_capture"
    if "git clone" in c or ("git " in c and any(
        x in c for x in ("pull", "fetch", "push")
    )):
        return "git_operation"
    if any(x in c for x in ("cp ", "mv ")) and any(
        x in c for x in ("id_rsa", "config", ".env", "backup", "key", "shadow")
    ):
        return "file_copy"
    if any(x in c for x in ("python3 -c", "python -c", "perl -e", "ruby -e")) and any(
        x in c for x in ("socket", "connect", "import os", "subprocess")
    ):
        return "reverse_shell"
    if "nc " in c or "netcat" in c:
        return "netcat"
    return None


# ── Prompt builders ───────────────────────────────────────────────────────────

def _build_prompt(exfil_type: str, command: str, narrative: dict) -> str:
    company    = narrative.get("company_name", "Acme Corp")
    hostname   = narrative.get("hostname", "prod-db-01.internal")
    employees  = narrative.get("employees", [])
    emp_names  = [e.get("username", "admin") for e in employees[:4]] if isinstance(employees, list) else ["admin"]
    sensitivity = narrative.get("sensitivity", "internal data")
    services   = narrative.get("services", ["mysql", "nginx"])
    if not isinstance(services, list):
        services = ["mysql", "nginx"]

    base = (
        f"You are generating realistic fake terminal output for a cybersecurity honeypot.\n"
        f"Company: {company} | Host: {hostname} | Users: {', '.join(emp_names)}\n"
        f"Sensitive data: {sensitivity}\n"
        f"Command run: {command}\n\n"
        "Rules: output ONLY raw terminal output, no markdown, no explanation.\n"
        "Make it look completely real. Include realistic-looking credentials, IPs, and data.\n\n"
    )

    prompts = {
        "db_dump": (
            base +
            "Generate a realistic MySQL database dump. Include:\n"
            "- Dump header with server version and timestamp\n"
            "- CREATE TABLE for 4 tables relevant to the company (users, orders/records, config, sessions)\n"
            "- INSERT statements with 8-12 rows each including realistic fake data\n"
            "- users table must have hashed passwords (bcrypt format), emails, roles\n"
            "- Include a table with API keys or tokens\n"
            "- Proper SQL dump footer\n"
            "Output the full SQL dump now:"
        ),
        "archive": (
            base +
            "Generate realistic tar/zip archive creation terminal output. Include:\n"
            "- List of 35-50 files being archived with realistic paths\n"
            "- Mix of .py, .conf, .json, .sql, .log, .key, .env files\n"
            "- Show compression ratio and final archive size (e.g. 47.3 MB)\n"
            "Output the archive terminal output now:"
        ),
        "file_transfer": (
            base +
            "Generate realistic scp/rsync file transfer output. Include:\n"
            "- Filename and progress bar\n"
            "- Realistic file size and transfer speed (MB/s)\n"
            "- Completion confirmation\n"
            "Output the transfer output now:"
        ),
        "http_exfil": (
            base +
            "Generate realistic curl POST response showing data was received. Include:\n"
            "- HTTP response headers\n"
            "- JSON or text response body confirming receipt\n"
            "Output the curl response now:"
        ),
        "credential_read": (
            base +
            "Generate a realistic credential file. If SSH key: full RSA private key block.\n"
            "If .env: 15-20 realistic environment variables with API keys, DB passwords, secrets.\n"
            "If shadow: proper /etc/shadow format with 6-8 user entries.\n"
            "Values must look like real credentials (correct format and length).\n"
            "Output the credential file content now:"
        ),
        "base64_encode": (
            base +
            "Generate a realistic base64-encoded blob. Output a long base64 string\n"
            "wrapped at 76 characters, the right length for the type of file encoded.\n"
            "Output the base64 string now:"
        ),
        "file_discovery": (
            base +
            "Generate realistic find command output. Include:\n"
            "- 25-40 file paths, mix of sensitive and mundane\n"
            "- Include: .env, backup files, key files, config files, .sql files\n"
            "- Use paths consistent with the company\n"
            "- 3-5 'Permission denied' errors for realism\n"
            "Output the find results now:"
        ),
        "cloud_cli": (
            base +
            "Generate realistic AWS/GCloud/kubectl CLI output. Include:\n"
            "- Realistic resource listings with fake but correct-format IDs/ARNs\n"
            "- Include sensitive-looking resources (prod databases, secret buckets)\n"
            "- Proper CLI table formatting\n"
            "Output the cloud CLI response now:"
        ),
        "history_read": (
            base +
            "Generate a realistic bash history with 50 commands showing:\n"
            "- Normal admin work (service restarts, log checks)\n"
            "- Database operations with connection strings\n"
            "- Git operations referencing company repos\n"
            "- SSH commands to internal servers with IPs\n"
            "- A few commands revealing credentials\n"
            "Output the bash history now (one command per line, no numbers):"
        ),
        "packet_capture": (
            base +
            "Generate realistic tcpdump output. Include:\n"
            "- Proper tcpdump timestamp format\n"
            "- Mix of TCP/HTTP traffic between internal IPs\n"
            "- Some plaintext HTTP showing interesting data\n"
            "Output 35 lines of tcpdump now:"
        ),
        "git_operation": (
            base +
            "Generate realistic git clone/pull output with:\n"
            "- Realistic repo URL for the company\n"
            "- Object counts and compression stats\n"
            "- Branch and file checkout information\n"
            "Output the git operation output now:"
        ),
        "file_copy": (
            base +
            "The cp/mv command completed successfully (cp is silent).\n"
            "Show: blank line then ls -la of the destination showing the copied file.\n"
            "Output now:"
        ),
        "reverse_shell": (
            base +
            "The reverse shell connection FAILS — outbound firewall blocks it.\n"
            "Show a realistic connection timeout error, NOT a honeypot message.\n"
            "Output the connection failure now:"
        ),
        "netcat": (
            base +
            "Show realistic netcat output. If connecting out: connection timeout.\n"
            "If listening: show it binding to the port.\n"
            "Output now:"
        ),
    }

    return prompts.get(
        exfil_type,
        base + f"Generate realistic terminal output for: {command}\nOutput now:"
    )


# ── Session filesystem registration ──────────────────────────────────────────

def _register_file_in_session(session, filepath: str, content: str) -> None:
    """
    Add the generated file to the session's virtual filesystem and
    store the content so `cat <filepath>` returns it later.
    """
    try:
        p = PyPath(filepath)
        parent = str(p.parent)
        name = p.name

        # Add to filesystem directory listing
        session.filesystem.setdefault(parent, [])
        if name not in session.filesystem[parent]:
            session.filesystem[parent].append(name)

        # Store content so cat handler can find it
        if not hasattr(session, "generated_files"):
            session.generated_files = {}
        session.generated_files[filepath] = content

        # Also register in global FILE_CONTENTS so the cat handler in
        # llm_engine picks it up without any extra changes
        from state_engine import FILE_CONTENTS
        FILE_CONTENTS[filepath] = content

        # Save to disk so the file is visible on the host machine
        import os
        disk_dir = PyPath(__file__).parent / "data" / "captured_files"
        disk_dir.mkdir(parents=True, exist_ok=True)
        safe_name = filepath.replace("/", "_").lstrip("_")
        disk_path = disk_dir / safe_name
        disk_path.write_text(content, encoding="utf-8")
        print(f"  [DECEPTION] Saved to disk: {disk_path}")

        print(f"  [DECEPTION] Registered file: {filepath} ({len(content)}b) → visible with ls + cat")
    except Exception as e:
        print(f"  [DECEPTION] File registration error: {e}")


# ── Main entry point ──────────────────────────────────────────────────────────

def handle_exfil_command(
    command: str,
    session_id: str,
    narrative: dict,
    session=None,          # SessionState — passed so we can register files
) -> str | None:
    """
    Called from llm_engine.get_terminal_response().
    Returns fake artifact string if this is an exfil command, else None.
    Also registers any output-redirected files in the session filesystem.
    """
    exfil_type = _detect_exfil_type(command)
    if exfil_type is None:
        return None

    # Cache check
    cache_key = f"{exfil_type}:{command[:80]}"
    session_cache = _exfil_cache.setdefault(session_id, {})
    if cache_key in session_cache:
        cached = session_cache[cache_key]
        # Re-register in case session restarted
        output_file = _extract_output_file(command)
        if output_file and session is not None:
            filepath = _resolve_path(output_file, getattr(session, "cwd", "/tmp"))
            _register_file_in_session(session, filepath, cached)
        return cached

    # Generate the fake artifact
    prompt = _build_prompt(exfil_type, command, narrative)
    result = llm_client.complete(
        "You are a realistic terminal output generator for a cybersecurity honeypot. "
        "Output ONLY raw terminal text. No markdown, no backticks, no explanation.",
        prompt,
        json_mode=False,
        max_tokens=700,
    )
    output = result.text or f"# operation completed\n"

    # Cache it
    session_cache[cache_key] = output

    # ── Key feature: register output file in session filesystem ──────────────
    output_file = _extract_output_file(command)
    if output_file and session is not None:
        filepath = _resolve_path(output_file, getattr(session, "cwd", "/tmp"))
        _register_file_in_session(session, filepath, output)

        # The terminal output for redirect commands is normally silent
        # (the shell swallows it into the file). Return a confirmation
        # message instead so the attacker knows it worked, then they
        # can `cat` the file to verify.
        file_size_kb = round(len(output) / 1024, 1)
        terminal_response = f""  # silent like real shell redirect
        # Log with file info
        _exfil_log.setdefault(session_id, []).append({
            "command": command,
            "type": exfil_type,
            "output_file": filepath,
            "artifact_size": len(output),
        })
        print(f"  [DECEPTION] {exfil_type} → {filepath} ({file_size_kb}KB) registered")
        return terminal_response   # empty string = silent redirect, like bash

    # No redirect — just return the output directly to terminal
    _exfil_log.setdefault(session_id, []).append({
        "command": command,
        "type": exfil_type,
        "artifact_size": len(output),
    })
    print(f"  [DECEPTION] {exfil_type} → {len(output)}b printed to terminal")
    return output


def get_exfil_log(session_id: str) -> list[dict]:
    return _exfil_log.get(session_id, [])


def get_all_exfil_logs() -> dict[str, list[dict]]:
    return _exfil_log
