from __future__ import annotations

"""
state_engine.py — Project Chimera (fixed)

SessionState now carries:
  - d_scores: list[float]  — GAN discriminator score per command
  - osi_log: list[dict]    — OSI layer data per command

command_log entries now include an osi_layer field so the dashboard
can show it inline without a separate data file.

_persist_live() also writes evolutions, narrative, d_scores so the
dashboard can read them without separate API calls.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from config import DATA_DIR

MITRE_RULES = [
    (["whoami", "id", "who", "w "], "T1033", "System Owner Discovery"),
    (["cat /etc/passwd", "cat /etc/shadow"], "T1003", "Credential Dumping"),
    (["find / -perm -4000", "find / -suid"], "T1548", "Setuid/Setgid Abuse"),
    (["sudo", "su -", "sudo su"], "T1548", "Privilege Escalation"),
    (["crontab", "cron", "/etc/cron"], "T1053", "Scheduled Task"),
    (["nmap", "masscan", "nc -zv"], "T1046", "Network Service Scanning"),
    (["wget ", "curl "], "T1105", "Ingress Tool Transfer"),
    (["cat ~/.ssh", "ls .ssh", "id_rsa"], "T1552", "Unsecured Credentials"),
    (["ps aux", "ps -ef", "top"], "T1057", "Process Discovery"),
    (["netstat", "ss -", "ip a"], "T1049", "System Network Connections"),
    (["uname", "cat /etc/os-release", "lsb_release"], "T1082", "System Info Discovery"),
    (["history", "cat ~/.bash_history"], "T1552", "Shell History Access"),
    (["echo ", "> /etc/", ">> /etc/"], "T1565", "Data Manipulation"),
    (["python", "perl", "ruby", "php"], "T1059", "Command/Script Interpreter"),
    (["base64", "xxd", "od "], "T1027", "Obfuscated Files"),
    (["scp ", "rsync ", "ftp "], "T1048", "Exfiltration Over C2"),
    (["iptables", "ufw ", "firewall"], "T1562", "Impair Defenses"),
    (["adduser", "useradd", "passwd "], "T1136", "Create Account"),
    (["cat /var/www", "cat /var/log"], "T1005", "Data from Local System"),
    (["mysql", "psql", "sqlite3"], "T1005", "Database Access"),
]

DEFAULT_FS = {
    "/": ["home", "etc", "var", "usr", "tmp", "root", "opt"],
    "/home": ["admin"],
    "/home/admin": [".bash_history", ".ssh", "notes.txt", "backup.sh"],
    "/home/admin/.ssh": ["id_rsa", "id_rsa.pub", "known_hosts", "authorized_keys"],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "cron.d", "nginx", "mysql"],
    "/etc/nginx": ["nginx.conf", "sites-enabled"],
    "/etc/mysql": ["my.cnf"],
    "/var": ["www", "log", "backups"],
    "/var/www": ["html"],
    "/var/www/html": ["index.php", "config.php", "admin.php", ".htaccess"],
    "/var/log": ["auth.log", "syslog", "nginx", "mysql.log"],
    "/tmp": [],
    "/root": [".bash_history", ".ssh", "flag.txt"],
    "/opt": ["app", "backup"],
    "/opt/app": ["app.py", "config.json", "requirements.txt"],
    "/opt/backup": ["db_backup_2024.sql.gz", "keys.tar.gz"],
}

FILE_CONTENTS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "/etc/hostname": "prod-db-01.internal",
    "/etc/hosts": "127.0.0.1 localhost\n10.0.0.1 prod-db-01.internal prod-db-01\n10.0.0.2 prod-web-01.internal\n10.0.0.3 prod-mysql-01.internal",
    "/home/admin/notes.txt": "TODO:\n- fix nginx config\n- rotate credentials\n- update cron job for db backups\npasswords.txt location: /opt/backup/keys.tar.gz",
    "/var/www/html/config.php": "<?php\ndefine('DB_HOST', 'prod-mysql-01.internal');\ndefine('DB_USER', 'webapp');\ndefine('DB_PASS', 'W3bApp#2024!');\ndefine('ADMIN_TOKEN', 'chimera.fake.jwt');\n?>",
    "/root/flag.txt": "FLAG{CHIMERA_H0N3YP0T_PWNED}",
    "/home/admin/.bash_history": "ls -la\ncd /var/www/html\nvim config.php\nmysql -u root -p\nsudo systemctl restart nginx\nexit",
    "/opt/app/config.json": '{"database": {"host": "prod-mysql-01.internal", "port": 3306, "user": "appuser", "password": "Pr0d#DB!2024", "name": "production"}, "debug": false}',
}

_LOG_PATH = DATA_DIR / "sessions.jsonl"
_LIVE_PATH = DATA_DIR / "live_sessions.json"


def tag_mitre(command: str) -> list[dict[str, Any]]:
    cmd = command.lower()
    out, seen = [], set()
    for triggers, tid, name in MITRE_RULES:
        if any(trigger in cmd for trigger in triggers) and tid not in seen:
            out.append({"id": tid, "name": name, "command": command})
            seen.add(tid)
    return out


@dataclass
class SessionState:
    session_id: str
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    cwd: str = "/home/admin"
    user: str = "admin"
    privilege_level: str = "user"
    filesystem: dict[str, list[str]] = field(default_factory=lambda: {k: list(v) for k, v in DEFAULT_FS.items()})
    command_log: list[dict[str, Any]] = field(default_factory=list)
    files_read: list[str] = field(default_factory=list)
    # New fields
    d_scores: list[float] = field(default_factory=list)
    osi_log: list[dict] = field(default_factory=list)

    def log_command(self, command: str, osi_layer: str = "", d_score: float | None = None) -> list[dict[str, Any]]:
        tags = tag_mitre(command)
        entry: dict[str, Any] = {
            "time": datetime.utcnow().strftime("%H:%M:%S"),
            "command": command,
            "mitre_tags": tags,
        }
        if osi_layer:
            entry["osi_layer"] = osi_layer
        if d_score is not None:
            entry["d_score"] = round(d_score, 4)
            self.d_scores.append(d_score)
        self.command_log.append(entry)

        for cf in ("/var/www/html/config.php", "/opt/app/config.json", "/root/flag.txt", "/opt/backup/keys.tar.gz"):
            if cf in command and cf not in self.files_read:
                self.files_read.append(cf)
        self._persist_live()
        return tags

    def update_fs(self, command: str) -> None:
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0]
        if cmd == "cd" and len(parts) > 1:
            target = parts[1]
            if target == "..":
                self.cwd = str(Path(self.cwd).parent) or "/"
            elif target.startswith("/"):
                self.cwd = target.rstrip("/") or "/"
            else:
                self.cwd = (self.cwd.rstrip("/") + "/" + target).replace("//", "/")
        elif cmd == "mkdir" and len(parts) > 1:
            path = self._resolve(parts[-1])
            parent = str(Path(path).parent)
            name = Path(path).name
            self.filesystem.setdefault(parent, [])
            if name not in self.filesystem[parent]:
                self.filesystem[parent].append(name)
            self.filesystem.setdefault(path, [])
        elif cmd in ("touch", "echo") and len(parts) > 1:
            path = self._resolve(parts[-1])
            parent = str(Path(path).parent)
            name = Path(path).name
            self.filesystem.setdefault(parent, [])
            if name not in self.filesystem[parent]:
                self.filesystem[parent].append(name)
        elif cmd == "rm" and len(parts) > 1:
            path = self._resolve(parts[-1])
            parent = str(Path(path).parent)
            name = Path(path).name
            if parent in self.filesystem and name in self.filesystem[parent]:
                self.filesystem[parent].remove(name)
            self.filesystem.pop(path, None)
        elif cmd == "sudo" and "su" in command:
            self.privilege_level = "root"
            self.user = "root"

    def _resolve(self, path: str) -> str:
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        return (self.cwd.rstrip("/") + "/" + path).replace("//", "/")

    def ls_output(self, path: str | None = None) -> str:
        target = path or self.cwd
        if not target.startswith("/"):
            target = self._resolve(target)
        items = self.filesystem.get(target, [])
        if not items:
            return ""
        lines = [
            f"total {len(items) * 4}",
            "drwxr-xr-x 2 admin admin 4096 Mar 28 09:12 .",
            "drwxr-xr-x 8 admin admin 4096 Mar 28 09:12 ..",
        ]
        for item in items:
            is_dir = (target.rstrip("/") + "/" + item) in self.filesystem
            perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
            lines.append(f"{perm} 1 admin admin 512 Mar 28 09:12 {item}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "start_time": self.start_time,
            "cwd": self.cwd,
            "user": self.user,
            "privilege_level": self.privilege_level,
            "command_count": len(self.command_log),
            "command_log": self.command_log,
            "files_read": self.files_read,
            "filesystem": self.filesystem,
            "d_scores": self.d_scores,
            "narrative": getattr(self, "_narrative_snapshot", {}),
            "evolutions": [],  # populated by controller._persist_evolutions()
        }

    def _persist_live(self) -> None:
        try:
            data = {}
            if _LIVE_PATH.exists():
                data = json.loads(_LIVE_PATH.read_text(encoding="utf-8"))
            data[self.session_id] = self.to_dict()
            _LIVE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass


_SESSIONS: dict[str, SessionState] = {}


def get_or_create_session(session_id: str) -> SessionState:
    if session_id not in _SESSIONS:
        _SESSIONS[session_id] = SessionState(session_id)
    return _SESSIONS[session_id]


def save_session(session: SessionState) -> None:
    try:
        with _LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(session.to_dict()) + "\n")
    except Exception:
        pass


def get_all_sessions() -> list[dict[str, Any]]:
    return [s.to_dict() for s in _SESSIONS.values()]
