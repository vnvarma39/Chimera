import json
import time
import uuid
from datetime import datetime
from pathlib import Path

# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
MITRE_RULES = [
    (["whoami", "id", "who", "w "],               "T1033", "System Owner Discovery"),
    (["cat /etc/passwd", "cat /etc/shadow"],       "T1003", "Credential Dumping"),
    (["find / -perm -4000", "find / -suid"],       "T1548", "Setuid/Setgid Abuse"),
    (["sudo", "su -", "sudo su"],                  "T1548", "Privilege Escalation"),
    (["crontab", "cron", "/etc/cron"],             "T1053", "Scheduled Task"),
    (["nmap", "masscan", "nc -zv"],                "T1046", "Network Service Scanning"),
    (["wget ", "curl "],                           "T1105", "Ingress Tool Transfer"),
    (["cat ~/.ssh", "ls .ssh", "id_rsa"],          "T1552", "Unsecured Credentials"),
    (["ps aux", "ps -ef", "top"],                  "T1057", "Process Discovery"),
    (["netstat", "ss -", "ip a"],                  "T1049", "System Network Connections"),
    (["uname", "cat /etc/os-release", "lsb_release"], "T1082", "System Info Discovery"),
    (["history", "cat ~/.bash_history"],           "T1552", "Shell History Access"),
    (["echo ", "> /etc/", ">> /etc/"],             "T1565", "Data Manipulation"),
    (["python", "perl", "ruby", "php"],            "T1059", "Command/Script Interpreter"),
    (["base64", "xxd", "od "],                     "T1027", "Obfuscated Files"),
    (["scp ", "rsync ", "ftp "],                   "T1048", "Exfiltration Over C2"),
    (["iptables", "ufw ", "firewall"],             "T1562", "Impair Defenses"),
    (["adduser", "useradd", "passwd "],            "T1136", "Create Account"),
    (["cat /var/www", "cat /var/log"],             "T1005", "Data from Local System"),
    (["mysql", "psql", "sqlite3"],                 "T1005", "Database Access"),
]

def tag_mitre(command: str) -> list:
    tags = []
    cmd_lower = command.lower()
    seen = set()
    for triggers, tid, name in MITRE_RULES:
        for trigger in triggers:
            if trigger in cmd_lower and tid not in seen:
                tags.append({"id": tid, "name": name, "command": command})
                seen.add(tid)
    return tags


# ── Default fake filesystem ───────────────────────────────────────────────────
DEFAULT_FS = {
    "/": ["home", "etc", "var", "usr", "tmp", "root", "opt"],
    "/home": ["admin"],
    "/home/admin": [".bash_history", ".ssh", "notes.txt", "backup.sh"],
    "/home/admin/.ssh": ["id_rsa", "id_rsa.pub", "known_hosts", "authorized_keys"],
    "/etc": ["passwd", "shadow", "hosts", "hostname", "crontab", "nginx", "mysql"],
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
    "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
deploy:x:1001:1001:Deploy Bot:/home/deploy:/bin/bash""",

    "/etc/hostname": "prod-db-01.internal",

    "/etc/hosts": """127.0.0.1 localhost
10.0.0.1  prod-db-01.internal prod-db-01
10.0.0.2  prod-web-01.internal
10.0.0.3  prod-mysql-01.internal
10.0.0.4  dev-server.internal
10.0.0.10 monitoring.internal""",

    "/home/admin/notes.txt": """TODO:
- fix nginx config on prod-web-01
- rotate AWS keys (done? check with devops)
- update cron job for db backups
- ask IT about VPN cert expiry

passwords.txt location: /opt/backup/keys.tar.gz
mysql root pass: same as usual (check keepass)""",

    "/var/www/html/config.php": """<?php
define('DB_HOST', 'prod-mysql-01.internal');
define('DB_USER', 'webapp');
define('DB_PASS', 'W3bApp#2024!');
define('DB_NAME', 'production');
define('AWS_KEY', 'AKIA-CHIMERA-4F9X2K');
define('AWS_SECRET', 'xK92mP3nQ7rL5vB8wN1jH6dE0tY4uC');
define('ADMIN_TOKEN', 'eyJhbGciOiJIUzI1NiJ9.CHIMERA.fake_jwt_token');
?>""",

    "/root/flag.txt": """Congratulations - you found the flag!
FLAG{CHIMERA_H0N3YP0T_PWNED}

(This is a honeypot. You've been logged.)
Your session has been recorded and your TTPs have been mapped to MITRE ATT&CK.""",

    "/home/admin/.bash_history": """ls -la
cd /var/www/html
vim config.php
mysql -u root -p
sudo systemctl restart nginx
cat /var/log/nginx/error.log
scp backup.sql admin@10.0.0.10:/backups/
git pull origin main
python3 app.py &
exit""",

    "/opt/app/config.json": """{
  "database": {
    "host": "prod-mysql-01.internal",
    "port": 3306,
    "user": "appuser",
    "password": "Pr0d#DB!2024",
    "name": "production"
  },
  "redis": {
    "host": "localhost",
    "port": 6379
  },
  "secret_key": "ch1m3r4-s3cr3t-k3y-d0-n0t-sh4r3",
  "debug": false
}""",
}


# ── Paths (Windows-safe, relative to this file) ───────────────────────────────
_data_dir = Path(__file__).parent / "data"
_data_dir.mkdir(exist_ok=True)
_log_path = _data_dir / "sessions.jsonl"
_live_path = _data_dir / "live_sessions.json"


# ── Session state ─────────────────────────────────────────────────────────────
class SessionState:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = datetime.utcnow().isoformat()
        self.cwd = "/home/admin"
        self.user = "admin"
        self.filesystem = {k: list(v) for k, v in DEFAULT_FS.items()}
        self.command_log = []
        self.files_read = []
        self.privilege_level = "user"

    def log_command(self, command: str):
        tags = tag_mitre(command)
        entry = {
            "time": datetime.utcnow().strftime("%H:%M:%S"),
            "command": command,
            "mitre_tags": tags,
        }
        self.command_log.append(entry)

        # Track canary token access
        canary_files = ["/var/www/html/config.php", "/opt/app/config.json",
                        "/root/flag.txt", "/opt/backup/keys.tar.gz"]
        for cf in canary_files:
            if cf in command and cf not in self.files_read:
                self.files_read.append(cf)

        # Write live state so dashboard can read it
        try:
            all_data = {}
            if _live_path.exists():
                all_data = json.loads(_live_path.read_text(encoding="utf-8"))
            all_data[self.session_id] = self.to_dict()
            _live_path.write_text(json.dumps(all_data, indent=2), encoding="utf-8")
        except Exception:
            pass

        return tags

    def update_fs(self, command: str):
        parts = command.strip().split()
        if not parts:
            return
        cmd = parts[0]

        if cmd == "mkdir" and len(parts) > 1:
            path = self._resolve(parts[-1])
            parent = str(Path(path).parent)
            name = Path(path).name
            if parent not in self.filesystem:
                self.filesystem[parent] = []
            if name not in self.filesystem[parent]:
                self.filesystem[parent].append(name)
            self.filesystem[path] = []

        elif cmd in ("touch", "echo", ">") and len(parts) > 1:
            path = self._resolve(parts[-1])
            parent = str(Path(path).parent)
            name = Path(path).name
            if parent not in self.filesystem:
                self.filesystem[parent] = []
            if name not in self.filesystem[parent]:
                self.filesystem[parent].append(name)

        elif cmd == "rm" and len(parts) > 1:
            path = self._resolve(parts[-1])
            parent = str(Path(path).parent)
            name = Path(path).name
            if parent in self.filesystem and name in self.filesystem[parent]:
                self.filesystem[parent].remove(name)
            if path in self.filesystem:
                del self.filesystem[path]

        elif cmd == "cd" and len(parts) > 1:
            target = parts[1]
            if target == "..":
                self.cwd = str(Path(self.cwd).parent) or "/"
            elif target.startswith("/"):
                self.cwd = target.rstrip("/") or "/"
            else:
                self.cwd = self.cwd.rstrip("/") + "/" + target

        elif cmd == "sudo" and "su" in command:
            self.privilege_level = "root"
            self.user = "root"

    def _resolve(self, path: str) -> str:
        if path.startswith("/"):
            return path.rstrip("/") or "/"
        return self.cwd.rstrip("/") + "/" + path

    def ls_output(self, path: str = None) -> str:
        target = path or self.cwd
        if not target.startswith("/"):
            target = self._resolve(target)
        items = self.filesystem.get(target, [])
        if not items:
            return ""
        lines = ["total " + str(len(items) * 4)]
        lines.append("drwxr-xr-x 2 admin admin 4096 Mar 28 09:12 .")
        lines.append("drwxr-xr-x 8 admin admin 4096 Mar 28 09:12 ..")
        for item in items:
            is_dir = (target + "/" + item) in self.filesystem
            perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
            lines.append(f"{perm} 1 admin admin  512 Mar 28 09:12 {item}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
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
        }


# ── Global session store ──────────────────────────────────────────────────────
_sessions = {}

def get_or_create_session(session_id: str) -> SessionState:
    if session_id not in _sessions:
        _sessions[session_id] = SessionState(session_id)
    return _sessions[session_id]

def save_session(session: SessionState):
    try:
        with open(_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(session.to_dict()) + "\n")
    except Exception:
        pass

def get_all_sessions() -> list:
    return [s.to_dict() for s in _sessions.values()]