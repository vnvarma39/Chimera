from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path

from state_engine import MITRE_RULES

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

print("=" * 60)
print("Project Chimera X — Data Pipeline")
print(f"Run at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
print("=" * 60)

mitre_index = {tid: name for _, tid, name in MITRE_RULES}
print(f"MITRE rules loaded: {len(mitre_index)}")

log_file = DATA_DIR / "sessions.jsonl"
sessions = []
if log_file.exists():
    for line in log_file.read_text(encoding="utf-8").splitlines():
        try:
            sessions.append(json.loads(line))
        except Exception:
            pass

print(f"Sessions loaded: {len(sessions)}")
all_commands = []
all_tags = []
for s in sessions:
    for e in s.get("command_log", []):
        all_commands.append(e.get("command", ""))
        all_tags.extend([t["id"] for t in e.get("mitre_tags", [])])

records = []
for s in sessions:
    records.append({
        "session_id": s.get("session_id"),
        "start_time": s.get("start_time"),
        "command_count": s.get("command_count", 0),
        "privilege": s.get("privilege_level", "user"),
        "mitre_ids": sorted({t["id"] for e in s.get("command_log", []) for t in e.get("mitre_tags", [])}),
        "canary_hits": s.get("files_read", []),
        "commands": [e.get("command", "") for e in s.get("command_log", [])],
    })

(DATA_DIR / "chimera_dataset.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
summary = {
    "pipeline_run": datetime.utcnow().isoformat(),
    "sessions_total": len(sessions),
    "commands_total": len(all_commands),
    "unique_commands": len(set(all_commands)),
    "mitre_tags_total": len(all_tags),
    "top_commands": Counter(all_commands).most_common(5),
    "top_techniques": Counter(all_tags).most_common(5),
}
(DATA_DIR / "pipeline_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print("Exported chimera_dataset.json and pipeline_summary.json")
