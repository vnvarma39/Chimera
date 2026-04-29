"""
red_team.py — Project Chimera
A second LLM instance plays adversarial red-teamer.
It reviews session transcripts and tries to identify inconsistencies
that would reveal this is a honeypot. Findings are logged for display
in the dashboard. This is the GAN-style self-improvement loop.
"""

from openai import OpenAI
import json
from pathlib import Path
from datetime import datetime

client = OpenAI(
    api_key="YOUR OPEN ROUTER API KEY HERE",
    base_url="https://openrouter.ai/api/v1"
)

_data_dir = Path(__file__).parent / "data"
_data_dir.mkdir(exist_ok=True)
_redteam_log = _data_dir / "redteam_findings.json"


def run_red_team_analysis(session_transcript: list, narrative: dict) -> dict:
    """
    Given a list of (command, response) pairs from the session,
    asks the red-team LLM to find anything that would expose the honeypot.
    Returns structured findings.
    """
    if len(session_transcript) < 3:
        return {"findings": [], "detection_risk": "low", "summary": "Not enough data yet."}

    # Build transcript string (last 15 exchanges)
    transcript_lines = []
    for entry in session_transcript[-15:]:
        cmd = entry.get("command", "")
        resp = entry.get("response", "")[:200]  # truncate long responses
        transcript_lines.append(f"$ {cmd}\n{resp}")
    transcript_str = "\n---\n".join(transcript_lines)

    company = narrative.get("company_name", "Unknown Corp")
    hostname = narrative.get("hostname", "prod-db-01.internal")

    prompt = f"""You are an expert penetration tester trying to determine if this is a REAL Linux server 
or a HONEYPOT / AI simulation. Analyze this SSH session transcript:

SERVER CLAIMS: hostname={hostname}, company={company}

TRANSCRIPT:
{transcript_str}

Look for these red flags that indicate AI/honeypot:
- Response timing inconsistencies (mentioned by user)
- File contents that are TOO perfect or convenient
- Missing system noise (processes, log clutter, etc.)
- Inconsistent user histories or file timestamps  
- Responses that are too clean / lack realistic artifacts
- Missing common system daemons in ps output
- File sizes/permissions that don't match real systems

Respond with JSON only (no markdown):
{{
  "detection_risk": "low|medium|high",
  "findings": [
    {{"issue": "specific inconsistency found", "severity": "low|medium|high", "fix_suggestion": "how to make it more convincing"}}
  ],
  "most_suspicious_response": "the response that most clearly looks AI-generated",
  "overall_assessment": "one sentence verdict",
  "would_i_be_fooled": true or false
}}"""

    try:
        resp = client.chat.completions.create(
            model="openai/gpt-4o-mini",
            max_tokens=700,
            messages=[
                {"role": "system", "content": "You are a red-team security expert. Be critical and specific."},
                {"role": "user", "content": prompt}
            ]
        )
        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1])
        result = json.loads(raw)
        result["timestamp"] = datetime.utcnow().strftime("%H:%M:%S")
        return result
    except Exception:
        return {
            "findings": [],
            "detection_risk": "unknown",
            "summary": "Red team analysis failed.",
            "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
        }


def save_redteam_findings(session_id: str, findings: dict):
    """Persist findings so the dashboard can display them."""
    try:
        all_findings = {}
        if _redteam_log.exists():
            all_findings = json.loads(_redteam_log.read_text(encoding="utf-8"))
        if session_id not in all_findings:
            all_findings[session_id] = []
        all_findings[session_id].append(findings)
        _redteam_log.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
    except Exception:
        pass


def load_redteam_findings() -> dict:
    try:
        if _redteam_log.exists():
            return json.loads(_redteam_log.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}
