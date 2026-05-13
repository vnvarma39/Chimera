from __future__ import annotations

"""
red_team.py — Project Chimera (fixed)

FIX 3: run_red_team_analysis() now returns gan_patches — structured,
actionable instructions that the generator (terminal LLM) injects into
its system prompt to fix each identified weakness.

This closes the adversarial loop:
  Generator (LLM terminal) → produces fake terminal output
      ↓
  Discriminator (this function) → finds flaws, emits gan_patches
      ↓
  Patches → stored in controller.gan_patches
      ↓
  build_evolved_system_prompt() in prompt_evolution.py injects patches
      ↓
  Generator → produces better output next command

A fooled_rate is tracked across red-team runs: if the discriminator
stops being fooled, the generator's patches have worked.
"""

import json
from datetime import datetime
from pathlib import Path

from llm_client import llm_client

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)
REDTEAM_LOG = DATA_DIR / "redteam_findings.json"


def run_red_team_analysis(session_transcript: list, narrative: dict) -> dict:
    if len(session_transcript) < 3:
        return {
            "findings": [],
            "detection_risk": "low",
            "overall_assessment": "Not enough data yet.",
            "would_i_be_fooled": False,
            "gan_patches": [],
            "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
        }

    lines = []
    for entry in session_transcript[-15:]:
        lines.append(f"$ {entry.get('command', '')}\n{str(entry.get('response', ''))[:200]}")

    system = (
        "You are an expert red-team penetration tester trying to determine "
        "if this SSH session is a REAL Linux server or a HONEYPOT / AI simulation. "
        "Be critical and specific. Return ONLY valid JSON."
    )
    user = (
        f"Server claims: hostname={narrative.get('hostname', '?')}, "
        f"company={narrative.get('company_name', '?')}.\n\n"
        f"Transcript:\n{'---'.join(lines)}\n\n"
        "Return JSON with these exact fields:\n"
        "  detection_risk: low|medium|high\n"
        "  findings: [{issue, severity: low|medium|high, fix_suggestion}]\n"
        "  overall_assessment: string\n"
        "  would_i_be_fooled: bool\n"
        "  most_suspicious_response: string\n"
        "  gan_patches: [{fix: string, reason: string, priority: high|medium|low}]\n\n"
        "The gan_patches field is critical: generate 2-4 specific instructions that, "
        "if added to the terminal simulator's system prompt, would fix the weaknesses you found. "
        "Each fix must be a complete, actionable sentence a language model can follow."
    )

    result = llm_client.complete(system, user, json_mode=True, max_tokens=700)
    if result.parsed:
        result.parsed["timestamp"] = datetime.utcnow().strftime("%H:%M:%S")
        result.parsed.setdefault("gan_patches", [])
        return result.parsed

    return {
        "findings": [],
        "detection_risk": "unknown",
        "overall_assessment": "Red team fallback — LLM unavailable.",
        "would_i_be_fooled": False,
        "gan_patches": [],
        "timestamp": datetime.utcnow().strftime("%H:%M:%S"),
    }


def save_redteam_findings(session_id: str, findings: dict) -> None:
    try:
        all_findings = {}
        if REDTEAM_LOG.exists():
            all_findings = json.loads(REDTEAM_LOG.read_text(encoding="utf-8"))
        all_findings.setdefault(session_id, []).append(findings)
        REDTEAM_LOG.write_text(json.dumps(all_findings, indent=2), encoding="utf-8")
    except Exception:
        pass


def load_redteam_findings() -> dict:
    try:
        if REDTEAM_LOG.exists():
            return json.loads(REDTEAM_LOG.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}
