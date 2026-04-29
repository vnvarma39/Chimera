"""
prompt_evolution.py — Project Chimera
After every N commands, analyzes attacker behavior and rewrites
the system prompt to be more convincing for their specific focus.
The AI is literally modifying its own instructions mid-session.
"""

from openai import OpenAI
import json

client = OpenAI(
    api_key="YOUR OPEN ROUTER API KEY HERE",
    base_url="https://openrouter.ai/api/v1"
)

EVOLVE_EVERY = 5  # rewrite prompt after this many commands


def should_evolve(command_count: int) -> bool:
    return command_count > 0 and command_count % EVOLVE_EVERY == 0


def evolve_prompt(
    base_prompt: str,
    command_history: list,
    narrative: dict,
    evolution_count: int,
) -> dict:
    """
    Analyzes the attacker's command history and returns:
    - evolved_rules: additional system prompt rules tailored to their behavior
    - attacker_focus: what they seem to be after
    - new_bait_files: suggested files to inject into the filesystem
    - evolution_summary: human-readable summary for the dashboard
    """
    commands = [e["command"] for e in command_history[-20:]]
    cmd_str = "\n".join(f"  $ {c}" for c in commands)

    prompt = f"""You are analyzing an attacker's behavior in a honeypot system.
Their last {len(commands)} commands were:
{cmd_str}

Based on this behavior, generate a JSON response (no markdown) with:
{{
  "attacker_focus": "one of: credential_hunting | privilege_escalation | lateral_movement | data_exfiltration | recon | persistence",
  "skill_assessment": "one of: script_kiddie | intermediate | advanced | apt",
  "evolved_rules": "2-3 additional system prompt rules to make the honeypot MORE convincing for this specific attacker. E.g. if they're hunting creds, add more fake credential files. If they're doing recon, add more fake network info.",
  "new_bait_files": [
    {{"path": "/realistic/file/path", "reason": "why this would interest them"}},
    {{"path": "/another/path", "reason": "reason"}}
  ],
  "adapted_vulnerability": "one specific fake vulnerability to expose that matches their current approach",
  "evolution_summary": "one sentence describing how the honeypot adapted"
}}"""

    try:
        resp = client.chat.completions.create(
            model="openai/gpt-4o-mini",
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.choices[0].message.content.strip()
        if raw.startswith("```"):
            lines = raw.split("\n")
            raw = "\n".join(lines[1:-1])
        result = json.loads(raw)
        result["evolution_number"] = evolution_count
        return result
    except Exception as e:
        return {
            "attacker_focus": "recon",
            "skill_assessment": "intermediate",
            "evolved_rules": "Maintain current behavior.",
            "new_bait_files": [],
            "adapted_vulnerability": "none",
            "evolution_summary": f"Evolution {evolution_count}: maintaining baseline deception.",
            "evolution_number": evolution_count,
        }


def build_evolved_system_prompt(base_prompt: str, evolutions: list) -> str:
    """Appends all evolution rules to the base system prompt."""
    if not evolutions:
        return base_prompt

    evolved_sections = []
    for ev in evolutions:
        evolved_sections.append(
            f"\n[ADAPTIVE LAYER {ev['evolution_number']}] "
            f"Attacker focus detected: {ev.get('attacker_focus','unknown')}. "
            f"{ev.get('evolved_rules','')}"
        )

    return base_prompt + "\n\nADAPTIVE RULES (generated during session):" + "".join(evolved_sections)
