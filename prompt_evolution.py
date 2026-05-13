from __future__ import annotations

"""
prompt_evolution.py — Project Chimera (fixed)

FIX 3: build_evolved_system_prompt() now accepts and injects
gan_patches from the red-team discriminator into the generator's
system prompt. Previously this parameter was missing entirely.
"""

from llm_client import llm_client

EVOLVE_EVERY = 5


def should_evolve(command_count: int) -> bool:
    return command_count > 0 and command_count % EVOLVE_EVERY == 0


def evolve_prompt(base_prompt: str, command_history: list, narrative: dict, evolution_count: int) -> dict:
    recent = [e.get("command", "") for e in command_history[-20:]]
    system = "You adapt honeypot deception rules and return strict JSON."
    user = (
        f"Recent attacker commands: {recent}. "
        "Return JSON with: attacker_focus, skill_assessment, evolved_rules, "
        "new_bait_files (list of {path, reason}), adapted_vulnerability, evolution_summary."
    )
    result = llm_client.complete(system, user, json_mode=True, max_tokens=500)
    if result.parsed:
        result.parsed.setdefault("evolution_number", evolution_count)
        return result.parsed
    return {
        "attacker_focus": "recon",
        "skill_assessment": "intermediate",
        "evolved_rules": "Keep filesystem plausible and expose more realistic decoy files.",
        "new_bait_files": [{"path": "/var/backups/db_snapshot.sql", "reason": "credential and schema hunting"}],
        "adapted_vulnerability": "stale backup archive with useful metadata",
        "evolution_summary": "Maintained baseline deception while adding a backup bait path.",
        "evolution_number": evolution_count,
    }


def build_evolved_system_prompt(
    base_prompt: str,
    evolutions: list,
    gan_patches: list | None = None,   # FIX 3: was missing
) -> str:
    """
    Append adaptive evolution rules AND red-team GAN patches to the base prompt.
    Both sources of self-improvement are now injected into the generator.
    """
    result = base_prompt

    if evolutions:
        rules = []
        for ev in evolutions:
            rules.append(
                f"[ADAPTIVE LAYER {ev.get('evolution_number', '?')}] "
                f"Attacker focus: {ev.get('attacker_focus', 'unknown')}. "
                f"{ev.get('evolved_rules', '')}"
            )
        result += "\n\nADAPTIVE RULES:\n" + "\n".join(rules)

    # FIX 3: inject discriminator patches into the generator
    if gan_patches:
        patch_lines = []
        for p in gan_patches[-4:]:   # cap at 4 to avoid prompt bloat
            priority = p.get("priority", "medium")
            fix = p.get("fix", "")
            if fix:
                patch_lines.append(f"[GAN PATCH/{priority.upper()}] {fix}")
        if patch_lines:
            result += "\n\nGAN DISCRIMINATOR PATCHES (active — follow these precisely):\n" + "\n".join(patch_lines)

    return result
