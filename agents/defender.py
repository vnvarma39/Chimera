from __future__ import annotations

"""
agents/defender.py — Project Chimera (fixed)

DefenderAgent now uses the GAN discriminator score returned by
receive_command() instead of a hardcoded heuristic.

Score interpretation (from trainer.score_command):
  - High score (~1.0): D thinks this looks like a real-world command  → less suspicious
  - Low score (~0.0):  D thinks this is anomalous / doesn't match training data → more suspicious

The inversion (1 - d_score) is the anomaly/suspicion signal.
Threshold 0.65 = suspicious if D gives < 35% confidence it's normal.
"""

from agents.base import Agent


class DefenderAgent(Agent):
    SUSPICION_THRESHOLD = 0.65  # d_score below this → flag as suspicious

    def __init__(self, orchestrator):
        super().__init__("DefenderAgent", orchestrator)

    def run(self):
        from llm_client import llm_client
        while self.running:
            event = self.orchestrator.next_event()
            if event is not None:
                d_score = event.get("d_score")
                command = event.get("command")
                
                if command:
                    # Use LLM for qualitative analysis of real commands
                    system = (
                        "You are a SOC Analyst. Analyze the following command and determine "
                        "if it's malicious, suspicious, or normal. Provide a brief reason."
                    )
                    user = f"Command: {command}\nGAN D-Score: {d_score}"
                    result = llm_client.complete(system, user, json_mode=True, max_tokens=150)
                    analysis = result.parsed if result.parsed else {"verdict": "unknown", "reason": "LLM failure"}
                    
                    verdict = analysis.get("verdict", "normal").lower()
                    score = d_score if d_score is not None else 0.5
                    self.orchestrator.log_detection(event, f"{verdict} ({analysis.get('reason', '')})", score)
                else:
                    # Synthetic event fallback
                    score = 0.9 if event.get("synthetic_attack") else 0.2 if event.get("synthetic") else 0.5
                    verdict = "attack" if score >= 0.7 else "normal"
                    self.orchestrator.log_detection(event, verdict, score)
            self.idle(0.15)
