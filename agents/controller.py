from __future__ import annotations

"""
agents/controller.py — Project Chimera

Fixes applied:
  1. Evolution results are now persisted to live_sessions.json immediately
     so the dashboard shows them without restarting.
  2. Removed unused imports (session_to_dataset, score_command).
  3. set_narrative() now also syncs narrative to live_sessions.json.
  4. _persist_evolutions() helper centralises the write logic.
"""

import json
import queue
from pathlib import Path
from typing import Any

from agents.attacker import AttackerAgent
from agents.defender import DefenderAgent
from agents.memory import MemoryAgent
from agents.narrative import NarrativeAgent
from agents.osi_agent import OSIAgent
from agents.traffic import TrafficAgent
from gan.synthetic_data import build_dataset
from gan.trainer import GANArtifacts, train_gan, update_gan
from prompt_evolution import evolve_prompt, should_evolve
from red_team import run_red_team_analysis, save_redteam_findings
from state_engine import get_or_create_session
from config import DATA_DIR

_LIVE_PATH = DATA_DIR / "live_sessions.json"


class MultiAgentController:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.session = get_or_create_session(session_id)
        self.event_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.event_log: list[dict] = []
        self.detect_log: list[dict] = []
        self.narrative: dict = {}
        self.evolutions: list[dict] = []
        self.gan_patches: list[dict] = []
        self.osi_log: list[dict] = []
        self.d_scores: list[float] = []

        self.memory = MemoryAgent()
        self.osi = OSIAgent()

        # Train GAN on meaningful attacker-command feature vectors
        real, _ = build_dataset(n=256)
        self.gan_artifacts: GANArtifacts = train_gan(real, epochs=20, batch_size=32)

        self.agents = [
            NarrativeAgent(self),
            TrafficAgent(self),
            AttackerAgent(self),
            DefenderAgent(self),
        ]

    def start(self):
        for agent in self.agents:
            agent.start()

    def stop(self):
        for agent in self.agents:
            agent.stop()

    def set_narrative(self, narrative: dict):
        self.narrative = narrative
        self._persist_evolutions()

    # ── Primary entry point for real SSH commands ─────────────────────────────
    def receive_command(self, command: str) -> dict:
        """
        Called from honeypot.py for every real attacker command.
        Returns {osi_layer, d_score} for the caller to log into the session.
        """
        cmd_index = len(self.session.command_log)

        # OSI classification
        osi_data = self.osi.map_command(command)
        osi_data["command"] = command
        self.osi_log.append(osi_data)

        # Online GAN update + discriminator score
        d_score = update_gan(
            self.gan_artifacts,
            command,
            cmd_index=cmd_index,
            privilege_level=self.session.privilege_level,
        )
        self.d_scores.append(d_score)

        # Memory
        self.memory.store(command, {"osi": osi_data, "d_score": d_score})

        # Prompt evolution — persist immediately so dashboard shows it
        if should_evolve(len(self.session.command_log)):
            ev = evolve_prompt(
                "",
                self.session.command_log,
                self.narrative,
                len(self.evolutions) + 1,
            )
            self.evolutions.append(ev)
            self._persist_evolutions()

        return {"osi_layer": osi_data.get("layer_name", "?"), "d_score": d_score}

    # ── Evolution + narrative persistence ─────────────────────────────────────
    def _persist_evolutions(self) -> None:
        """Write evolutions and narrative into live_sessions.json immediately."""
        try:
            data: dict = {}
            if _LIVE_PATH.exists():
                data = json.loads(_LIVE_PATH.read_text(encoding="utf-8"))
            if self.session_id in data:
                data[self.session_id]["evolutions"] = self.evolutions
                if self.narrative:
                    data[self.session_id]["narrative"] = {
                        "company_name": self.narrative.get("company_name", ""),
                        "hostname":     self.narrative.get("hostname", ""),
                        "sensitivity":  self.narrative.get("sensitivity", ""),
                        "archetype": (
                            self.narrative.get("archetype", {}).get("type", "")
                            if isinstance(self.narrative.get("archetype"), dict)
                            else str(self.narrative.get("archetype", ""))
                        ),
                    }
                _LIVE_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    # ── Synthetic event path (background agents) ──────────────────────────────
    def receive_event(self, event: dict, source: str):
        self.event_log.append({"source": source, "event": event})
        self.event_queue.put(event)
        if source == "AttackerAgent":
            self.memory.store(f"synthetic:{source}", event)

    def next_event(self):
        try:
            return self.event_queue.get_nowait()
        except queue.Empty:
            return None

    def log_detection(self, event: dict, verdict: str, score: float):
        self.detect_log.append({"event": event, "verdict": verdict, "score": score})

    # ── Red-team analysis stores patches ──────────────────────────────────────
    def run_red_team(self, transcript: list, narrative: dict):
        findings = run_red_team_analysis(transcript, narrative)
        save_redteam_findings(self.session_id, findings)
        existing = {p.get("fix", "") for p in self.gan_patches}
        for patch in findings.get("gan_patches", []):
            if patch.get("fix", "") not in existing:
                self.gan_patches.append(patch)
                existing.add(patch.get("fix", ""))

    def get_gan_patches(self) -> list[dict]:
        return self.gan_patches

    def get_osi_log(self) -> list[dict]:
        return self.osi_log

    def get_d_scores(self) -> list[float]:
        return self.d_scores
