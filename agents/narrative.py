from __future__ import annotations

import time

from agents.base import Agent
from narrative_engine import generate_narrative
from llm_client import llm_client


class NarrativeAgent(Agent):
    def __init__(self, orchestrator):
        super().__init__("NarrativeAgent", orchestrator)
        self.narrative = None

    def run(self):
        while self.running:
            if self.narrative is None:
                self.narrative = generate_narrative(self.orchestrator.session_id)
                self.orchestrator.set_narrative(self.narrative)
            self.idle(1.0)
