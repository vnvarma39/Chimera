from __future__ import annotations

import time

from agents.base import Agent
from gan.synthetic_data import make_feature_vector
from osi import infer_osi_layer


class AttackerAgent(Agent):
    def __init__(self, orchestrator):
        super().__init__("AttackerAgent", orchestrator)

    def run(self):
        while self.running:
            vec = make_feature_vector(16)
            event = {
                "src_ip": "10.0.0.99",
                "dst_ip": "10.0.0.1",
                "src_port": 52000,
                "dst_port": 22,
                "command_hint": "recon",
                "packet_size": int(abs(vec[1]) * 1200) % 1500,
                "synthetic_attack": True,
            }
            event["osi_layer"] = infer_osi_layer(event)
            self.orchestrator.receive_event(event, source=self.name)
            self.idle(1.2)
