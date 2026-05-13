from __future__ import annotations

import random
import time

from agents.base import Agent
from gan.synthetic_data import make_feature_vector
from osi import infer_osi_layer


class TrafficAgent(Agent):
    def __init__(self, orchestrator):
        super().__init__("TrafficAgent", orchestrator)

    def run(self):
        from llm_client import llm_client
        while self.running:
            narrative = self.orchestrator.narrative
            if not narrative:
                self.idle(1.0)
                continue
                
            system = (
                "You are a network traffic generator for a specific company. "
                "Generate a single synthetic network event (JSON) that fits the company's "
                "profile and services. Include src_ip, dst_ip, src_port, dst_port, "
                "and a 'description' of what this traffic represents (e.g., 'Employee accessing internal HR portal')."
            )
            user = f"Company Profile: {narrative.get('company_name')}, Services: {narrative.get('services')}"
            
            result = llm_client.complete(system, user, json_mode=True, max_tokens=150)
            event = result.parsed if result.parsed else {
                "src_ip": f"10.0.0.{random.randint(2, 254)}",
                "dst_ip": f"10.0.0.{random.randint(2, 254)}",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443]),
            }
            
            event["synthetic"] = True
            event["osi_layer"] = infer_osi_layer(event)
            self.orchestrator.receive_event(event, source=self.name)
            self.idle(random.uniform(2.0, 5.0))
