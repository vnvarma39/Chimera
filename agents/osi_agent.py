from __future__ import annotations

from osi import osi_summary
from llm_client import llm_client


class OSIAgent:
    def map_command(self, command: str) -> dict:
        """
        Uses GenAI to classify a command into a synthetic network event
        at the appropriate OSI layer.
        """
        system = (
            "You are a network traffic simulator. Given a Linux command, "
            "generate a synthetic network event that would occur if this command "
            "were executed. Return JSON with fields like src_ip, dst_ip, src_port, "
            "dst_port, http_method, url, ssh_banner, etc. "
            "Be creative but realistic."
        )
        user = f"Command: {command}"
        
        result = llm_client.complete(system, user, json_mode=True, max_tokens=150)
        event = result.parsed if result.parsed else {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1"}
        
        # Ensure basic fields exist for osi_summary
        if "src_ip" not in event: event["src_ip"] = "10.0.0.5"
        if "dst_ip" not in event: event["dst_ip"] = "10.0.0.1"
        
        summary = osi_summary(event)
        summary["event"] = event
        return summary
