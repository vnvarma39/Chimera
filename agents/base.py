from __future__ import annotations

import threading
import time


class Agent(threading.Thread):
    def __init__(self, name: str, orchestrator):
        super().__init__(name=name, daemon=True)
        self.orchestrator = orchestrator
        self.running = True

    def stop(self):
        self.running = False

    def idle(self, seconds: float = 0.2):
        time.sleep(seconds)
