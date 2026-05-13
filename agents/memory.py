from __future__ import annotations


class MemoryAgent:
    def __init__(self):
        self.history = []

    def store(self, command: str, metadata: dict):
        self.history.append({"command": command, "metadata": metadata})

    def retrieve(self):
        return list(self.history)
