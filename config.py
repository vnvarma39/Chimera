from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
LOG_DIR = ROOT / "logs"
MODEL_DIR = ROOT / "models"

for _d in (DATA_DIR, LOG_DIR, MODEL_DIR):
    _d.mkdir(parents=True, exist_ok=True)

LISTEN_HOST = os.getenv("CHIMERA_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("CHIMERA_PORT", "2222"))
RED_TEAM_EVERY = int(os.getenv("CHIMERA_RED_TEAM_EVERY", "10"))
EVOLVE_EVERY = int(os.getenv("CHIMERA_EVOLVE_EVERY", "5"))

OPENAI_API_KEY = "YOUR OPENAI API KEY HERE"
OPENAI_BASE_URL = "https://openrouter.ai/api/v1"
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
OPENAI_TIMEOUT = int(os.getenv("OPENAI_TIMEOUT", "30"))

GAN_NOISE_DIM = int(os.getenv("CHIMERA_GAN_NOISE_DIM", "64"))
GAN_FEATURE_DIM = int(os.getenv("CHIMERA_GAN_FEATURE_DIM", "16"))
