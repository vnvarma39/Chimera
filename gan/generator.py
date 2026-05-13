from __future__ import annotations

import torch
from torch import nn


class Generator(nn.Module):
    def __init__(self, noise_dim: int = 64, feature_dim: int = 16):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(noise_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 256),
            nn.ReLU(),
            nn.Linear(256, feature_dim),
            nn.Tanh(),
        )

    def forward(self, z):
        return self.net(z)
