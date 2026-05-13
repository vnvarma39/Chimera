from __future__ import annotations

import torch
from torch import nn


class Discriminator(nn.Module):
    def __init__(self, feature_dim: int = 16):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(feature_dim, 256),
            nn.LeakyReLU(0.2),
            nn.Linear(256, 128),
            nn.LeakyReLU(0.2),
            nn.Linear(128, 1),
        )

    def forward(self, x):
        return self.net(x)
