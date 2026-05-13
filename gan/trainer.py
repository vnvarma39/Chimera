from __future__ import annotations

"""
gan/trainer.py — Project Chimera (fixed)

The GAN now has two modes:

1. train_gan(real_data)  — standard offline training on a dataset.
   Called once at startup with the synthetic baseline dataset.

2. update_gan(artifacts, new_command, session) — online one-step update
   called from the SSH command loop for every real attacker command.
   This is what actually connects the GAN to the live honeypot session:
   the generator learns from the real attacker's commands in real time.

The discriminator score for a new command is also returned so the
DefenderAgent can use it as a detection signal without a separate model.
"""

from dataclasses import dataclass

import numpy as np
import torch
from torch import optim
from torch.utils.data import DataLoader, TensorDataset

from gan.discriminator import Discriminator
from gan.generator import Generator
from gan.synthetic_data import FEATURE_DIM, command_to_feature_vector


@dataclass
class GANArtifacts:
    generator: Generator
    discriminator: Discriminator
    g_losses: list[float]
    d_losses: list[float]
    noise_dim: int = 64


def train_gan(
    real_data: np.ndarray,
    noise_dim: int = 64,
    epochs: int = 20,
    batch_size: int = 32,
) -> GANArtifacts:
    """Full offline GAN training on a dataset of feature vectors."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    x = torch.tensor(real_data, dtype=torch.float32)
    dataset = TensorDataset(x)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=True)

    feat_dim = real_data.shape[1]
    G = Generator(noise_dim=noise_dim, feature_dim=feat_dim).to(device)
    D = Discriminator(feature_dim=feat_dim).to(device)
    opt_g = optim.Adam(G.parameters(), lr=2e-4, betas=(0.5, 0.999))
    opt_d = optim.Adam(D.parameters(), lr=2e-4, betas=(0.5, 0.999))
    criterion = torch.nn.BCEWithLogitsLoss()

    g_losses, d_losses = [], []
    for _ in range(epochs):
        g_loss_val = d_loss_val = torch.tensor(0.0)
        for (real_batch,) in loader:
            real_batch = real_batch.to(device)
            b = real_batch.size(0)
            ones = torch.ones((b, 1), device=device)
            zeros = torch.zeros((b, 1), device=device)

            # Train D
            z = torch.randn((b, noise_dim), device=device)
            fake = G(z).detach()
            d_loss_val = criterion(D(real_batch), ones) + criterion(D(fake), zeros)
            opt_d.zero_grad()
            d_loss_val.backward()
            opt_d.step()

            # Train G
            z = torch.randn((b, noise_dim), device=device)
            fake = G(z)
            g_loss_val = criterion(D(fake), ones)
            opt_g.zero_grad()
            g_loss_val.backward()
            opt_g.step()

        g_losses.append(float(g_loss_val.detach().cpu()))
        d_losses.append(float(d_loss_val.detach().cpu()))

    return GANArtifacts(
        generator=G, discriminator=D,
        g_losses=g_losses, d_losses=d_losses,
        noise_dim=noise_dim,
    )


def score_command(artifacts: GANArtifacts, command: str, cmd_index: int = 0, privilege_level: str = "user") -> float:
    """
    Run the discriminator on a real command's feature vector.
    Returns a score in [0, 1]: higher = more 'real-looking' (less anomalous).
    The defender agent uses the INVERSE (1 - score) as a suspicion signal.
    """
    vec = command_to_feature_vector(command, cmd_index=cmd_index, privilege_level=privilege_level)
    device = next(artifacts.discriminator.parameters()).device
    with torch.no_grad():
        t = torch.tensor(vec, dtype=torch.float32).unsqueeze(0).to(device)
        logit = artifacts.discriminator(t)
        return float(torch.sigmoid(logit).item())


def update_gan(
    artifacts: GANArtifacts,
    command: str,
    cmd_index: int = 0,
    privilege_level: str = "user",
) -> float:
    """
    Online one-step GAN update using a single real attacker command.

    - Converts the command to a feature vector (the 'real' sample for D).
    - Runs one discriminator step: D should say 1 for real, 0 for generated fake.
    - Runs one generator step: G tries to fool D.
    - Returns discriminator's confidence that the real command looks 'real'
      (used by DefenderAgent as an anomaly signal).

    This is what wires the GAN to the live session: every SSH command
    the attacker types triggers a gradient update in both G and D.
    """
    vec = command_to_feature_vector(command, cmd_index=cmd_index, privilege_level=privilege_level)
    device = next(artifacts.generator.parameters()).device

    real_t = torch.tensor(vec, dtype=torch.float32).unsqueeze(0).to(device)
    ones = torch.ones((1, 1), device=device)
    zeros = torch.zeros((1, 1), device=device)

    criterion = torch.nn.BCEWithLogitsLoss()

    # Optimisers for online updates (small lr to avoid catastrophic forgetting)
    opt_d = optim.Adam(artifacts.discriminator.parameters(), lr=5e-5, betas=(0.5, 0.999))
    opt_g = optim.Adam(artifacts.generator.parameters(), lr=5e-5, betas=(0.5, 0.999))

    # D step
    z = torch.randn((1, artifacts.noise_dim), device=device)
    fake = artifacts.generator(z).detach()
    d_loss = criterion(artifacts.discriminator(real_t), ones) + criterion(artifacts.discriminator(fake), zeros)
    opt_d.zero_grad()
    d_loss.backward()
    opt_d.step()

    # G step
    z = torch.randn((1, artifacts.noise_dim), device=device)
    fake = artifacts.generator(z)
    g_loss = criterion(artifacts.discriminator(fake), ones)
    opt_g.zero_grad()
    g_loss.backward()
    opt_g.step()

    # Return discriminator's view of the real command
    with torch.no_grad():
        score = float(torch.sigmoid(artifacts.discriminator(real_t)).item())

    return score
