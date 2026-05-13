"""Tests that the GAN produces real feature vectors and trains without error."""
import numpy as np
from gan.synthetic_data import build_dataset, command_to_feature_vector, FEATURE_DIM
from gan.trainer import train_gan, score_command, update_gan


def test_feature_vector_shape():
    vec = command_to_feature_vector("whoami", cmd_index=0, privilege_level="user")
    assert vec.shape == (FEATURE_DIM,)
    assert vec.dtype == np.float32
    assert all(0.0 <= v <= 1.0 for v in vec)


def test_build_dataset():
    real, labels = build_dataset(n=32)
    assert real.shape == (32, FEATURE_DIM)
    assert labels.shape == (32, 1)


def test_train_and_score():
    real, _ = build_dataset(n=64)
    arts = train_gan(real, epochs=2, batch_size=16)
    score = score_command(arts, "whoami", cmd_index=0)
    assert 0.0 <= score <= 1.0


def test_online_update():
    real, _ = build_dataset(n=64)
    arts = train_gan(real, epochs=2, batch_size=16)
    score = update_gan(arts, "cat /etc/passwd", cmd_index=3, privilege_level="user")
    assert 0.0 <= score <= 1.0
