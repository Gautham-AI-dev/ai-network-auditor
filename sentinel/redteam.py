#!/usr/bin/env python3
"""Red-team flood generator: deterministic alert storms.

Flood = test set replicated K times (exact duplicates) + fixed-seed shuffle.
Tests verdict consistency under volume: identical copies must yield identical
verdicts; precision must not collapse; runtime must stay bounded.
"""
import numpy as np

SEED = 99


def make_flood(Xte, factor=10, seed=SEED):
    rng = np.random.default_rng(seed)
    idx = np.tile(np.arange(len(Xte)), factor)
    rng.shuffle(idx)
    return Xte[idx], idx
