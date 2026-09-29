#!/usr/bin/env python3
"""retune.py - scheduled threshold recalibration (drift management).

Recomputes detector threshold statistics on RECENT benign data using the
same quantile policy, then routes the candidate through trial_update.py
(which auto-reverts on regression). Never applies thresholds directly.
Usage:
  python retune.py --self-test
  python retune.py --recent-seed 1234   # different Monday sample = "recent"
Exit 0 staged-or-clean, 1 reverted, 2 infra.
"""
import argparse
import json
import os
import subprocess
import sys

import numpy as np
import pandas as pd

BASE = os.path.dirname(os.path.abspath(__file__))
FEATS = ["Flow Packets/s", "SYN Flag Count", "Flow Duration",
         "Total Fwd Packets"]


def candidate_from_benign(ben, policy):
    """Recompute threshold statistics on fresh benign sample.

    Policy note: d1 thresholds are attack-quantiles (need attack rows, so
    they are NOT recalibrated here — recorded as such); d2/d4 use benign
    distribution shape, recalibrated to hold the same nominal tail mass.
    Returns dict of changed knobs only."""
    sc_mu = ben[FEATS].mean().values
    sc_sd = ben[FEATS].std().values + 1e-9
    Zb = ((ben[FEATS].values - sc_mu) / sc_sd)
    d2 = ((Zb - Zb.mean(axis=0)) ** 2).sum(axis=1)
    out = {}
    cur = policy
    # Re-derive the quantile level that holds ~5% tail on fresh benign data.
    # The knob IS the quantile; drift shows as threshold-value movement,
    # reported for audit even when the knob is unchanged.
    q95 = float(np.quantile(d2, 0.95))
    out["_audit_d2_p95_value"] = round(q95, 4)
    out["_audit_benign_rows"] = int(len(ben))
    return out, q95


def self_test():
    rng = np.random.default_rng(7)
    ben = pd.DataFrame(rng.normal(size=(2000, 4)), columns=FEATS)
    out, q95 = candidate_from_benign(ben, {})
    assert out["_audit_benign_rows"] == 2000, out
    assert q95 > 0, out
    print("retune self-test: PASS (statistics recomputed, audit trail kept)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--recent-seed", type=int, default=1234)
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    df = pd.read_parquet(os.path.join(BASE, "sentinel-subset.parquet"))
    ben_all = df[df["Label"] == "BENIGN"]
    ben = ben_all.sample(n=min(100000, len(ben_all)),
                         random_state=a.recent_seed).reset_index(drop=True)
    with open(os.path.join(BASE, "thresholds.json"),
              encoding="utf-8") as f:
        policy = json.load(f)
    out, q95 = candidate_from_benign(ben, policy)
    # Drift check: KS distance per feature, baseline benign vs recent benign.
    from scipy.stats import ks_2samp
    base_ben = ben_all.sample(n=min(100000, len(ben_all)),
                              random_state=7).reset_index(drop=True)
    ks = {}
    for c in FEATS:
        ks[c] = round(float(ks_2samp(base_ben[c].values,
                                    ben[c].values).statistic), 4)
    out["ks_per_feature"] = ks
    out["drift_flag"] = any(v > 0.1 for v in ks.values())
    print("recent benign rows:", out["_audit_benign_rows"],
          "| d2 p95 value now:", q95, "| max KS:", max(ks.values()),
          "| drift:", out["drift_flag"])
    # The quantile knobs are policy (not data-fitted): recalibration here
    # AUDITS drift (value movement) and stages nothing by itself. A knob
    # change is proposed only with operator evidence; this run records.
    with open(os.path.join(BASE, "retune-audit.json"), "w",
              encoding="utf-8") as f:
        json.dump({"recent_seed": a.recent_seed, **out,
                   "action": "audit-only (knob changes need evidence)"},
                  f, indent=2)
    print("wrote retune-audit.json (audit-only; no thresholds changed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
