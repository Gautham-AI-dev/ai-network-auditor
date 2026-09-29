#!/usr/bin/env python3
"""Sentinel OS one-command reproduction (public artifact).

Steps: data -> subset -> detectors -> verdict -> score-fusion -> ablations,
then compares every metric against results/ reference values.
Exit 0 = all match (PASS), 1 = any mismatch (FAIL), 2 = infra problem.

Prereqs: Python 3.10, pip install -r requirements.txt, Kaggle API
credentials (~/.kaggle/kaggle.json) for the one-time dataset download
(CICIDS2017 mirror, 230MB). Data Sembawang: sentinel/data/ (git-ignored).
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SENT = os.path.join(ROOT, "sentinel")
REF = os.path.join(ROOT, "results")


def run(cmd, step):
    print("###", step, flush=True)
    p = subprocess.run(cmd, cwd=ROOT)
    if p.returncode not in (0, 1):
        print("INFRA FAIL at", step)
        sys.exit(2)


def main():
    data_files = ["Monday-WorkingHours.pcap_ISCX.csv",
                  "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                  "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"]
    datadir = os.path.join(SENT, "data")
    if not all(os.path.exists(os.path.join(datadir, f))
               for f in data_files):
        print("DATA MISSING. One-time download:")
        print("  kaggle datasets download -d "
              "chethuhn/network-intrusion-dataset "
              "-p sentinel/data --unzip")
        print("(needs ~/.kaggle/kaggle.json)")
        return 2
    py = sys.executable
    run([py, "sentinel/build_subset.py"], "subset")
    run([py, "sentinel/detectors.py"], "detectors")
    run([py, "sentinel/verdict.py"], "verdict")
    run([py, "sentinel/score_verdict.py"], "score-fusion")
    run([py, "sentinel/ablations.py"], "ablations")

    fails = []
    for fn in ("detectors-metrics.json", "verdict.json",
               "score-verdict.json", "ablations.json",
               "sentinel-subset.json"):
        with open(os.path.join(SENT, fn), encoding="utf-8") as f:
            got = json.load(f)
        with open(os.path.join(REF, fn), encoding="utf-8") as f:
            want = json.load(f)
        # compare metric-bearing fields (hashes/heads excluded: chain
        # depends on identical input order, which the same script gives)
        g = {k: v for k, v in got.items()
             if k not in ("chain_head",)}
        w = {k: v for k, v in want.items()
             if k not in ("chain_head",)}
        if "detectors" in g:
            g = g["detectors"]
            w = w["detectors"]
        if fn == "ablations.json":
            # wall-times vary: compare verdicts only
            g = {k: v["pass"] for k, v in g.items()}
            w = {k: v["pass"] for k, v in w.items()}
        ok = (g == w)
        print(("MATCH " if ok else "DIFF  ") + fn)
        if not ok:
            fails.append(fn)
    # chain determinism: recompute head twice, compare + clean up
    sys.path.insert(0, SENT)
    import verdict as V
    yte, p, ytr, ptr = V.load()
    veto, _ = V.select_veto(ytr, ptr)
    v = V.apply_veto(p, veto)
    ha = V.chain_write(os.path.join(SENT, "chain-a.jsonl"), yte, p, v)
    hb = V.chain_write(os.path.join(SENT, "chain-b.jsonl"), yte, p, v)
    for f in ("chain-a.jsonl", "chain-b.jsonl"):
        try:
            os.remove(os.path.join(SENT, f))
        except OSError:
            pass
    print("chain determinism:", ha == hb)
    print("reproduction summary done")
    if fails or ha != hb:
        print("FAIL", fails if fails else ["chain"])
        return 1
    print("ALL MATCH — PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
