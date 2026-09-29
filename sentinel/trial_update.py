#!/usr/bin/env python3
"""trial_update.py - AV-industry rollback discipline for detector thresholds.

Usage: python trial_update.py --set d1_quantiles=[0.4,0.4,0.4]
Flow: snapshot baseline metrics -> backup config -> apply candidate ->
rerun detectors -> compare total FP (+ recall guard) ->
  better-or-equal: STAGED (human promotes by committing).
  worse: auto-REVERT config + rerun detectors (artifacts always match config).
Exit 0 staged-or-equal, 1 reverted, 2 infra error.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
CFG = os.path.join(BASE, "thresholds.json")
METRICS = os.path.join(BASE, "detectors-metrics.json")


def total_fp(m):
    return sum(v["fp"] for v in m["detectors"].values())


def recalls(m):
    return {k: v["recall"] for k, v in m["detectors"].items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", action="append", default=[],
                    help="key=jsonvalue, e.g. d2_quantile=0.99")
    a = ap.parse_args()
    try:
        with open(METRICS, encoding="utf-8") as f:
            base = json.load(f)
        with open(CFG, encoding="utf-8") as f:
            cfg = json.load(f)
    except (OSError, ValueError) as e:
        print("baseline unreadable:", e, file=sys.stderr)
        return 2
    bak = CFG + ".trialbak"
    shutil.copy(CFG, bak)
    try:
        for item in a.set:
            k, v = item.split("=", 1)
            cfg[k.strip()] = json.loads(v)
        with open(CFG, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        p = subprocess.run([sys.executable, "detectors.py"], cwd=BASE,
                           capture_output=True, text=True, timeout=1200)
        if p.returncode != 0:
            raise RuntimeError("detectors failed: "
                               + (p.stderr or "")[-300:])
        with open(METRICS, encoding="utf-8") as f:
            new = json.load(f)
        fp0, fp1 = total_fp(base), total_fp(new)
        r0, r1 = recalls(base), recalls(new)
        regressed = [k for k in r0 if r1.get(k, 1) < r0[k] - 0.005]
        if fp1 <= fp0 and not regressed:
            print("STAGED: total FP %d -> %d, recalls hold" % (fp0, fp1))
            os.remove(bak)
            return 0
        print("REVERTED: FP %d -> %d, regressed=%s; restoring"
              % (fp0, fp1, regressed))
    except Exception as e:
        print("trial error, reverting:", str(e)[:200], file=sys.stderr)
    shutil.copy(bak, CFG)
    subprocess.run([sys.executable, "detectors.py"], cwd=BASE,
                   capture_output=True, timeout=1200)
    os.remove(bak)
    print("restored baseline config + artifacts")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
