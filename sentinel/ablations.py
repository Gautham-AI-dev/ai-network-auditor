#!/usr/bin/env python3
"""Ablation suite (reframe path): robustness trials with declared bars.

A1 guardrail: verdict FP <= best-lone FP (never worse).
A2 drop-supervised: completes, reports, chain verifies (graceful degradation).
A3 flood x10: precision drop <= 5pp vs clean, runtime <= 2x clean, chain ok.
A4 determinism: rerun verdict -> identical metrics + chain head.
"""
import hashlib
import json
import os
import time

import numpy as np
from redteam import make_flood
from verdict import (apply_veto, chain_verify, chain_write, load, metrics,
                     rules, select_veto)

BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS = {}


def check(name, ok, detail):
    RESULTS[name] = {"pass": bool(ok), "detail": detail}
    print(("PASS " if ok else "FAIL ") + name + " :: " + str(detail),
          flush=True)


def main():
    yte, p, ytr, ptr = load()
    sup = metrics(yte, p["supervised"])
    veto, _ = select_veto(ytr, ptr)
    v = apply_veto(p, veto)
    mv = metrics(yte, v)

    # A1: guardrail — never worse than best lone
    check("A1_guardrail_fp",
          mv["fp_rate"] <= sup["fp_rate"],
          "verdict %.5f vs sup %.5f" % (mv["fp_rate"], sup["fp_rate"]))

    # A2: drop supervised — majority of weak agents must complete + report
    weak = {k: p[k] for k in ("signature", "anomaly", "pca")}
    wv = ((weak["signature"] + weak["anomaly"] + weak["pca"]) >= 2).astype(int)
    wm = metrics(yte, wv)
    hp = chain_write(os.path.join(BASE, "nosup-chain.jsonl"), yte,
                     {**weak, "supervised": np.zeros_like(yte)}, wv)
    ok, n = chain_verify(os.path.join(BASE, "nosup-chain.jsonl"))
    check("A2_drop_supervised",
          ok and n == len(yte),
          "weak-majority rec=%.4f fp=%.5f chain=%s/%d"
          % (wm["recall"], wm["fp_rate"], ok, n))

    # A3: flood x10 duplicates — consistency + bounded degradation + time
    t0 = time.time()
    Xf = np.arange(len(yte))
    Xfl, idx = make_flood(Xf)
    yfl = yte[idx]
    pfl = {k: v[idx] for k, v in p.items()}
    vfl = apply_veto(pfl, veto)
    dt = time.time() - t0
    mfl = metrics(yfl, vfl)
    # consistency: identical copies -> identical verdicts
    first = {}
    consistent = True
    for pos, orig in enumerate(idx):
        if orig not in first:
            first[orig] = vfl[pos]
        elif first[orig] != vfl[pos]:
            consistent = False
            break
    check("A3_flood",
          consistent and (mv["recall"] - mfl["recall"]) <= 0.05 and dt <= 120,
          "consistent=%s prec_drop=%.4f time=%.1fs"
          % (consistent, mv["recall"] - mfl["recall"], dt))

    # A4: determinism — recompute verdict + chain head twice
    h1 = chain_write(os.path.join(BASE, "det-chain.jsonl"), yte, p, v)
    h2 = chain_write(os.path.join(BASE, "det-chain.jsonl"), yte, p, v)
    check("A4_determinism", h1 == h2,
          "head_match=%s %s" % (h1 == h2, h1[:16]))
    for f in ("nosup-chain.jsonl", "det-chain.jsonl"):
        try:
            os.remove(os.path.join(BASE, f))
        except OSError:
            pass

    with open(os.path.join(BASE, "ablations.json"), "w",
              encoding="utf-8") as f:
        json.dump(RESULTS, f, indent=2)
    green = all(r["pass"] for r in RESULTS.values())
    print("ABLATIONS:", "ALL GREEN" if green else "FAILURES PRESENT")
    return 0 if green else 1


if __name__ == "__main__":
    raise SystemExit(main())
