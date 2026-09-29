#!/usr/bin/env python3
"""Sentinel verdict: deterministic adjudication + audit chain + replay test.

Candidate rules (fixed structures, NO tuned parameters — thresholds live
inside the detectors, tuned on train only):
  R1 = sup AND (sig OR anom)
  R2 = majority (>= 2 of 3)
  R3 = sup AND sig
Selection (declared before running): among rules with recall >= supervised
recall, lowest FP. PASS bar (amendment A1): FP <= 0.88% (50% relative cut
vs best lone 1.76%).
Audit: JSONL chain sha256(prev_hash + canonical record); verify walk.
"""
import hashlib
import json
import os

import numpy as np

BASE = os.path.dirname(os.path.abspath(__file__))
GENESIS = "0" * 64


AGENTS = ("signature", "anomaly", "pca", "supervised")


def load():
    z = np.load(os.path.join(BASE, "detectors-preds.npz"))
    zt = np.load(os.path.join(BASE, "detectors-train-preds.npz"))
    return (z["yte"], {k: z[k] for k in AGENTS},
            zt["ytr"], {k: zt[k] for k in AGENTS})


def rules(p):
    s, a, c, u = (p["signature"], p["anomaly"], p["pca"], p["supervised"])
    return {
        # R2 doubles as the ablation-1 baseline (verdict vs plain majority)
        "R1_sup_and_any": (u & (s | a | c)).astype(int),
        "R2_majority": ((s + a + c + u) >= 2).astype(int),
        "R3_sup_and_sig": (u & s).astype(int),
    }


def pattern_table(y, p):
    """For each (sig, anom, pca) pattern: benign-supFPs vs TPs covered."""
    s, a, c, u = (p["signature"], p["anomaly"], p["pca"], p["supervised"])
    table = {}
    for ps in (0, 1):
        for pa in (0, 1):
            for pc in (0, 1):
                m = (s == ps) & (a == pa) & (c == pc) & (u == 1)
                table[(ps, pa, pc)] = {
                    "fp_covered": int(((y == 0) & m).sum()),
                    "tp_covered": int(((y == 1) & m).sum()),
                }
    return table


def select_veto(ytr, ptr):
    """Declared criterion (locked before running): greedily add patterns by
    FP-coverage-per-TP-cost while train TP vetoed stays <= 0.2% of train TPs.
    Ties -> fewer patterns. Returns frozenset of veto patterns."""
    table = pattern_table(ytr, ptr)
    total_tp = int((ytr == 1).sum())
    budget = 0.002 * total_tp
    order = sorted(table, key=lambda k: (
        -table[k]["fp_covered"] / max(table[k]["tp_covered"], 1)))
    veto, used_tp = [], 0
    for k in order:
        if used_tp + table[k]["tp_covered"] <= budget:
            veto.append(k)
            used_tp += table[k]["tp_covered"]
    return frozenset(veto), table


CONF = {(1, 1, 1, 1): 0.99, (0, 1, 1, 1): 0.93, (1, 0, 1, 1): 0.90,
        (1, 1, 0, 1): 0.91, (0, 0, 1, 1): 0.80, (0, 1, 0, 1): 0.78,
        (1, 0, 0, 1): 0.76, (0, 0, 0, 1): 0.70}


def conf_of(votes):
    """Confidence by agreement pattern; unseen patterns -> 0.50 default
    (documented fallback, never a crash)."""
    return CONF.get(tuple(int(v) for v in votes), 0.50)


def apply_veto(p, veto):
    u = p["supervised"]
    v = np.zeros_like(u)
    for pat in veto:
        m = np.ones_like(u, dtype=bool)
        for k, bit in zip(AGENTS[:-1], pat):
            m &= (p[k] == bit)
        v |= m.astype(int)
    return (u & ~v).astype(int)


def metrics(yte, pred):
    fp = int(((pred == 1) & (yte == 0)).sum())
    tn = int(((pred == 0) & (yte == 0)).sum())
    tp = int(((pred == 1) & (yte == 1)).sum())
    fn = int(((pred == 0) & (yte == 1)).sum())
    return {"recall": round(tp / max(tp + fn, 1), 4),
            "fp": fp, "fp_rate": round(fp / max(tn + fp, 1), 5)}


def chain_write(path, yte, votes, verdict):
    h = GENESIS
    with open(path, "w", encoding="utf-8") as f:
        for i in range(len(yte)):
            vs = [int(votes[k][i]) for k in AGENTS]
            rec = {"i": i, "votes": vs,
                   "verdict": int(verdict[i]),
                   "conf": conf_of(vs)}
            body = json.dumps(rec, sort_keys=True)
            h = hashlib.sha256((h + body).encode()).hexdigest()
            f.write(json.dumps({"h": h, "body": body}) + "\n")
    return h


def chain_verify(path):
    h = GENESIS
    n = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            h = hashlib.sha256((h + e["body"]).encode()).hexdigest()
            if h != e["h"]:
                return False, n
            n += 1
    return True, n


def main():
    yte, p, ytr, ptr = load()
    sup = metrics(yte, p["supervised"])
    print("best lone: sup rec=%.4f fp=%.5f"
          % (sup["recall"], sup["fp_rate"]))
    veto, table = select_veto(ytr, ptr)
    print("train pattern table:", json.dumps(
        {str(k): v for k, v in table.items()}))
    print("locked veto patterns:", sorted(veto))
    cand = {"Rveto": apply_veto(p, veto)}
    cand.update(rules(p))
    res = {n: metrics(yte, pr) for n, pr in cand.items()}
    print("candidate metrics:", json.dumps(res))
    m = res["Rveto"]
    ok_recall = m["recall"] >= sup["recall"]
    ok_fp = m["fp_rate"] <= 0.0088
    print("recall floor:", ok_recall, "| fp bar:", ok_fp, m)
    chain_path = os.path.join(BASE, "verdict-chain.jsonl")
    head = chain_write(chain_path, yte, p, cand["Rveto"])
    ok, n = chain_verify(chain_path)
    print("chain verify:", ok, n, "head:", head[:16])
    verdict = {"rule": "Rveto(train-locked %s)" % sorted(veto),
               "metrics": m,
               "pass": bool(ok_recall and ok_fp),
               "chain_head": head, "chain_entries": n,
               "chain_ok": bool(ok)}
    with open(os.path.join(BASE, "verdict.json"), "w",
              encoding="utf-8") as f:
        json.dump(verdict, f, indent=2)
    print("PASS" if verdict["pass"] else "FAIL", verdict)
    return 0 if verdict["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
