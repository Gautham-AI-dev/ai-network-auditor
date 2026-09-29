#!/usr/bin/env python3
"""Score-fusion verdict (hybrid path part 1): stacking on detector SCORES.

Method (textbook stacking, openly labeled as such — novelty downgrade
recorded): StandardScaler + LogisticRegression fit on TRAIN scores only.
Threshold locked on TRAIN: highest threshold with train recall >= train
supervised recall (i.e., cheapest FP price that keeps all train catches).
Single test evaluation. Chain + PASS/FAIL vs A1 bar (FP <= 0.88%,
recall >= test supervised recall).
"""
import hashlib
import json
import os

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

BASE = os.path.dirname(os.path.abspath(__file__))
GENESIS = "0" * 64
FEATS = ("signature", "anomaly", "pca", "supervised")


def load_scores(path, ykey):
    z = np.load(os.path.join(BASE, path))
    X = np.column_stack([z[k] for k in FEATS])
    return z[ykey], X


def metrics(y, pred):
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    tp = int(((pred == 1) & (y == 1)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    return {"recall": round(tp / max(tp + fn, 1), 4),
            "fp": fp, "fp_rate": round(fp / max(tn + fp, 1), 5)}


def main():
    ytr, Xtr = load_scores("detectors-train-scores.npz", "ytr")
    yte, Xte = load_scores("detectors-scores.npz", "yte")
    sc = StandardScaler().fit(Xtr)
    clf = LogisticRegression(max_iter=2000, random_state=11)
    clf.fit(sc.transform(Xtr), ytr)
    print("stack weights:", [round(float(w), 4) for w in clf.coef_[0]],
          "b=", round(float(clf.intercept_[0]), 4))

    # Threshold locked on TRAIN: max recall-preserving FP cut.
    ptr = clf.predict_proba(sc.transform(Xtr))[:, 1]
    sup_tr = (Xtr[:, 3] >= 0.5).astype(int)
    sup_tr_rec = float(metrics(ytr, sup_tr)["recall"])
    best_t, best_fp = 0.5, None
    for t in [i / 100 for i in range(1, 100)]:
        pt = (ptr >= t).astype(int)
        r = metrics(ytr, pt)
        if r["recall"] >= sup_tr_rec and (best_fp is None
                                          or r["fp"] < best_fp):
            best_t, best_fp = t, r["fp"]
    print("locked threshold:", best_t, "train sup recall:", round(sup_tr_rec, 4))

    pte = clf.predict_proba(sc.transform(Xte))[:, 1]
    pred = (pte >= best_t).astype(int)
    sup_te = (Xte[:, 3] >= 0.5).astype(int)
    m = metrics(yte, pred)
    s = metrics(yte, sup_te)
    print("test stack:", m, "| test sup:", s)

    h = GENESIS
    chain = os.path.join(BASE, "score-chain.jsonl")
    with open(chain, "w", encoding="utf-8") as f:
        for i in range(len(yte)):
            body = json.dumps({"i": i, "p": round(float(pte[i]), 6),
                               "v": int(pred[i]),
                               "t": best_t}, sort_keys=True)
            h = hashlib.sha256((h + body).encode()).hexdigest()
            f.write(json.dumps({"h": h, "body": body}) + "\n")
    ok = m["recall"] >= s["recall"] and m["fp_rate"] <= 0.0088
    out = {"method": "stacking (textbook, train-fit)", "threshold": best_t,
           "metrics": m, "best_lone": s, "pass": bool(ok),
           "chain_head": h}
    with open(os.path.join(BASE, "score-verdict.json"), "w",
              encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("PASS" if ok else "FAIL", out)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
