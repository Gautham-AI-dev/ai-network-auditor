#!/usr/bin/env python3
"""Sentinel detectors: 3 heterogeneous agents, standalone-measured.

Split: 70/30 stratified, seed 11 (fixed for all verdict comparisons).
D1 signature/rules, D2 anomaly (IsolationForest on benign-only train),
D3 supervised (logistic regression). Outputs per-detector test predictions
+ metrics JSON. No verdict logic here (verdict.py owns that).
"""
import json
import os

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

BASE = os.path.dirname(os.path.abspath(__file__))
SEED = 11


def thresholds():
    """Tunable knobs live in thresholds.json (versioned, rollback-able).
    No silent defaults: a missing file is a hard error."""
    import json as _json
    with open(os.path.join(BASE, "thresholds.json"), encoding="utf-8") as f:
        return _json.load(f)

FEATS = ["Flow Packets/s", "SYN Flag Count", "Flow Duration",
         "Total Fwd Packets"]


def load():
    df = pd.read_parquet(os.path.join(BASE, "sentinel-subset.parquet"))
    y = (df["Label"] != "BENIGN").astype(int).values
    X = df[FEATS].values.astype(np.float64)
    Xfull = df.drop(columns=["Label"]).values.astype(np.float64)
    return X, y, Xfull, FEATS


def d1_signature(Xtr, ytr, Xte):
    """Hand rules on real features, thresholds tuned on train for precision:
    scan-like = SYN-heavy short flows; flood-like = extreme packet rate."""
    rate, syn, dur = Xtr[:, 0], Xtr[:, 1], Xtr[:, 2]
    q = thresholds()["d1_quantiles"]
    t_rate = float(np.quantile(rate[ytr == 1], q[0]))
    t_syn = float(np.quantile(syn[ytr == 1], q[1]))
    t_dur = float(np.quantile(dur[ytr == 1], q[2]))
    scan = (Xte[:, 1] >= max(t_syn, 1)) & (Xte[:, 2] <= t_dur)
    flood = Xte[:, 0] >= t_rate
    pred = (scan | flood).astype(int)
    return pred, {"rule": "syn>=p50 & dur<=p50 | rate>=p50 (attack-train)",
                  "thresholds": [t_rate, t_syn, t_dur]}, pred.astype(float)


def d2_anomaly(Xtr, ytr, Xte, Xftr=None, Xfte=None):
    use_tr = Xftr if Xftr is not None else Xtr
    use_te = Xfte if Xfte is not None else Xte
    sc = StandardScaler().fit(use_tr[ytr == 0])
    Ztr = sc.transform(use_tr[ytr == 0])
    mu = Ztr.mean(axis=0)
    d_tr = ((Ztr - mu) ** 2).sum(axis=1)
    thr = float(np.quantile(d_tr, thresholds()["d2_quantile"]))
    d_te = ((sc.transform(use_te) - mu) ** 2).sum(axis=1)
    pred = (d_te > thr).astype(int)
    return pred, {"method": "full-feature benign-centroid L2, 95th-pct"}, d_te


def d4_pca(Xtr, ytr, Xte, Xftr=None, Xfte=None):
    """PCA reconstruction error, fit on benign-only (full features)."""
    use_tr = Xftr if Xftr is not None else Xtr
    use_te = Xfte if Xfte is not None else Xte
    sc = StandardScaler().fit(use_tr[ytr == 0])
    Ztr = sc.transform(use_tr[ytr == 0])
    cfg = thresholds()
    pca = PCA(n_components=cfg["d4_n_components"], random_state=SEED)
    Zp = pca.fit_transform(Ztr)
    err_tr = ((Ztr - pca.inverse_transform(Zp)) ** 2).sum(axis=1)
    thr = float(np.quantile(err_tr, cfg["d4_quantile"]))
    Zte = sc.transform(use_te)
    err_te = ((Zte - pca.inverse_transform(pca.transform(Zte))) ** 2).sum(
        axis=1)
    pred = (err_te > thr).astype(int)
    return pred, {"method": "PCA20 benign-only recon-error, 95th-pct"}, err_te


def d3_supervised(Xtr, ytr, Xte):
    sc = StandardScaler().fit(Xtr)
    clf = LogisticRegression(max_iter=2000, random_state=SEED, n_jobs=-1)
    clf.fit(sc.transform(Xtr), ytr)
    proba = clf.predict_proba(sc.transform(Xte))[:, 1]
    return (proba >= 0.5).astype(int), {"model": "logreg"}, proba


def main():
    X, y, Xfull, feats = load()
    print("detector features:", feats)
    idx = np.arange(len(y))
    tr_idx, te_idx = train_test_split(idx, test_size=0.30, random_state=SEED,
                                      stratify=y)
    Xtr, Xte, ytr, yte = X[tr_idx], X[te_idx], y[tr_idx], y[te_idx]
    Xftr, Xfte = Xfull[tr_idx], Xfull[te_idx]
    out = {"seed": SEED, "n_train": len(ytr), "n_test": len(yte),
           "features": feats, "detectors": {}}
    preds = {}

    def record(name, pred, info):
        preds[name] = pred
        fp = int(((pred == 1) & (yte == 0)).sum())
        tn = int(((pred == 0) & (yte == 0)).sum())
        out["detectors"][name] = {
            "precision": round(float(precision_score(yte, pred,
                                                    zero_division=0)), 4),
            "recall": round(float(recall_score(yte, pred)), 4),
            "fp": fp,
            "fp_rate": round(fp / max(tn + fp, 1), 5),
            "info": info,
        }
        print(f"{name:11s} prec={out['detectors'][name]['precision']} "
              f"rec={out['detectors'][name]['recall']} "
              f"fp_rate={out['detectors'][name]['fp_rate']}", flush=True)

    pred, info, sc = d2_anomaly(Xtr, ytr, Xte, Xftr, Xfte)
    record("anomaly", pred, info)
    scores = {"anomaly": sc}
    pred, info, sc = d4_pca(Xtr, ytr, Xte, Xftr, Xfte)
    record("pca", pred, info)
    scores["pca"] = sc
    for name, fn, Atr, Ate in (("signature", d1_signature, Xtr, Xte),
                               ("supervised", d3_supervised, Xftr, Xfte)):
        pred, info, sc = fn(Atr, ytr, Ate)
        record(name, pred, info)
        scores[name] = sc
    np.savez_compressed(os.path.join(BASE, "detectors-preds.npz"),
                        yte=yte, **preds)
    np.savez_compressed(os.path.join(BASE, "detectors-scores.npz"),
                        yte=yte, **scores)
    tr_preds, tr_scores = {}, {}
    for name, fn, Atr, Ate in (("signature", d1_signature, Xtr, Xte),
                               ("supervised", d3_supervised, Xftr, Xfte)):
        tr_preds[name], _, tr_scores[name] = fn(Atr, ytr, Atr)
    tr_preds["anomaly"], _, tr_scores["anomaly"] = d2_anomaly(
        Xtr, ytr, Xtr, Xftr, Xftr)
    tr_preds["pca"], _, tr_scores["pca"] = d4_pca(Xtr, ytr, Xtr, Xftr, Xftr)
    np.savez_compressed(os.path.join(BASE, "detectors-train-preds.npz"),
                        ytr=ytr, **tr_preds)
    np.savez_compressed(os.path.join(BASE, "detectors-train-scores.npz"),
                        ytr=ytr, **tr_scores)
    with open(os.path.join(BASE, "detectors-metrics.json"), "w",
              encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print("saved detectors-metrics.json")


if __name__ == "__main__":
    main()
