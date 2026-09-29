#!/usr/bin/env python3
"""Build the locked Sentinel OS subset (see subset-lock section in code).

Friday attack rows (all) + Monday benign sample (seed 7). Engelen-style
cleaning: strip column whitespace, drop NaN/inf rows, drop zero-variance
cols (recorded, not silent). Outputs parquet + sha256 + manifest JSON.
"""
import hashlib
import json
import os

import pandas as pd

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
SEED = 7
N_BENIGN = 300000


def load_day(fn, keep_labels):
    frames = []
    for ch in pd.read_csv(os.path.join(DATA, fn), chunksize=200000,
                          low_memory=False):
        ch.columns = [c.strip() for c in ch.columns]
        ch = ch[ch["Label"].isin(keep_labels)]
        frames.append(ch)
    return pd.concat(frames, ignore_index=True)


def main():
    ddos = load_day("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
                    ["DDoS"])
    ps = load_day("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
                  ["PortScan"])
    attacks = pd.concat([ddos, ps], ignore_index=True)
    ben = load_day("Monday-WorkingHours.pcap_ISCX.csv", ["BENIGN"])
    ben = ben.sample(n=N_BENIGN, random_state=SEED).reset_index(drop=True)
    df = pd.concat([attacks, ben], ignore_index=True)
    df = df.sample(frac=1.0, random_state=SEED).reset_index(drop=True)

    df = df.replace([float("inf"), float("-inf")], pd.NA).dropna()
    nzv = [c for c in df.columns if c != "Label" and df[c].nunique() <= 1]
    df = df.drop(columns=nzv)

    out = os.path.join(BASE, "sentinel-subset.parquet")
    df.to_parquet(out, index=False)
    sha = hashlib.sha256(open(out, "rb").read()).hexdigest()
    manifest = {
        "seed": SEED,
        "composition": {
            "ddos": int((df["Label"] == "DDoS").sum()),
            "portscan": int((df["Label"] == "PortScan").sum()),
            "benign": int((df["Label"] == "BENIGN").sum()),
        },
        "rows": len(df),
        "features": len(df.columns) - 1,
        "dropped_zero_variance": nzv,
        "sha256": sha,
    }
    with open(os.path.join(BASE, "sentinel-subset.json"), "w",
              encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
