#!/usr/bin/env python3
"""reputation.py - detector track-record ledger (shared-learning seed).

Append-only JSONL: every metrics run appends {ts, detector, precision,
recall, fp_rate, source}. Queries are pure functions over the log
(deterministic, replayable). No auto-actions: ledger informs operators
and future verdict weights; it changes nothing by itself.
Usage:
  python reputation.py --record detectors-metrics.json [--self-test]
  python reputation.py --query [detector]
"""
import argparse
import datetime
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
LEDGER = os.path.join(BASE, "reputation-ledger.jsonl")


def record(metrics_path, ledger=LEDGER):
    with open(metrics_path, encoding="utf-8") as f:
        m = json.load(f)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    n = 0
    with open(ledger, "a", encoding="utf-8") as f:
        for det, v in m.get("detectors", {}).items():
            f.write(json.dumps({"ts": ts, "detector": det,
                                "precision": v["precision"],
                                "recall": v["recall"],
                                "fp_rate": v["fp_rate"],
                                "source": os.path.basename(metrics_path)})
                    + "\n")
            n += 1
    print("recorded %d detector snapshots -> %s" % (n, ledger))
    return 0


def query(det=None, ledger=LEDGER):
    rows = []
    try:
        with open(ledger, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except OSError:
        return {"entries": [], "note": "ledger empty"}
    if det:
        rows = [r for r in rows if r["detector"] == det]
    trend = {}
    for r in rows:
        t = trend.setdefault(r["detector"], {"n": 0, "fp_rates": []})
        t["n"] += 1
        t["fp_rates"].append(r["fp_rate"])
    return {"entries": len(rows), "trend": trend}


def self_test():
    import tempfile
    fx = {"detectors": {"a": {"precision": 0.9, "recall": 0.8,
                              "fp_rate": 0.05},
                        "b": {"precision": 0.7, "recall": 0.6,
                              "fp_rate": 0.2}}}
    with tempfile.TemporaryDirectory() as tmp:
        mp = os.path.join(tmp, "m.json")
        lp = os.path.join(tmp, "l.jsonl")
        json.dump(fx, open(mp, "w"))
        assert record(mp, lp) == 0
        assert record(mp, lp) == 0
        q = query(ledger=lp)
        assert q["entries"] == 4, q
        assert q["trend"]["a"]["n"] == 2, q
        assert query("b", lp)["trend"]["b"]["fp_rates"] == [0.2, 0.2]
    print("reputation self-test: PASS (append-only, deterministic query)")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--record", default=None)
    ap.add_argument("--query", nargs="?", const=None, default="__none__")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if a.record:
        return record(a.record)
    if a.query != "__none__":
        print(json.dumps(query(a.query), indent=2))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
