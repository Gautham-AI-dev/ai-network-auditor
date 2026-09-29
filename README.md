# Sentinel OS — deterministic swarm adjudication + audit (public artifact)

Verdict-combination research artifact. Core result (honest): on the locked
CICIDS2017 subset, no adjudication beats the best lone detector — proven
three ways. What this system DOES deliver, measured: deterministic
replayable verdicts, signed hash-chained audit, graceful degradation,
flood-proof consistency. See `docs/novelty-lock.md` (frozen claim +
closure) and `results/`.

## Reproduce (one command)

```bash
pip install -r requirements.txt
kaggle datasets download -d chethuhn/network-intrusion-dataset \
  -p sentinel/data --unzip   # one-time, needs ~/.kaggle/kaggle.json
python reproduce.py          # exit 0 = ALL MATCH (PASS)
```

`reproduce.py` runs subset → detectors → verdict → score-fusion →
ablations, then compares every metric against `results/` reference values
plus chain-determinism. Anything differing = FAIL with file names.

## Layout

- `sentinel/` — pipeline scripts (deterministic, seeded).
- `results/` — reference metrics, manifests, verdict records.
- `docs/` — frozen novelty lock + FP-target literature note.
- `sentinel/data/` — dataset (downloaded, git-ignored; checksums in manifest).
