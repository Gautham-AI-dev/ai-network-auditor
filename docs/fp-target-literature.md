# FP-target literature check (2026-09-28) — why 15pp absolute is unachievable

## Published FP rates on CICIDS2017-class data

- DRX ensemble (2023): FPR 0.00012 on CICIDS2017 (best reported).
- Subspace-clustering ensemble (2024, IoT): FPR 0.029.
- MDPI deterministic comparison (2025): LR FAR 0.0091–0.0126 on CICIDS2017.
- Our supervised detector: FPR 0.0176 — squarely inside the published band.
  (Corroborates our pipeline; no headline inflation.)

## How the field reports FP reduction: ALWAYS relative

- ALAC: −30% false alerts. CLARAty: −50%. Julisch hand-rules: −87% alarms.
- Fuzzy aggregation: −83% to −98%. Statistical architecture: −89.59% FP.
- Nobody reports absolute percentage-point cuts vs sub-2% baselines —
  because at FPR ~1%, a "15pp cut" is arithmetically impossible.

## Conclusion for the lock

The locked "≥15pp lower FP rate" implicitly assumed a weak best-lone
baseline (like our 19%-FP signature rules). Against the measured best lone
(supervised, 1.76%), the literature-consistent formulation is RELATIVE:
≥50% relative FP reduction at equal-or-better recall (→ ≤0.88%), a bar
stricter than ALAC (−30%) and matching CLARAty (−50%), measured
self-controlled on the locked subset. Proposed as lock amendment A1 —
operator approval required before verdict construction.
