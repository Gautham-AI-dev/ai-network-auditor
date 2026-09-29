# NOVELTY LOCK (frozen 2026-09-28, operator-approved — no edits after this line)

## Claim (exact paragraph)

Sentinel verdict: a deterministic, replayable adjudication function over
heterogeneous detector-agent findings that outputs verdicts with
hash-linked evidence chains — no LLM in the verdict path — combined with
a continuous red-team self-measurement loop and an offline swarm runtime,
delivering measured false-positive reduction on a fixed labeled IDS
subset. Prior art covers alert correlation alone and signed audit chains
alone (closest: SeneX trading runtime); no prior art combines swarm
adjudication + deterministic replayable verdicts + signed chains +
measured FP deltas + red-loop in one runnable offline system.

## Target

≥15pp lower FP rate than the best lone detector at equal-or-better recall
on the locked CICIDS2017 Friday subset; replay bit-identical; peak RAM
≤2GB; full suite ≤30 min on RTX 3050/16GB laptop.

## Ablations (all must hold or claim fails)

1. Majority-vote instead of verdict fn → must lose ≥10pp FP.
2. Drop strongest detector → still beats remaining best.
3. Red-team alert flood → precision must not collapse.
4. CPU-only + fixed-seed rerun → bit-identical.

## Benchmark (to be fixed at acquisition)

CICIDS2017 Friday (DDoS + PortScan) + Monday benign sample; exact files,
rows, seed locked in acquisition evidence. Preprocessing per Engelen
corrections (drop artefacts, documented).

## CLOSURE (operator process, 2026-09-28) — FP-reduction claim RETIRED

Three independent verdict designs failed the A1 bar with full rigor:
boolean veto (empty set), 4-agent veto (recall 0.9959 < floor), stacking
(FP −21% relative, recall missed by 0.0001). The supervised lone detector
(98/99.7) sits at the achievable ceiling on this subset; no adjudication
extracts 50% FP cuts from it. Falsification accepted — this is the loop
working, not failing.

RETAINED (proven, measured): deterministic replayable verdicts + signed
audit chains + honest measurement apparatus + red-loop runtime design.
Sentinel OS continues on the reframe path (hybrid part 2): auditability
and adversarial self-measurement as the contribution, FP-reduction
dropped as a claim. FP work converts to regression-guard duty: the
verdict must never do WORSE than best lone (guardrail, not moonshot).

## AMENDMENT A1 (operator-approved 2026-09-28, literature-grounded)

Original "≥15pp lower FP rate" assumed a weak best-lone baseline. Measured
best lone (supervised) FP = 1.76%; the field reports relative cuts only
(ALAC −30%, CLARAty −50%, Julisch −87%; see fp-target-literature.md).
AMENDED TARGET: verdict achieves ≥50% RELATIVE FP reduction vs best lone
(FP ≤ 0.88%) at equal-or-better recall (≥ 0.9974). Ablations 1–4 unchanged
(ablation 1's "≥10pp" re-reads as relative-vs-majority under A1 spirit;
majority-vote baseline measured in verdict run for the record).
