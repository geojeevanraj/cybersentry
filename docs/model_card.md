# Model card - cybersentry-auth-risk

## Purpose
Rank authentication events by attack likelihood so a 1% tier-1 triage budget surfaces brute-force
and lateral-movement activity with evidence attached.

## Not for
Automated containment of any kind (the platform is recommendation-only by ADR-0002); techniques
outside the replay's scenario set; network-flow or process telemetry until those sources land in M3.

## Data
- Source: Committed seeded simulator: 30 days of benign enterprise auth traffic plus 30 labelled attack
scenarios in LANL-flavoured schema.
- Split: Out-of-time: train days 1-20, val days 21-24, test days 25-30, 24-hour embargo between each
- Labels: Per event: part of an injected scenario; scenario-technique map isolated for evaluation only.

## Model
LightGBM classifier over causal per-entity behavioural counters; tuned class re-weighting; early-stopped on a strictly-later validation window.

## Incumbent baseline
M1 Sigma-style rule pack (five weighted, ATT&CK-tagged rules) - the thing this model replaces or
augments.

## Evaluation (held-out test set; numbers filled from reports/eval.json)
Promotion gates (all must pass):
- `model.coverage_T1110` >= 0.85 - Platform objective: 85%+ of brute-force scenarios surfaced in
 budget
- `model.coverage_T1021` >= 0.85 - ...and 85%+ of lateral-movement scenarios - per technique, not
 averaged
- `model.precision_at_budget` >= 0.5 - At least half the queue is real attack activity
- `model.pr_auc` >= 0.7 - Ranking quality on the unseen future window
- `derived.precision_gain_at_budget` > 0.0 - Same analyst effort, cleaner queue than the rules
 alone

Actual results: coverage_T1110=1.00, coverage_T1021=1.00, precision_at_budget=0.54, pr_auc=0.83, precision_gain_at_budget=0.16. See `reports/eval.json` and the MLflow run tagged `champion`.

## Known limitations
- Simulated traffic: real enterprises add service accounts, VPN churn and ticket storms the
 simulator does not model.
- Two techniques only; a new technique scores as whatever its counters resemble.
- Counters reset at replay start; the first day of any entity is feature-poor.

## Ownership
Group: CyberSentry candidates.
Retrain trigger: real labelled segments (LANL slices, red-team exercises) being staged, or monthly from analyst
dispositions once M5's feedback loop lands.
