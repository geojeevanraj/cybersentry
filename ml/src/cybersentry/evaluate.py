"""The SOC lens: a tier-1 team can look at a fixed share of events (the triage
budget). Score the test window once, take the top budget-share by score, and report (a)
coverage per ATT&CK technique - was each attack scenario surfaced inside the budget? -
(b) precision inside the budget, and (c) event-level PR-AUC. Model and rule engine get
identical treatment; the derived gates demand the model adds scenarios the rules miss."""
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score
from .config import PROCESSED, ARTIFACTS, load_cfg
from .features import build_features
from .baseline import RuleEngine
from . import tracking

def budget_mask(score: np.ndarray, budget: float) -> np.ndarray:
    k = max(1, int(round(len(score) * budget)))
    cut = np.partition(score, -k)[-k]
    return score >= cut

def coverage(te: pd.DataFrame, flagged: np.ndarray, scen: pd.DataFrame) -> dict:
    hit = set(te.loc[flagged & te.event_id.isin(scen.event_id),
                     "event_id"].map(scen.set_index("event_id")["scenario"]))
    out = {}
    for tech, grp in scen.groupby("technique"):
        total = grp.scenario.nunique()
        out[f"coverage_{tech}"] = len(set(grp.scenario) & hit) / max(total, 1)
    out["scenarios_detected"] = len(hit)
    return out

def block(te, score, scen, budget) -> dict:
    flagged = budget_mask(score, budget)
    y = te.malicious.to_numpy()
    return {"pr_auc": float(average_precision_score(y, score)),
            "precision_at_budget": float(y[flagged].mean()),
            "recall_at_budget": float(y[flagged].sum() / max(y.sum(), 1)),
            "alerts_at_budget": int(flagged.sum()),
            **coverage(te, flagged, scen)}

def main():
    cfg = load_cfg()
    budget = cfg["triage_budget"]
    b = joblib.load(ARTIFACTS / "model.joblib")
    df = build_features(pd.read_parquet(PROCESSED / "dataset.parquet"))
    scen = pd.read_parquet(PROCESSED / "scenarios.parquet")
    te = df[df.split == "test"].reset_index(drop=True)
    scen_te = scen[scen.event_id.isin(te.event_id)]
    model = block(te, b["clf"].predict_proba(te[b["features"]])[:, 1], scen_te, budget)
    base = block(te, RuleEngine().predict_proba(te)[:, 1], scen_te, budget)
    n_scen = int(scen_te.scenario.nunique())
    report = {"run_id": tracking.load_run_id(), "test_events": int(len(te)),
              "test_scenarios": n_scen, "model": model, "baseline": base,
              "derived": {
                  "pr_auc_gain": model["pr_auc"] - base["pr_auc"],
                  "coverage_gain": (model["scenarios_detected"]
                                    - base["scenarios_detected"]) / max(n_scen, 1),
                  "precision_gain_at_budget": model["precision_at_budget"]
                                              - base["precision_at_budget"]}}
    tracking.write_report(report)
    print(f"coverage T1110 {model.get('coverage_T1110', 0):.2f} / "
          f"T1021 {model.get('coverage_T1021', 0):.2f} | precision@budget "
          f"model={model['precision_at_budget']:.2f} rules={base['precision_at_budget']:.2f}")

if __name__ == "__main__":
    main()
