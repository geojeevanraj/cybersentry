"""Score the test window with the champion, fill auth_events.risk_score, and open
alerts rows for events inside the triage budget - each alert carrying the rules that
also fired, so an analyst sees model and rule evidence side by side."""
import json
import joblib
import mlflow
import numpy as np
import pandas as pd
from .config import PROCESSED, MODEL_NAME, MLFLOW_URI, load_cfg
from .features import build_features
from .baseline import RuleEngine
from .evaluate import budget_mask
from . import db, tracking

# M1 seeded auth_events with event_ref 'CS-E-<event_id>' and left risk_score /
# model_version nullable; alerts is empty. Adjust the SQL if your M1 differs.
ENTITY = "CS-E-{}"
FILL_SQL = """
UPDATE auth_events e
SET risk_score = p.score,
    model_version = p.model_version
FROM ml_predictions p
WHERE p.model_name = :model AND e.event_ref = p.entity_id
"""
ALERT_SQL = """
INSERT INTO alerts (event_ref, layer, score, techniques, evidence, model_version)
SELECT p.entity_id, 'model', p.score,
       ARRAY['T1110','T1021'], CAST(:evidence AS JSONB), p.model_version
FROM ml_predictions p
WHERE p.model_name = :model AND p.entity_id = :ref AND p.label = 'alert'
ON CONFLICT DO NOTHING
"""

def main():
    cfg = load_cfg()
    label, run_id = tracking.champion()
    mlflow.set_tracking_uri(MLFLOW_URI)
    b = joblib.load(mlflow.artifacts.download_artifacts(
        run_id=run_id, artifact_path="bundle/model.joblib"))
    df = build_features(pd.read_parquet(PROCESSED / "dataset.parquet"))
    te = df[df.split == "test"].reset_index(drop=True)
    score = b["clf"].predict_proba(te[b["features"]])[:, 1]
    flagged = budget_mask(score, cfg["triage_budget"])
    rules = RuleEngine.fired(te)
    names = np.array(rules.columns)
    out = pd.DataFrame({"entity_id": te.event_id.map(ENTITY.format),
                        "step": te.step.astype(str), "score": score,
                        "label": np.where(flagged, "alert", "ok")})
    out["extra"] = [{"rules": names[row].tolist()} for row in rules.values]
    n = db.upsert_predictions(out, MODEL_NAME, label)
    filled = db.run_sql(FILL_SQL, model=MODEL_NAME)
    opened = 0
    for ref, extra in zip(out.loc[flagged, "entity_id"], out.loc[flagged, "extra"]):
        opened += db.run_sql(ALERT_SQL, model=MODEL_NAME, ref=ref,
                             evidence=json.dumps(extra))
    print(f"{n} scores stored as {label}; {filled} auth_events filled; "
          f"{opened} alerts opened")

if __name__ == "__main__":
    main()
