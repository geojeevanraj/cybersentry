"""Supervised detection layer: LightGBM over the behavioural counters, trained on the
labelled replay's past and early-stopped on the validation window that lies strictly
after it. This is the calibrated-score layer of FR-8; the unsupervised GRU sequence
model (trained on attack-free segments) is M3's challenger on the same replay."""
import json
import joblib
import lightgbm as lgb
import mlflow
import pandas as pd
from sklearn.metrics import average_precision_score
from .config import PROCESSED, ARTIFACTS, SEED, load_cfg
from .features import build_features, feature_columns
from . import tracking

def frames():
    df = build_features(pd.read_parquet(PROCESSED / "dataset.parquet"))
    return {k: v for k, v in df.groupby("split")}, feature_columns(df)

def run(cfg: dict, log: bool = True) -> dict:
    parts, cols = frames()
    tr, va = parts["train"], parts["val"]
    m = cfg["model"]
    clf = lgb.LGBMClassifier(
        n_estimators=m["n_estimators"], learning_rate=m["learning_rate"],
        num_leaves=m["num_leaves"], min_child_samples=m["min_child_samples"],
        subsample=m["subsample"], subsample_freq=1, colsample_bytree=m["colsample_bytree"],
        reg_lambda=m["reg_lambda"], scale_pos_weight=m["scale_pos_weight"],
        random_state=SEED, verbose=-1)
    clf.fit(tr[cols], tr.malicious, eval_set=[(va[cols], va.malicious)],
            eval_metric="average_precision",
            callbacks=[lgb.early_stopping(50, verbose=False)])
    metrics = {"val_pr_auc": float(average_precision_score(
        va.malicious, clf.predict_proba(va[cols])[:, 1]))}
    if not log:
        return metrics
    with tracking.start(cfg) as r:
        mlflow.log_params({f"model.{k}": v for k, v in m.items()})
        mlflow.log_params({"n_features": len(cols), "best_iter": clf.best_iteration_,
                           "train_attack_rate": round(float(tr.malicious.mean()), 5)})
        mlflow.log_metrics(metrics)
        imp = pd.Series(clf.booster_.feature_importance("gain"), index=cols).sort_values()
        mlflow.log_text(imp.to_string(), "feature_importance_gain.txt")
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        joblib.dump({"clf": clf, "features": cols}, ARTIFACTS / "model.joblib")
        mlflow.sklearn.log_model(clf, "model")
        mlflow.log_artifact(str(ARTIFACTS / "model.joblib"), "bundle")
        tracking.save_run_id(r.info.run_id)
        metrics["run_id"] = r.info.run_id
        return metrics

def main():
    print(json.dumps(run(load_cfg()), indent=2))

if __name__ == "__main__":
    main()
