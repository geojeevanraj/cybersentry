"""Incumbent: the M1 Sigma-style rule pack, re-expressed as a weighted scorer over the
same behavioural counters the model reads - which makes the comparison airtight. Rules
stay in production beside the model (they are explainable and ATT&CK-tagged); the model
has to earn the queue by catching what the rules miss at the same analyst budget."""
import numpy as np
import pandas as pd

RULES = { # name: (weight, ATT&CK tag, predicate over the feature frame)
    "failed_auth_burst": (2.0, "T1110", lambda f: f["user_fails_last10"] >= 5),
    "target_fail_pileup": (1.5, "T1110", lambda f: f["dst_fails_last20"] >= 8),
    "novel_destination": (1.0, "T1021", lambda f: f["new_dst"] == 1),
    "dst_fanout": (2.0, "T1021", lambda f: f["novel_dst_last5"] >= 3),
    "offhours_new_src": (0.5, "T1078", lambda f: (f["off_hours"] == 1)
                         & (f["src_comp_new_for_user"] == 1)),
}

class RuleEngine:
    total = sum(w for w, _, _ in RULES.values())

    def predict_proba(self, f: pd.DataFrame) -> np.ndarray:
        score = sum(w * pred(f).astype(float).values
                    for w, _, pred in RULES.values()) / self.total
        return np.c_[1 - score, score]

    @staticmethod
    def fired(f: pd.DataFrame) -> pd.DataFrame:
        return pd.DataFrame({k: pred(f) for k, (_, _, pred) in RULES.items()})

if __name__ == "__main__":
    from .config import PROCESSED
    from .features import build_features
    df = build_features(pd.read_parquet(PROCESSED / "dataset.parquet"))
    tr = df[df.split == "train"]
    fired = RuleEngine.fired(tr)
    print("rule hit-rate and precision on train:")
    for r in fired:
        hit = fired[r]
        print(f"  {r:<20} fires {hit.mean():7.3%} precision {tr.malicious[hit].mean():7.2%}")
