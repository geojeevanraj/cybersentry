"""Single source of paths, connection strings and seeds for M2."""
import os
import pathlib
import yaml
ROOT = pathlib.Path(__file__).resolve().parents[3]          # repo root
RAW = ROOT / "data" / "raw"                                  # DVC-tracked in M1
PROCESSED = ROOT / "data" / "processed"
ARTIFACTS = ROOT / "artifacts"
REPORTS = ROOT / "reports"
CONFIGS = ROOT / "configs"
DATABASE_URL = os.getenv("DATABASE_URL",
                         "postgresql+psycopg2://cybersentry:cybersentry@localhost:5432/cybersentry")
MLFLOW_URI = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
MODEL_NAME = "cybersentry-auth-risk"
SEED = 42

def load_cfg(path=None) -> dict:
    with open(path or CONFIGS / "train.yaml") as fh:
        return yaml.safe_load(fh)