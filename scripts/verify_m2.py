"""M2 definition-of-done checks. Exit code 0 means ready to tag v0.2.0-M2."""
import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "ml" / "src"))
from cybersentry.config import ROOT, REPORTS, MODEL_NAME # noqa: E402
from cybersentry import db, tracking # noqa: E402
from cybersentry.promote import check # noqa: E402

FILES = [
    'ml/src/cybersentry/config.py',
    'ml/src/cybersentry/tracking.py',
    'ml/src/cybersentry/db.py',
    'ml/src/cybersentry/split.py',
    'ml/src/cybersentry/features.py',
    'ml/src/cybersentry/baseline.py',
    'ml/src/cybersentry/train.py',
    'ml/src/cybersentry/hpo.py',
    'ml/src/cybersentry/evaluate.py',
    'ml/src/cybersentry/promote.py',
    'ml/src/cybersentry/writeback.py',
    'configs/train.yaml',
    'configs/gates.yaml',
    'docs/model_card.md',
    'db/migrations/002_m2_predictions.sql',
    'ml/tests/test_m2_leakage.py',
]
FILLED_SQL = """SELECT count(*) FROM auth_events WHERE risk_score IS NOT NULL"""
results = []

def ok(name, cond, detail=""):
    results.append(cond)
    print(f"[{'OK ' if cond else 'XX '}] {name} {detail}")

for f in FILES:
    ok(f"file {f}", (ROOT / f).exists())

r = subprocess.run([sys.executable, "-m", "pytest", "-q", "ml/tests/test_m2_leakage.py"],
                   cwd=ROOT, env={"PYTHONPATH": "ml/src", "PATH": "/usr/bin:/bin"})
ok("leakage tests", r.returncode == 0)

rep = REPORTS / "eval.json"
ok("evaluation report", rep.exists())
if rep.exists():
    for path, val, op, thr, passed in check(json.loads(rep.read_text())):
        ok(f"gate {path}", passed, f"{val:.4f} {op} {thr}")

try:
    label, _ = tracking.champion()
    ok("registry champion", True, label)
except Exception as e: # noqa: BLE001
    ok("registry champion", False, str(e)[:80])

try:
    n_pred = db.scalar("SELECT count(*) FROM ml_predictions WHERE model_name = :m", m=MODEL_NAME)
    ok("ml_predictions rows", (n_pred or 0) > 0, str(n_pred))
    n_fill = db.scalar(FILLED_SQL)
    ok("M1 nullable column filled", (n_fill or 0) > 0, str(n_fill))
except Exception as e: # noqa: BLE001
    ok("database writeback", False, str(e)[:80])

print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if all(results) else 1)
