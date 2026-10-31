"""Generate a labelled authentication-event replay (LANL-flavoured schema) from the
committed simulator and split OUT-OF-TIME with an embargo.

Why simulated replay: the real LANL corpus is an 11 GB download whose labels cover a
single red-team exercise; the platform's own spec evaluates detection on "scenario
replays built from labelled segments". The committed, seeded simulator produces benign
enterprise auth traffic plus injected attack scenarios - credential brute force
(ATT&CK T1110) and lateral movement (T1021) - whose scenario windows are ground truth.
Per-event labels train the supervised layer; the scenario->technique table is
EVALUATION-ONLY and drives the coverage-per-technique report.

Why out-of-time: attacks are episodes in time and accounts persist across days. A random
split puts half a brute-force burst in train and half in test and the model learns the
burst, not the behaviour. Train on the first 20 days, validate on the next 4, test on
the final 5, with a 24-hour embargo discarded between each."""
import numpy as np
import pandas as pd
from .config import PROCESSED, SEED, load_cfg

AUTH = ["kerberos", "ntlm", "logon"]

def simulate(cfg, seed=SEED):
    rng = np.random.default_rng(seed)
    n_users, n_comps, n_steps = cfg["n_users"], cfg["n_comps"], cfg["n_steps"]
    users = [f"U{i:04d}" for i in range(n_users)]
    comps = [f"C{i:04d}" for i in range(n_comps)]
    home = {u: rng.choice(n_comps, size=rng.integers(1, 4), replace=False) for u in users}
    rows, scen_rows = [], []

    def emit(step, su, sc, dc, outcome, malicious, technique=None, scenario=None):
        rows.append({"step": int(step), "src_user": su, "src_comp": sc, "dst_comp": dc,
                     "auth_type": AUTH[rng.integers(0, 3)], "outcome": outcome,
                     "malicious": malicious, "technique": technique or "",
                     "scenario": scenario or ""})

    for step in range(1, n_steps + 1):
        hour = step % 24
        activity = 0.35 if 7 <= hour <= 19 else 0.04
        for ui in rng.choice(n_users, size=rng.binomial(n_users, activity), replace=False):
            u = users[ui]
            for _ in range(rng.integers(1, 4)):
                dst = comps[rng.choice(home[u]) if rng.random() < 0.92
                            else rng.integers(0, n_comps)]
                emit(step, u, comps[rng.choice(home[u])], dst,
                     "fail" if rng.random() < 0.02 else "success", False)

    for k in range(cfg["n_scenarios"]):
        kind = "bruteforce" if k % 2 == 0 else "lateral"
        start = int(rng.integers(12, n_steps - 12))
        sid = f"{kind}-{k:02d}"
        victim = users[rng.integers(0, n_users)]
        if kind == "bruteforce": # T1110: fail burst, then a success
            attacker = f"C9{rng.integers(0, 99):03d}"
            for j in range(int(rng.integers(12, 18))):
                emit(start + (j // 10), victim, attacker, comps[rng.choice(home[victim])],
                     "fail", True, "T1110", sid)
            emit(start + 2, victim, attacker, comps[rng.choice(home[victim])],
                 "success", True, "T1110", sid)
            scen_rows.append({"scenario": sid, "technique": "T1110",
                              "start": start, "end": start + 2})
        else: # T1021: hops to fresh machines
            hops = rng.choice(n_comps, size=int(rng.integers(5, 9)), replace=False)
            for j, h in enumerate(hops):
                emit(start + (j // 3), victim, comps[rng.choice(home[victim])],
                     f"C{h:04d}", "success", True, "T1021", sid)
                if rng.random() < 0.4:
                    emit(start + (j // 3), victim, comps[rng.choice(home[victim])],
                         f"C{h:04d}", "fail", True, "T1021", sid)
            scen_rows.append({"scenario": sid, "technique": "T1021",
                              "start": start, "end": start + 3})

    df = pd.DataFrame(rows).sort_values("step", kind="stable").reset_index(drop=True)
    df["event_id"] = np.arange(len(df))
    return df, pd.DataFrame(scen_rows)

def time_split(df, train_end, val_end, embargo):
    s = df["step"]
    split = pd.Series("drop", index=df.index) # embargo rows are discarded
    split[s <= train_end] = "train"
    split[(s > train_end + embargo) & (s <= val_end)] = "val"
    split[s > val_end + embargo] = "test"
    return df.assign(split=split.values)

def main():
    cfg = load_cfg()
    df, scenarios = simulate(cfg["simulate"])
    sp = cfg["split"]
    df = time_split(df, sp["train_end_step"], sp["val_end_step"], sp["embargo_steps"])
    PROCESSED.mkdir(parents=True, exist_ok=True)
    df.drop(columns=["technique", "scenario"]).to_parquet(
        PROCESSED / "dataset.parquet", index=False)
    df[df.malicious][["event_id", "step", "scenario"]].merge(scenarios).to_parquet(
        PROCESSED / "scenarios.parquet", index=False) # evaluation-only
    print(df.groupby("split").agg(events=("step", "size"),
                                  attack_rate=("malicious", "mean")).round(4))
    print(f"{len(scenarios)} scenarios "
          f"({(scenarios.technique == 'T1110').sum()} T1110, "
          f"{(scenarios.technique == 'T1021').sum()} T1021)")

if __name__ == "__main__":
    main()
