"""Leakage and split tests for out-of-time security detection."""
import numpy as np
import pandas as pd
from cybersentry.split import simulate, time_split
from cybersentry.features import build_features, feature_columns

CFG = {"n_users": 40, "n_comps": 30, "n_steps": 200, "n_scenarios": 6}

def toy():
    df, scen = simulate(CFG, seed=11)
    return time_split(df, 120, 160, 10), scen

def test_split_windows_are_ordered_with_embargo():
    df, _ = toy()
    agg = df[df.split != "drop"].groupby("split")["step"].agg(["min", "max"])
    assert agg.loc["val", "min"] - agg.loc["train", "max"] > 10
    assert agg.loc["test", "min"] - agg.loc["val", "max"] > 10

def test_embargo_rows_are_dropped_not_reused():
    df, _ = toy()
    assert df.loc[df.step.between(121, 130), "split"].eq("drop").all()

def test_behavioural_counters_are_causal():
    """Rewriting every event after step T must not change features at steps <= T."""
    df, _ = toy()
    poked = df.copy()
    late = poked.step > 100
    poked.loc[late, "outcome"] = "fail"
    poked.loc[late, "dst_comp"] = "C0001"
    a, b = build_features(df), build_features(poked)
    cols, past = feature_columns(a), a["step"] <= 100
    pd.testing.assert_frame_equal(a.loc[past, cols], b.loc[past, cols])

def test_label_and_scenario_never_enter_features():
    df, _ = toy()
    cols = set(feature_columns(build_features(df)))
    assert not {"malicious", "technique", "scenario", "split"} & cols

def test_simulation_is_deterministic_and_labels_sit_in_windows():
    a, sa = toy()
    b, sb = toy()
    pd.testing.assert_frame_equal(a, b)
    win = {r.scenario: (r.start, r.end) for r in sa.itertuples()}
    mal = a[a.malicious]
    for r in mal.itertuples():
        lo, hi = win[r.scenario]
        assert lo <= r.step <= hi
