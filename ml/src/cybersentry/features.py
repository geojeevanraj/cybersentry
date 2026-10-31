"""Per-event behavioural features, causal by construction: every statistic is a
cumulative or rolling view over the entity's OWN earlier events (the current log line
included - its outcome is on the line the SIEM just received). These are the streaming
counters FR-4 specifies; M3 compiles the same definitions into Redis updates, and the
parity test between the two is this module's whole reason for being pure."""
import pandas as pd

AUTH_CODES = {"kerberos": 0, "ntlm": 1, "logon": 2}

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.sort_values(["step", "event_id"], kind="stable").reset_index(drop=True).copy()
    df["_fail"] = (df["outcome"] == "fail").astype(int)
    gu = df.groupby("src_user", group_keys=False)
    f = pd.DataFrame(index=df.index)
    f["is_fail"] = df["_fail"]
    f["user_prior_events"] = gu.cumcount()
    f["user_prior_fails"] = gu["_fail"].cumsum() - df["_fail"]
    f["user_fails_last10"] = gu["_fail"].apply(
        lambda x: x.rolling(10, min_periods=1).sum())
    pair = df["src_user"] + ">" + df["dst_comp"]
    f["pair_prior"] = df.groupby(pair).cumcount()
    f["new_dst"] = (f["pair_prior"] == 0).astype(int)
    df["_new"] = f["new_dst"]
    f["novel_dst_last20"] = gu["_new"].apply(
        lambda x: x.rolling(20, min_periods=1).sum())
    f["novel_dst_last5"] = gu["_new"].apply(
        lambda x: x.rolling(5, min_periods=1).sum())
    gd = df.groupby("dst_comp", group_keys=False)
    f["dst_fails_last20"] = gd["_fail"].apply(
        lambda x: x.rolling(20, min_periods=1).sum())
    f["src_comp_new_for_user"] = (
        df.groupby(df["src_user"] + ">" + df["src_comp"]).cumcount() == 0).astype(int)
    f["hour"] = (df["step"] % 24).astype(int)
    f["off_hours"] = ((f["hour"] < 6) | (f["hour"] > 20)).astype(int)
    f["auth_c"] = df["auth_type"].map(AUTH_CODES).astype(int)
    return pd.concat([df.drop(columns=["_fail", "_new"]), f], axis=1)

def feature_columns(df: pd.DataFrame) -> list[str]:
    return ["is_fail", "user_prior_events", "user_prior_fails", "user_fails_last10",
            "pair_prior", "new_dst", "novel_dst_last20", "novel_dst_last5",
            "dst_fails_last20", "src_comp_new_for_user", "hour", "off_hours", "auth_c"]
