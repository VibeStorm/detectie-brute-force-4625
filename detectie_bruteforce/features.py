"""Transformă evenimentele în „ferestre" (o linie per adresă IP și interval de 5 minute).

Un analist SOC nu se uită la un eveniment izolat, ci la ce face o adresă într-un interval scurt.
De aceea modelul primește câte o linie pentru fiecare pereche (IP sursă, fereastră de 5 minute).
"""
from __future__ import annotations

import pandas as pd

FEATURE_COLUMNS = [
    "n_events",
    "n_failed",
    "n_success",
    "failed_ratio",
    "n_users_failed",
    "max_failed_per_user",
    "n_hosts",
    "success_after_failed",
    "events_per_minute",
]


def build_features(events: pd.DataFrame, window: str = "5min") -> pd.DataFrame:
    """Un rând per (src_ip, window), cu coloanele din FEATURE_COLUMNS plus etichetele de evaluare."""
    df = events.copy()
    df["window"] = df["timestamp"].dt.floor(window)
    df["failed"] = df["event_id"] == 4625
    df["success"] = df["event_id"] == 4624
    keys = ["src_ip", "window"]

    base = df.groupby(keys).agg(
        n_events=("event_id", "size"),
        n_failed=("failed", "sum"),
        n_success=("success", "sum"),
        n_hosts=("host", "nunique"),
        is_attack=("attack_type", lambda s: bool((s != "none").any())),
        attack_type=("attack_type", lambda s: next((x for x in s if x != "none"), "none")),
    )

    failed = df[df["failed"]]
    per_failed = failed.groupby(keys).agg(
        n_users_failed=("user", "nunique"),
        max_failed_per_user=("user", lambda s: int(s.value_counts().max())),
    )
    first_fail = failed.groupby(keys)["timestamp"].min().rename("first_fail")
    last_success = df[df["success"]].groupby(keys)["timestamp"].max().rename("last_success")

    feat = base.join(per_failed).join(first_fail).join(last_success)
    feat[["n_users_failed", "max_failed_per_user"]] = feat[["n_users_failed", "max_failed_per_user"]].fillna(0)
    feat["success_after_failed"] = (feat["last_success"] > feat["first_fail"]).fillna(False).astype(int)
    feat["failed_ratio"] = feat["n_failed"] / feat["n_events"]
    minutes = pd.Timedelta(window).total_seconds() / 60
    feat["events_per_minute"] = feat["n_events"] / minutes
    feat = feat.drop(columns=["first_fail", "last_success"]).reset_index()
    for c in ("n_events", "n_failed", "n_success", "n_users_failed", "max_failed_per_user", "n_hosts"):
        feat[c] = feat[c].astype(int)
    return feat
