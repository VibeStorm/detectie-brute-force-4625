"""Teste automate: rulează cu `python -m pytest`."""
import pandas as pd

from detectie_bruteforce.features import FEATURE_COLUMNS, build_features
from detectie_bruteforce.generate_data import Config, generate_events
from detectie_bruteforce.models import evaluate, isolation_forest, rule_baseline


def test_generator_is_deterministic():
    a = generate_events(Config(seed=1, n_users=10, days=2))
    b = generate_events(Config(seed=1, n_users=10, days=2))
    pd.testing.assert_frame_equal(a, b)


def test_generator_has_expected_columns_and_event_ids():
    ev = generate_events(Config(seed=1, n_users=10, days=2))
    assert list(ev.columns) == ["timestamp", "event_id", "user", "src_ip", "host", "attack_type"]
    assert set(ev["event_id"].unique()) <= {4624, 4625}
    assert {"none", "brute_force", "password_spray"} <= set(ev["attack_type"].unique())
    assert ev["timestamp"].is_monotonic_increasing


def test_features_on_tiny_hand_made_example():
    ts = pd.to_datetime(["2026-01-05 10:00:01", "2026-01-05 10:00:02", "2026-01-05 10:00:03", "2026-01-05 10:00:09"])
    ev = pd.DataFrame({
        "timestamp": ts,
        "event_id": [4625, 4625, 4625, 4624],
        "user": ["a", "a", "b", "a"],
        "src_ip": ["1.2.3.4"] * 4,
        "host": ["H1"] * 4,
        "attack_type": ["brute_force", "brute_force", "brute_force", "none"],
    })
    feat = build_features(ev)
    assert len(feat) == 1
    row = feat.iloc[0]
    assert row["n_events"] == 4 and row["n_failed"] == 3 and row["n_success"] == 1
    assert row["n_users_failed"] == 2 and row["max_failed_per_user"] == 2
    assert row["success_after_failed"] == 1
    assert bool(row["is_attack"]) is True
    assert set(FEATURE_COLUMNS) <= set(feat.columns)


def test_rule_flags_only_windows_over_threshold():
    feat = pd.DataFrame({"n_failed": [0, 9, 10, 25]})
    assert list(rule_baseline(feat, min_failed=10)) == [False, False, True, True]


def test_end_to_end_metrics_are_valid():
    ev = generate_events(Config(seed=3, n_users=30, days=3))
    feat = build_features(ev)
    alerts, scores = isolation_forest(feat, contamination=0.01, seed=3)
    m = evaluate(feat, alerts)
    assert 0.0 <= m["precizie"] <= 1.0 and 0.0 <= m["recall"] <= 1.0
    assert m["tp"] + m["fp"] + m["fn"] + m["tn"] == len(feat)
    assert len(scores) == len(feat)
