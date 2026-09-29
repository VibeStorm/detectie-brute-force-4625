"""Cele două metode comparate: o regulă simplă și un model de învățare automată (Isolation Forest)."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from .features import FEATURE_COLUMNS


def rule_baseline(feat: pd.DataFrame, min_failed: int = 10) -> np.ndarray:
    """Regula clasică: alertă dacă o adresă are cel puțin `min_failed` eșecuri într-o fereastră de 5 minute."""
    return (feat["n_failed"] >= min_failed).to_numpy()


def isolation_forest(feat: pd.DataFrame, contamination: float = 0.005, seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """Model NESUPERVIZAT: nu vede etichetele de atac, doar cât de „neobișnuită" e fereastra.

    `contamination` = proporția de ferestre pe care le semnalăm (aici 0,5%: capacitatea de analiză a unui analist).
    Returnează (alerte booleene, scoruri de anomalie; mai mare = mai suspect).
    """
    x = feat[FEATURE_COLUMNS].to_numpy(dtype=float)
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed)
    model.fit(x)
    alerts = model.predict(x) == -1
    scores = -model.score_samples(x)
    return alerts, scores


def evaluate(feat: pd.DataFrame, alerts: np.ndarray) -> dict:
    """Precizie, recall și F1 pe ferestre, plus câte atacuri de fiecare tip au fost prinse."""
    y = feat["is_attack"].to_numpy(dtype=bool)
    p, r, f1, _ = precision_recall_fscore_support(y, alerts, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, alerts, labels=[False, True]).ravel()
    by_type = {}
    for t in ("brute_force", "password_spray"):
        mask = (feat["attack_type"] == t).to_numpy()
        by_type[t] = {"ferestre_atac": int(mask.sum()), "prinse": int((alerts & mask).sum())}
    return {
        "precizie": float(p), "recall": float(r), "f1": float(f1),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "alerte_totale": int(alerts.sum()),
        "pe_tip_de_atac": by_type,
    }
