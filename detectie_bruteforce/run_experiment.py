"""Rulează experimentul complet: generează date, construiește ferestrele, compară cele două metode.

Exemplu:
    python -m detectie_bruteforce.run_experiment --n-seeds 5

Rezultatele se salvează în folderul `results/` (metrics.json, tabelul de mai jos și un grafic).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from .features import build_features
from .generate_data import Config, generate_events
from .models import evaluate, isolation_forest, rule_baseline


def run_once(seed: int, contamination: float, min_failed: int):
    events = generate_events(Config(seed=seed))
    feat = build_features(events)
    rule_alerts = rule_baseline(feat, min_failed=min_failed)
    if_alerts, if_scores = isolation_forest(feat, contamination=contamination, seed=seed)
    # același „buget de alerte" ca regula: un analist poate verifica doar atâtea alerte
    budget = max(int(rule_alerts.sum()), 1) / len(feat)
    iff_alerts, _ = isolation_forest(feat, contamination=min(budget, 0.5), seed=seed)
    feat = feat.assign(rule_alert=rule_alerts, if_alert=if_alerts, if_score=if_scores, if_budget_alert=iff_alerts)
    result = {
        "seed": seed,
        "n_evenimente": int(len(events)),
        "n_ferestre": int(len(feat)),
        "n_ferestre_atac": int(feat["is_attack"].sum()),
        "regula": evaluate(feat, rule_alerts),
        "isolation_forest": evaluate(feat, if_alerts),
        "isolation_forest_acelasi_buget": evaluate(feat, iff_alerts),
    }
    return result, feat


def _summarize(runs: list[dict], method: str) -> dict:
    out = {}
    for m in ("precizie", "recall", "f1"):
        vals = np.array([r[method][m] for r in runs])
        out[m] = {"medie": float(vals.mean()), "abatere_std": float(vals.std())}
    out["alerte_medii"] = float(np.mean([r[method]["alerte_totale"] for r in runs]))
    out["fp_mediu"] = float(np.mean([r[method]["fp"] for r in runs]))
    return out


def _plot(feat, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6))
    for ax, col, title in ((axes[0], "rule_alert", "Regula (≥10 eșecuri / 5 min)"),
                           (axes[1], "if_budget_alert", "Isolation Forest (același nr. de alerte)")):
        y = feat["is_attack"].to_numpy(dtype=bool)
        a = feat[col].to_numpy(dtype=bool)
        mat = np.array([[np.sum(~y & ~a), np.sum(~y & a)], [np.sum(y & ~a), np.sum(y & a)]])
        ax.imshow(mat, cmap="Blues")
        ax.set_xticks([0, 1], ["fără alertă", "alertă"])
        ax.set_yticks([0, 1], ["normal", "atac"])
        ax.set_title(title, fontsize=10)
        for (i, j), v in np.ndenumerate(mat):
            ax.text(j, i, str(v), ha="center", va="center", color="black" if v < mat.max() / 2 else "white")
    fig.suptitle("Matrici de confuzie pe ferestre (un singur set de date)", fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n-seeds", type=int, default=5, help="câte seturi de date diferite se generează")
    ap.add_argument("--contamination", type=float, default=0.005, help="proporția de ferestre semnalate de Isolation Forest")
    ap.add_argument("--min-failed", type=int, default=10, help="pragul regulii: eșecuri într-o fereastră de 5 minute")
    ap.add_argument("--out", default="results", help="folderul cu rezultate")
    a = ap.parse_args()

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    runs, first_feat = [], None
    for s in range(a.n_seeds):
        res, feat = run_once(42 + s, a.contamination, a.min_failed)
        runs.append(res)
        if first_feat is None:
            first_feat = feat

    summary = {
        "parametri": {"n_seeds": a.n_seeds, "contamination": a.contamination, "min_failed": a.min_failed},
        "regula": _summarize(runs, "regula"),
        "isolation_forest": _summarize(runs, "isolation_forest"),
        "isolation_forest_acelasi_buget": _summarize(runs, "isolation_forest_acelasi_buget"),
        "rulari": runs,
    }
    (out / "metrics.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    _plot(first_feat, out / "confusion_matrices.png")

    r0 = runs[0]
    print(f"Set de date (seed {r0['seed']}): {r0['n_evenimente']} evenimente, "
          f"{r0['n_ferestre']} ferestre, {r0['n_ferestre_atac']} ferestre de atac\n")
    print(f"{'Metodă':<20}{'Precizie':>18}{'Recall':>18}{'F1':>18}{'Alerte':>9}{'Fals poz.':>11}")
    for name, key in (("Regula (>=%d)" % a.min_failed, "regula"),
                      ("IF, %.1f%% ferestre" % (a.contamination * 100), "isolation_forest"),
                      ("IF, același buget", "isolation_forest_acelasi_buget")):
        s = summary[key]
        fmt = lambda m: f"{s[m]['medie']:.2f} ± {s[m]['abatere_std']:.2f}"
        print(f"{name:<20}{fmt('precizie'):>18}{fmt('recall'):>18}{fmt('f1'):>18}"
              f"{s['alerte_medii']:>9.1f}{s['fp_mediu']:>11.1f}")
    print(f"\n(medii pe {a.n_seeds} seturi de date; rezultate salvate în {out}/)")


if __name__ == "__main__":
    main()
