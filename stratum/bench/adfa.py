"""Runtime anomaly model on ADFA-LD: STIDE baseline vs STRATUM n-gram novelty (+ optional IForest).

Protocol (standard for ADFA-LD): fit on Training_Data_Master (833 normal
traces), score Validation_Data_Master (4,372 normal) and Attack_Data_Master
(746 attack traces, 6 families). No attack data is used for fitting or for
choosing hyper-parameters; all configured variants are reported.
"""
from __future__ import annotations

import time
from pathlib import Path

from ..syscall import NgramIsolationForest, NgramNovelty, Stide, load_adfa, roc_auc, tpr_at_fpr

FPRS = (0.01, 0.05, 0.15)


def detectors():
    yield "STIDE n=6 (baseline, Forrest 1996)", Stide(6)
    yield "STIDE n=3", Stide(3)
    yield "STRATUM n-gram novelty n=3", NgramNovelty(3)
    yield "STRATUM n-gram novelty n=5", NgramNovelty(5)
    try:
        import sklearn  # noqa: F401
        yield "Isolation Forest, TF-IDF 1..3-grams", NgramIsolationForest(3)
    except ImportError:  # pragma: no cover
        return


def run(root: Path, roc: bool = True) -> dict:
    d = load_adfa(root / "adfa")
    pos = [t for _, t in d["attack"]]
    fams = sorted({f for f, _ in d["attack"]})
    out = {"n_train": len(d["train"]), "n_val_normal": len(d["val"]), "n_attack": len(pos), "detectors": {}}
    for name, m in detectors():
        t0 = time.perf_counter()
        m.fit(d["train"])
        if hasattr(m, "score_many"):
            neg, sp = [float(x) for x in m.score_many(d["val"])], [float(x) for x in m.score_many(pos)]
        else:
            neg, sp = [m.score(t) for t in d["val"]], [m.score(t) for t in pos]
        res = {"auc": round(roc_auc(neg, sp), 4), "seconds": round(time.perf_counter() - t0, 1)}
        for f in FPRS:
            tpr, real = tpr_at_fpr(neg, sp, f)
            res[f"tpr@{f:g}"] = round(tpr, 4)
            res[f"fpr_real@{f:g}"] = round(real, 4)
        # per-family detection at the 5% FPR operating point
        thr = sorted(neg)[int(0.95 * (len(neg) - 1))]
        res["family_tpr@0.05"] = {fam: round(sum(s > thr for (ff, _), s in zip(d["attack"], sp) if ff == fam)
                                              / sum(1 for ff, _ in d["attack"] if ff == fam), 3) for fam in fams}
        if roc:
            res["_roc"] = _roc_points(neg, sp)
        out["detectors"][name] = res
    return out


def _roc_points(neg, pos, n=200):
    thr = sorted(set(neg + pos))
    step = max(1, len(thr) // n)
    pts = []
    for t in thr[::step] + [float("inf")]:
        pts.append((sum(x >= t for x in neg) / len(neg), sum(x >= t for x in pos) / len(pos)))
    return sorted(pts)


def markdown(r: dict) -> str:
    lines = [f"### Syscall anomaly detection on ADFA-LD ({r['n_train']} train / {r['n_val_normal']} normal test / "
             f"{r['n_attack']} attack traces)", "",
             "| detector | ROC-AUC | TPR @1% FPR | TPR @5% FPR | TPR @15% FPR |", "|---|---:|---:|---:|---:|"]
    for n, d in r["detectors"].items():
        lines.append(f"| {n} | {d['auc']:.3f} | {d['tpr@0.01']:.3f} | {d['tpr@0.05']:.3f} | {d['tpr@0.15']:.3f} |")
    lines += ["", "Per attack family, TPR at 5% FPR:", "",
              "| detector | " + " | ".join(next(iter(r["detectors"].values()))["family_tpr@0.05"]) + " |",
              "|---|" + "---:|" * len(next(iter(r["detectors"].values()))["family_tpr@0.05"])]
    for n, d in r["detectors"].items():
        lines.append(f"| {n} | " + " | ".join(f"{v:.2f}" for v in d["family_tpr@0.05"].values()) + " |")
    return "\n".join(lines)
