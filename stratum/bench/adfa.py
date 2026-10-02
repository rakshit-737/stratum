"""Runtime anomaly model on ADFA-LD: STIDE baseline vs STRATUM n-gram novelty (+ optional IForest).

Protocol (standard for ADFA-LD): fit on Training_Data_Master (833 normal
traces), score Validation_Data_Master (4,372 normal) and Attack_Data_Master
(746 attack traces, 6 families). No attack data is used for fitting or for
choosing hyper-parameters; all configured variants are reported.
"""
from __future__ import annotations

import time
from pathlib import Path

from ..syscall import (
    NgramIsolationForest,
    NgramNovelty,
    Stide,
    bootstrap_ci,
    fpr_at_tpr,
    load_adfa,
    paired_bootstrap_diff,
    roc_auc,
    tpr_at_fpr,
    tpr_at_fpr_interp,
)

FPRS = (0.01, 0.05, 0.15)
N_BOOT = 500
IFOREST_SEEDS = (0, 1, 2, 3, 4)
# Published ADFA-LD operating points (false-alarm rate at 90% detection), as summarised by
# Kim et al. 2016 (arXiv:1611.01726, Sec. 3.2, p. 8) from Creech & Hu 2014 (IEEE Trans. Computers 63(4)).
PUBLISHED_FAR_AT_90 = {"STIDE (Creech & Hu 2014, via Kim et al. 2016)": 0.23,
                       "HMM (Creech & Hu 2014, via Kim et al. 2016)": 0.42,
                       "ELM, semantic features (Creech & Hu 2014, via Kim et al. 2016)": 0.13}
PAIRS = (("STIDE n=6 (baseline, Forrest 1996)", "STRATUM n-gram novelty n=5", "auc"),
         ("STRATUM n-gram novelty n=3", "STIDE n=3", "tpr@0.01_interp"))


def detectors():
    yield "STIDE n=6 (baseline, Forrest 1996)", Stide(6)
    yield "STIDE n=3", Stide(3)
    yield "STRATUM n-gram novelty n=3", NgramNovelty(3)
    yield "STRATUM n-gram novelty n=5", NgramNovelty(5)
    try:
        import sklearn  # noqa: F401
        yield "Isolation Forest, TF-IDF 1..3-grams", [NgramIsolationForest(3, seed=s) for s in IFOREST_SEEDS]
    except ImportError:  # pragma: no cover
        return


def _scores(m, train, val, pos):
    m.fit(train)
    if hasattr(m, "score_many"):
        return [float(x) for x in m.score_many(val)], [float(x) for x in m.score_many(pos)]
    return [m.score(t) for t in val], [m.score(t) for t in pos]


def _ci(neg, sp, n_boot):
    out = {"auc_ci95": [round(x, 4) for x in bootstrap_ci(neg, sp, roc_auc, n_boot)]}
    out["far@dr0.9_ci95"] = [round(x, 4) for x in bootstrap_ci(neg, sp, lambda a, b: fpr_at_tpr(a, b, 0.9), n_boot)]
    out["tpr@0.01_interp_ci95"] = [round(x, 4) for x in bootstrap_ci(neg, sp, lambda a, b: tpr_at_fpr_interp(a, b, 0.01), n_boot)]
    for f in (0.01, 0.05):
        out[f"tpr@{f:g}_ci95"] = [round(x, 4) for x in bootstrap_ci(neg, sp, lambda a, b, f=f: tpr_at_fpr(a, b, f)[0], n_boot)]
    return out


def run(root: Path, roc: bool = True, n_boot: int = N_BOOT) -> dict:
    d = load_adfa(root / "adfa")
    pos = [t for _, t in d["attack"]]
    fams = sorted({f for f, _ in d["attack"]})
    out = {"n_train": len(d["train"]), "n_val_normal": len(d["val"]), "n_attack": len(pos), "detectors": {}}
    scores = {}
    for name, m in detectors():
        t0 = time.perf_counter()
        seeds = {}
        if isinstance(m, list):  # stochastic model: one run per seed, report seed 0 plus mean/sd over seeds
            runs = [_scores(mm, d["train"], d["val"], pos) for mm in m]
            aucs = [roc_auc(a, b) for a, b in runs]
            mu = sum(aucs) / len(aucs)
            sd = (sum((a - mu) ** 2 for a in aucs) / max(len(aucs) - 1, 1)) ** 0.5
            seeds = {"seeds": list(IFOREST_SEEDS), "auc_seed_mean": round(mu, 4), "auc_seed_sd": round(sd, 4)}
            neg, sp = runs[0]
        else:
            neg, sp = _scores(m, d["train"], d["val"], pos)
        scores[name] = (neg, sp)
        top = max(neg)
        res = {"auc": round(roc_auc(neg, sp), 4), "seconds": round(time.perf_counter() - t0, 1), **seeds,
               "tpr@0.01_interp": round(tpr_at_fpr_interp(neg, sp, 0.01), 4),
               "far@dr0.9": round(fpr_at_tpr(neg, sp, 0.9), 4),
               "ties_at_max_normal_score": {"normal": sum(x == top for x in neg), "attack": sum(x == top for x in sp)}}
        if n_boot:
            res.update(_ci(neg, sp, n_boot))
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
    stats = {"auc": roc_auc, "tpr@0.01_interp": lambda a, b: tpr_at_fpr_interp(a, b, 0.01)}
    out["paired"] = []
    for a, b, k in PAIRS:
        if a in scores and b in scores and n_boot:
            r = paired_bootstrap_diff(*scores[a], *scores[b], stats[k], n_boot=2 * n_boot)
            out["paired"].append({"a": a, "b": b, "metric": k, "diff": round(r["diff"], 4), "n_boot": r["n_boot"],
                                  "ci95": [round(x, 4) for x in r["ci95"]], "p_boot": round(r["p_boot"], 4)})
    out["published_far@dr0.9"] = PUBLISHED_FAR_AT_90
    out["resplit"] = resplit(d)
    return out


RESPLIT_SEEDS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
T975 = {4: 2.776, 9: 2.262}   # Student t 0.975 quantiles for df = n_seeds - 1


def resplit(d: dict, seeds=RESPLIT_SEEDS) -> dict:
    """Harder check of split luck: pool all 5,205 normals, draw a fresh 833-trace training set per seed,
    test on the remaining normals vs all attacks. Mean AUC with a t-based 95% CI over seeds."""
    import random
    normals = d["train"] + d["val"]
    pos = [t for _, t in d["attack"]]
    out = {}
    for name, make in (("STIDE n=6", lambda: Stide(6)), ("STIDE n=3", lambda: Stide(3)),
                       ("STRATUM n-gram novelty n=3", lambda: NgramNovelty(3)),
                       ("STRATUM n-gram novelty n=5", lambda: NgramNovelty(5))):
        aucs, tprs = [], []
        for sd in seeds:
            idx = list(range(len(normals)))
            random.Random(sd).shuffle(idx)
            tr = [normals[i] for i in idx[:len(d["train"])]]
            te = [normals[i] for i in idx[len(d["train"]):]]
            neg, sp = _scores(make(), tr, te, pos)
            aucs.append(roc_auc(neg, sp))
            tprs.append(tpr_at_fpr_interp(neg, sp, 0.01))
        n = len(aucs)

        n_tr, n_te = len(d["train"]), len(normals) - len(d["train"])

        def stat(xs, n=n, n_tr=n_tr, n_te=n_te):
            # Nadeau & Bengio (2003) corrected resampled t: variance x (1/n + n_test/n_train), because the
            # random training sets overlap; plain t-intervals over re-splits are too narrow.
            mu = sum(xs) / n
            var = sum((x - mu) ** 2 for x in xs) / (n - 1)
            h = T975.get(n - 1, 1.96) * (var * (1 / n + n_te / n_tr)) ** 0.5
            return {"mean": round(mu, 4), "sd": round(var ** 0.5, 4), "min": round(min(xs), 4), "max": round(max(xs), 4),
                    "ci95_corrected": [round(mu - h, 4), round(mu + h, 4)]}
        out[name] = {"auc": stat(aucs), "tpr@0.01_interp": stat(tprs)}
    return {"seeds": list(seeds), "detectors": out}


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
             "95% CIs: stratified percentile bootstrap over test traces (500 resamples, seed 0). "
             "Isolation Forest: seed 0 shown, AUC mean ± sd over seeds 0-4 in the last column.", "",
             "| detector | ROC-AUC [95% CI] | TPR @1% FPR [95% CI] | TPR @5% FPR [95% CI] | TPR @15% FPR | seed AUC mean ± sd |",
             "|---|---:|---:|---:|---:|---:|"]

    def ci(d, k):
        c = d.get(f"{k}_ci95")
        return f" [{c[0]:.3f}, {c[1]:.3f}]" if c else ""
    for n, d in r["detectors"].items():
        sd = f"{d['auc_seed_mean']:.3f} ± {d['auc_seed_sd']:.3f}" if "auc_seed_mean" in d else "deterministic"
        lines.append(f"| {n} | {d['auc']:.3f}{ci(d, 'auc')} | {d['tpr@0.01']:.3f}{ci(d, 'tpr@0.01')} | "
                     f"{d['tpr@0.05']:.3f}{ci(d, 'tpr@0.05')} | {d['tpr@0.15']:.3f} | {sd} |")
    lines += ["", "Per attack family, TPR at 5% FPR:", "",
              "| detector | " + " | ".join(next(iter(r["detectors"].values()))["family_tpr@0.05"]) + " |",
              "|---|" + "---:|" * len(next(iter(r["detectors"].values()))["family_tpr@0.05"])]
    for n, d in r["detectors"].items():
        lines.append(f"| {n} | " + " | ".join(f"{v:.2f}" for v in d["family_tpr@0.05"].values()) + " |")
    lines += ["", "Tie-aware operating points (ROC interpolated across tied scores, i.e. random tie-breaking). "
              "The threshold-based TPR @1% FPR above counts only scores strictly above the 99th normal percentile, "
              "so a detector whose top normal scores tie (STIDE n=6: many traces score exactly 1.0) can show 0 "
              "with a degenerate [0, 0] interval.", "",
              "| detector | TPR @ exactly 1% FPR [95% CI] | false-alarm rate @ 90% detection [95% CI] | "
              "normal / attack traces tied at the max normal score |", "|---|---:|---:|---:|"]
    for n, d in r["detectors"].items():
        if "far@dr0.9" in d:
            t = d.get("ties_at_max_normal_score", {})
            lines.append(f"| {n} | {d['tpr@0.01_interp']:.3f}{ci(d, 'tpr@0.01_interp')} | {d['far@dr0.9']:.3f}{ci(d, 'far@dr0.9')} | "
                         f"{t.get('normal', '-')} / {t.get('attack', '-')} |")
    if r.get("paired"):
        lines += ["", f"Paired, stratified bootstrap of the difference (same resampled traces for both detectors, "
                  f"{r['paired'][0]['n_boot']} resamples):", "",
                  "| A | B | metric | A - B [95% CI] | bootstrap p |", "|---|---|---|---:|---:|"]
        for q in r["paired"]:
            lines.append(f"| {q['a']} | {q['b']} | {q['metric']} | {q['diff']:+.4f} [{q['ci95'][0]:+.4f}, {q['ci95'][1]:+.4f}] "
                         f"| {q['p_boot']:.3f} |")
    if r.get("published_far@dr0.9"):
        lines += ["", "Comparison with published ADFA-LD results (false-alarm rate at 90% detection). The published figures "
                  "are taken from Kim et al. 2016's summary of Creech & Hu 2014 (we could not access the primary's full text); "
                  "ELM uses semantic features and a different decision engine.", "",
                  "| system | FAR @ 90% DR | source |", "|---|---:|---|"]
        for k, v in r["published_far@dr0.9"].items():
            lines.append(f"| {k.split(' (')[0]} | {v:.2f} | published |")
        for n, d in r["detectors"].items():
            if "far@dr0.9" in d and "Isolation" not in n:
                lines.append(f"| {n} | {d['far@dr0.9']:.3f} | this repo |")
    rs = r.get("resplit")
    if rs:
        lines += ["", f"Random re-splits ({len(rs['seeds'])} seeds): pool all normals, draw a fresh {r['n_train']}-trace "
                  "training set per seed, test on the rest. CI = Nadeau-Bengio corrected resampled t.", "",
                  "| detector | AUC mean [corrected 95% CI] | AUC min-max | TPR @1% FPR (interp.) mean [corrected 95% CI] |",
                  "|---|---:|---:|---:|"]
        for n, d in rs["detectors"].items():
            a, t = d["auc"], d["tpr@0.01_interp"]
            ac, tc = a["ci95_corrected"], t["ci95_corrected"]
            lines.append(f"| {n} | {a['mean']:.3f} [{ac[0]:.3f}, {ac[1]:.3f}] | {a['min']:.3f}-{a['max']:.3f} | "
                         f"{t['mean']:.3f} [{tc[0]:.3f}, {tc[1]:.3f}] |")
    return "\n".join(lines)
