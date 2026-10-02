"""Syscall anomaly models on container traces recorded in GitHub Actions (scripts/record_syscalls.sh).

LID-DS and CB-DS are only distributed through interactive file-hosting links, so this is the
container-native substitute: each of R independent recording runs (separate runners, a different
random order of routine operations per seed) gives ~120 normal traces and 40 traces of benign
attack-shaped actions. Protocol: leave-one-run-out. Fit on the *normal* traces of the other runs only,
score the held-out run's normal and attack traces. Report per-fold AUC and TPR at 1% FPR, their mean,
and a 95% percentile-bootstrap CI over the pooled held-out scores.

    python -m stratum.bench.container_syscalls <dir with run-*/ folders> [results-dir]
"""
from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

from ..syscall import NgramNovelty, Stide, bootstrap_ci, roc_auc, tpr_at_fpr_interp


def detectors():
    yield "STIDE n=6 (baseline)", lambda: Stide(6)
    yield "STIDE n=3", lambda: Stide(3)
    yield "STRATUM n-gram novelty n=3", lambda: NgramNovelty(3)
    yield "STRATUM n-gram novelty n=5", lambda: NgramNovelty(5)


def load(root: str | Path) -> dict[str, dict[str, list[list[int]]]]:
    """{run: {"normal": [...], "attack": [...]}} with syscall names mapped to ints (shared vocabulary)."""
    vocab: dict[str, int] = {}
    runs: dict[str, dict[str, list[list[int]]]] = {}
    for d in sorted(p for p in Path(root).glob("run-*") if p.is_dir()):
        r = runs.setdefault(d.name, {"normal": [], "attack": []})
        for f in sorted(d.rglob("*.txt")):
            names = f.read_text(encoding="utf-8").split()
            if not names:
                continue
            seq = [vocab.setdefault(s, len(vocab)) for s in names]
            r["normal" if f.name.startswith("normal") else "attack"].append(seq)
    return runs


def evaluate(runs: dict[str, dict[str, list[list[int]]]]) -> dict:
    out: dict = {"runs": len(runs), "traces": {k: {c: len(v[c]) for c in v} for k, v in runs.items()},
                 "protocol": "leave-one-run-out; fit on normal traces of the other runs", "detectors": {}}
    for name, mk in detectors():
        folds, pn, pa = [], [], []
        for held in runs:
            m = mk().fit(t for k, v in runs.items() if k != held for t in v["normal"])
            neg = [m.score(t) for t in runs[held]["normal"]]
            pos = [m.score(t) for t in runs[held]["attack"]]
            folds.append({"run": held, "auc": roc_auc(neg, pos), "tpr@0.01": tpr_at_fpr_interp(neg, pos, 0.01)})
            pn += neg
            pa += pos
        aucs = [f["auc"] for f in folds]
        tprs = [f["tpr@0.01"] for f in folds]
        out["detectors"][name] = {
            "folds": folds, "auc_mean": statistics.fmean(aucs), "auc_min": min(aucs), "auc_max": max(aucs),
            "tpr@0.01_mean": statistics.fmean(tprs),
            "auc_pooled_ci95": list(bootstrap_ci(pn, pa, roc_auc)),
            "tpr@0.01_pooled_ci95": list(bootstrap_ci(pn, pa, lambda n, p: tpr_at_fpr_interp(n, p, 0.01))),
        }
    return out


def markdown(r: dict) -> str:
    n = sum(v["normal"] for v in r["traces"].values())
    a = sum(v["attack"] for v in r["traces"].values())
    rows = [f"### Container syscall traces recorded in CI ({r['runs']} runs, {n} normal / {a} attack-shaped)", "",
            f"Protocol: {r['protocol']}. Attack traces are benign, scripted actions, so this measures separation "
            "of a small, known action set, not detection of real intrusions.", "",
            "| Detector | AUC mean (min-max over runs) | AUC pooled 95% CI | TPR at 1% FPR mean | pooled 95% CI |",
            "|---|---:|---:|---:|---:|"]
    for k, v in r["detectors"].items():
        c, t = v["auc_pooled_ci95"], v["tpr@0.01_pooled_ci95"]
        rows.append(f"| {k} | {v['auc_mean']:.3f} ({v['auc_min']:.3f}-{v['auc_max']:.3f}) | "
                    f"{c[0]:.3f}-{c[1]:.3f} | {v['tpr@0.01_mean']:.3f} | {t[0]:.3f}-{t[1]:.3f} |")
    return "\n".join(rows)


def main(argv: list[str]) -> None:
    r = evaluate(load(argv[0]))
    out = Path(argv[1] if len(argv) > 1 else "results")
    out.mkdir(parents=True, exist_ok=True)
    (out / "container_syscalls.json").write_text(json.dumps(r, indent=1) + "\n", encoding="utf-8")
    md = markdown(r)
    (out / "container_syscalls.md").write_text(md + "\n", encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main(sys.argv[1:])
