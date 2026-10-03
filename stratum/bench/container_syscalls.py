"""Syscall anomaly models on container traces recorded in GitHub Actions (scripts/record_syscalls.sh).

LID-DS and CB-DS are only distributed through interactive file-hosting links, so this is the
container-native substitute: each of R independent recording runs (separate runners, seed = run number,
which sets the random order of routine operations) gives 120 ``strace -f`` traces (syscall names only)
of 9 routine operations and 8 traces each of 5 benign attack-shaped actions. Protocol: leave-one-run-out.
Fit on the *normal* traces of the other runs only, score the held-out run's normal and attack traces.

The traces are repeats of a few scripted commands, so trace-level resampling would treat 800 near-copies
as independent. Reported instead: per-fold AUC and TPR at 1% FPR (mean, min-max over runs); a cluster
bootstrap that resamples whole clusters (attack: action type x run; normal: identical syscall sequence x
run); and, per attack action type, whether every one of its traces scores above every normal trace of its
fold ("separated"). The honest unit is the number of action types a detector separates, with a Wilson CI.

    python -m stratum.bench.container_syscalls <dir with run-*/ folders> [results-dir] [--traces-run URL]
"""
from __future__ import annotations

import argparse
import json
import random
import re
import statistics
from pathlib import Path

from ..syscall import NgramNovelty, Stide, roc_auc, tpr_at_fpr_interp
from .metrics import wilson

# scripts/record_syscalls.sh ATTACK[] in order (file names attack<i>-<n>.txt)
ACTIONS = ["shell + recon (id, uname, read /etc/passwd)", "cat the dummy service-account token",
           "nc to the in-cluster sink", "fetch a dummy script and chmod +x it", "find token files + ps"]
N_BOOT = 1000


def detectors():
    yield "STIDE n=6 (baseline)", lambda: Stide(6)
    yield "STIDE n=3", lambda: Stide(3)
    yield "STRATUM n-gram novelty n=3", lambda: NgramNovelty(3)
    yield "STRATUM n-gram novelty n=5", lambda: NgramNovelty(5)


def load(root: str | Path) -> dict[str, dict[str, list]]:
    """{run: {"normal": [...], "attack": [...], "attack_type": [...]}}; syscall names mapped to ints."""
    vocab: dict[str, int] = {}
    runs: dict[str, dict[str, list]] = {}
    for d in sorted((p for p in Path(root).glob("run-*") if p.is_dir()), key=lambda p: _num(p.name)):
        r = runs.setdefault(d.name, {"normal": [], "attack": [], "attack_type": []})
        for f in sorted(d.rglob("*.txt")):
            names = f.read_text(encoding="utf-8").split()
            if not names:
                continue
            seq = [vocab.setdefault(s, len(vocab)) for s in names]
            m = re.match(r"attack(\d+)-", f.name)
            if m:
                r["attack"].append(seq)
                r["attack_type"].append(int(m.group(1)))
            else:
                r["normal"].append(seq)
    return runs


def _num(name: str) -> int:
    m = re.search(r"(\d+)$", name)
    return int(m.group(1)) if m else 0


def _cluster_ci(neg_cl: list[list[float]], pos_cl: list[list[float]], stat, n_boot: int = N_BOOT,
                seed: int = 0) -> list[float]:
    """Percentile bootstrap that resamples whole clusters of normal and attack scores (stratified)."""
    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        bn = [x for _ in neg_cl for x in neg_cl[rng.randrange(len(neg_cl))]]
        bp = [x for _ in pos_cl for x in pos_cl[rng.randrange(len(pos_cl))]]
        vals.append(stat(bn, bp))
    vals.sort()
    return [round(vals[int(0.025 * (n_boot - 1))], 4), round(vals[int(0.975 * (n_boot - 1))], 4)]


def evaluate(runs: dict[str, dict[str, list]], n_boot: int = N_BOOT) -> dict:
    types = sorted({t for v in runs.values() for t in v.get("attack_type", [])})
    out: dict = {"runs": len(runs), "seeds": [_num(k) for k in runs],
                 "traces": {k: {c: len(v[c]) for c in ("normal", "attack")} for k, v in runs.items()},
                 "distinct_normal_sequences": len({tuple(t) for v in runs.values() for t in v["normal"]}),
                 "attack_actions": {str(t): ACTIONS[t] if t < len(ACTIONS) else f"action {t}" for t in types},
                 "protocol": "leave-one-run-out; fit on normal traces of the other runs", "detectors": {}}
    for name, mk in detectors():
        folds, neg_cl, pos_cl = [], [], []
        sep = {t: True for t in types}
        type_auc: dict[int, list[float]] = {t: [] for t in types}
        for held in runs:
            m = mk().fit(t for k, v in runs.items() if k != held for t in v["normal"])
            neg = [m.score(t) for t in runs[held]["normal"]]
            pos = [m.score(t) for t in runs[held]["attack"]]
            folds.append({"run": held, "auc": roc_auc(neg, pos), "tpr@0.01": tpr_at_fpr_interp(neg, pos, 0.01)})
            groups: dict[tuple, list[float]] = {}
            for t, s in zip(runs[held]["normal"], neg):
                groups.setdefault(tuple(t), []).append(s)
            neg_cl += list(groups.values())
            top = max(neg)
            for t in types:
                ps = [s for s, k in zip(pos, runs[held]["attack_type"]) if k == t]
                if ps:
                    pos_cl.append(ps)
                    sep[t] = sep[t] and min(ps) > top
                    type_auc[t].append(roc_auc(neg, ps))
        aucs = [f["auc"] for f in folds]
        tprs = [f["tpr@0.01"] for f in folds]
        k = sum(sep.values())
        out["detectors"][name] = {
            "folds": folds, "auc_mean": statistics.fmean(aucs), "auc_min": min(aucs), "auc_max": max(aucs),
            "tpr@0.01_mean": statistics.fmean(tprs), "tpr@0.01_min": min(tprs), "tpr@0.01_max": max(tprs),
            "auc_cluster_ci95": _cluster_ci(neg_cl, pos_cl, roc_auc, n_boot),
            "tpr@0.01_cluster_ci95": _cluster_ci(neg_cl, pos_cl, lambda a, b: tpr_at_fpr_interp(a, b, 0.01), n_boot),
            "clusters": {"normal": len(neg_cl), "attack": len(pos_cl)},
            "per_action": {str(t): {"auc_mean": round(statistics.fmean(type_auc[t]), 4), "separated_in_every_fold": sep[t]}
                           for t in types},
            "actions_separated": k, "actions": len(types), "actions_separated_wilson95": wilson(k, len(types)),
        }
    return out


def markdown(r: dict) -> str:
    n = sum(v["normal"] for v in r["traces"].values())
    a = sum(v["attack"] for v in r["traces"].values())
    acts = r.get("attack_actions") or {}
    rows = [f"### Container syscall traces recorded in CI ({r['runs']} runs, seeds {r.get('seeds')}, {n} normal / {a} "
            "attack-shaped)", "",
            f"Protocol: {r['protocol']}. Traces are `strace -f` syscall names from `docker exec` into a container on an "
            "internal Docker network on the runner (not eBPF/Tetragon). Attack traces are benign, scripted actions, so "
            "this measures separation of a small, known action set, not detection of real intrusions. The "
            f"{n} normal traces contain {r.get('distinct_normal_sequences', '?')} distinct sequences; intervals resample "
            "whole clusters (attack: action type x run; normal: identical sequence x run), not traces.", "",
            "| Detector | Action types separated (Wilson 95% CI) | AUC mean (min-max over runs) | AUC cluster 95% CI | "
            "TPR at 1% FPR mean (min-max) | cluster 95% CI |", "|---|---:|---:|---:|---:|---:|"]
    for k, v in r["detectors"].items():
        c, t = v.get("auc_cluster_ci95") or v.get("auc_pooled_ci95"), v.get("tpr@0.01_cluster_ci95") or v.get("tpr@0.01_pooled_ci95")
        w = v.get("actions_separated_wilson95")
        sep = f"{v['actions_separated']}/{v['actions']} [{w[0]:.2f}, {w[1]:.2f}]" if w else "-"
        rows.append(f"| {k} | {sep} | {v['auc_mean']:.3f} ({v['auc_min']:.3f}-{v['auc_max']:.3f}) | "
                    f"{c[0]:.3f}-{c[1]:.3f} | {v['tpr@0.01_mean']:.3f} ({v.get('tpr@0.01_min', v['tpr@0.01_mean']):.3f}-"
                    f"{v.get('tpr@0.01_max', v['tpr@0.01_mean']):.3f}) | {t[0]:.3f}-{t[1]:.3f} |")
    first = next(iter(r["detectors"].values()))
    if first.get("per_action"):
        rows += ["", "Per attack action, AUC against the fold's normal traces (mean over runs); "
                 "a dagger marks an action separated from every normal trace in every fold:", "",
                 "| Detector | " + " | ".join(acts.get(t, t) for t in first["per_action"]) + " |",
                 "|---|" + "---:|" * len(first["per_action"])]
        for k, v in r["detectors"].items():
            rows.append(f"| {k} | " + " | ".join(f"{x['auc_mean']:.3f}{' †' if x['separated_in_every_fold'] else ''}"
                                                 for x in v["per_action"].values()) + " |")
    prov = r.get("provenance") or {}
    src = [f"traces recorded by {prov['traces_run']}" if prov.get("traces_run") else "",
           f"evaluated by {prov['source_run']}" if prov.get("source_run") else "evaluated locally",
           f"at commit `{(prov.get('commit') or '?')[:7]}`" if prov.get("commit") else ""]
    rows += ["", "Source: " + ", ".join(x for x in src if x) + "."]
    return "\n".join(rows)


def main(argv: list[str] | None = None) -> None:
    from .meta import provenance
    ap = argparse.ArgumentParser(prog="python -m stratum.bench.container_syscalls")
    ap.add_argument("traces", help="directory holding run-*/ folders of *.txt traces")
    ap.add_argument("out", nargs="?", default="results", help="results directory (default results/)")
    ap.add_argument("--traces-run", default="", help="URL of the CI run that recorded the traces (default: this run)")
    a = ap.parse_args(argv)
    r = evaluate(load(a.traces))
    prov = provenance()
    prov["traces_run"] = a.traces_run or prov.get("source_run")
    r["provenance"] = prov
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "container_syscalls.json").write_text(json.dumps(r, indent=1) + "\n", encoding="utf-8")
    md = markdown(r)
    (out / "container_syscalls.md").write_text(md + "\n", encoding="utf-8")
    print(md)


if __name__ == "__main__":
    main()
