"""Policy-engine conformance: STRATUM PSS checks vs the upstream PSA fixtures.

Ground truth = kubernetes/pod-security-admission test/testdata/<level>/<version>/{pass,fail}.
Baseline = the v0.1 MVP heuristic (privileged / root / hostNetwork).
"""
from __future__ import annotations

from pathlib import Path

import yaml

from ..pss import evaluate_pod, legacy_check
from .metrics import confusion

VERSION = "v1.37"


def fixtures(root: Path, level: str, version: str = VERSION):
    d = root / "pss" / "testdata" / level / version
    for exp in ("pass", "fail"):
        for f in sorted((d / exp).glob("*.yaml")):
            yield f, exp == "fail", f.stem.rstrip("0123456789")


def run(root: Path) -> dict:
    out: dict = {"version": VERSION, "levels": {}}
    for level in ("baseline", "restricted"):
        y, ours, legacy, attributed, n_fail = [], [], [], 0, 0
        per_check: dict[str, dict] = {}
        misses = []
        for f, should_fail, check in fixtures(root, level):
            pod = yaml.safe_load(f.read_text())
            v = evaluate_pod(pod, level)
            y.append(should_fail)
            ours.append(bool(v))
            legacy.append(legacy_check(pod))
            if should_fail:
                n_fail += 1
                attributed += check in v
                pc = per_check.setdefault(check, {"fixtures": 0, "stratum": 0, "legacy": 0})
                pc["fixtures"] += 1
                pc["stratum"] += bool(v)
                pc["legacy"] += legacy[-1]
            if bool(v) != should_fail:
                misses.append(f.name)
        out["levels"][level] = {
            "stratum": confusion(y, ours), "legacy_mvp": confusion(y, legacy),
            "check_attribution": round(attributed / n_fail, 4) if n_fail else 0.0,
            "per_check": dict(sorted(per_check.items())), "misclassified": misses,
        }
    return out


def markdown(r: dict) -> str:
    lines = [f"### Pod Security Standards conformance (upstream PSA fixtures, {r['version']})", "",
             "| level | engine | fixtures | precision | recall | F1 | accuracy | FP | FN |",
             "|---|---|---:|---:|---:|---:|---:|---:|---:|"]
    for lvl, d in r["levels"].items():
        for name, key in (("STRATUM", "stratum"), ("v0.1 heuristic (baseline)", "legacy_mvp")):
            m = d[key]
            lines.append(f"| {lvl} | {name} | {m['n']} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} "
                         f"| {m['accuracy']:.3f} | {m['fp']} | {m['fn']} |")
    lines += ["", "Check attribution (the violated check named in the fixture is among the checks STRATUM "
              "reports): " + ", ".join(f"{k} {v['check_attribution']:.0%}" for k, v in r["levels"].items())]
    return "\n".join(lines)
