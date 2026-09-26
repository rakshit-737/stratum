"""Zero-Trust posture of real open-source install manifests / Helm charts.

No ground truth exists for "is this chart secure", so this reports what the
policy engine finds, per project and per control, plus how many workloads the
v0.1 workload check (privileged / root / hostNetwork) would have caught vs the
full Pod Security Standards evaluation.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..corpus import manifest_index, manifests_dataset
from ..graph import build_graph
from ..policy import CONTROLS, evaluate


def run(root: Path) -> dict:
    idx = manifest_index(root)
    projects, totals = {}, Counter()
    all_levels, legacy_hits, pss_hits, n_wl = Counter(), 0, 0, 0
    risks = Counter()
    for name, meta in idx.items():
        ds = manifests_dataset(root, [name])
        fs = evaluate(ds, build_graph(ds))
        by = Counter(f.control_id for f in fs)
        lv = Counter(w.pss_level for w in ds.workloads)
        totals.update(by)
        all_levels.update(lv)
        n_wl += len(ds.workloads)
        legacy_hits += sum(w.privileged or w.run_as_root or w.host_network for w in ds.workloads)
        pss_hits += sum(w.pss_level != "restricted" for w in ds.workloads)
        for sa in ds.service_accounts:
            risks.update(r.split(" cluster-wide")[0].split(" in ")[0] for r in sa.rbac_risks)
        projects[name] = {"version": meta["version"], "category": meta["category"], "workloads": len(ds.workloads),
                          "pss": dict(lv), "findings": dict(sorted(by.items())),
                          "check_violations": dict(Counter(k for w in ds.workloads for k in w.pss_violations))}
    return {"projects": projects, "n_projects": len(projects), "n_workloads": n_wl,
            "pss_levels": dict(all_levels), "findings_by_control": dict(totals.most_common()),
            "workload_hardening_flagged": {"v0.1 heuristic": legacy_hits, "PSS restricted (v0.2)": pss_hits},
            "rbac_risks": dict(risks.most_common())}


def markdown(r: dict) -> str:
    lv = r["pss_levels"]
    lines = [f"### Posture of {r['n_projects']} real projects ({r['n_workloads']} workloads)", "",
             f"Pod Security level reached: restricted **{lv.get('restricted', 0)}**, baseline "
             f"**{lv.get('baseline', 0)}**, privileged **{lv.get('privileged', 0)}**.  ",
             "Workloads needing hardening flagged by the v0.1 heuristic vs full PSS: "
             + ", ".join(f"{k} = {v}" for k, v in r["workload_hardening_flagged"].items()) + ".", "",
             "| project | version | workloads | PSS (R/B/P) | findings by control |", "|---|---|---:|---|---|"]
    for n, p in sorted(r["projects"].items()):
        s = p["pss"]
        f = ", ".join(f"{k}:{v}" for k, v in p["findings"].items())
        lines.append(f"| {n} | {p['version']} | {p['workloads']} | {s.get('restricted', 0)}/{s.get('baseline', 0)}/"
                     f"{s.get('privileged', 0)} | {f} |")
    lines += ["", "| control | title | findings |", "|---|---|---:|"]
    for c, v in r["findings_by_control"].items():
        lines.append(f"| {c} | {CONTROLS[c].title} | {v} |")
    return "\n".join(lines)
