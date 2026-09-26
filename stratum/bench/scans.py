"""Image scan results (Trivy) joined with CISA KEV and the lifecycle graph (blast radius)."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ..graph import build_graph
from ..realdata import real_dataset

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def run(root: Path) -> dict:
    ds = real_dataset(root, with_events=False)
    reps = ds.image_reports
    idx_p = root / "scans" / "index.json"
    idx = json.loads(idx_p.read_text()) if idx_p.exists() else {}
    g = build_graph(ds)
    sev = Counter()
    for r in reps:
        sev.update(r.vulns)
    kev = Counter(c for r in reps for c in r.kev)
    oses = Counter(r.os or "none (distroless/static)" for r in reps)
    bases = sorted(((b, g.blast_radius(b)) for b in g.of_type("base_image")), key=lambda x: -len(x[1]))
    return {
        "images_scanned": len(reps), "skipped_budget": len(idx.get("skipped", [])),
        "failed": len(idx.get("failed", [])),
        "vulns_by_severity": {s: sev.get(s, 0) for s in SEVS},
        "images_with_critical": sum(bool(r.critical) for r in reps),
        "images_with_kev": sum(bool(r.kev) for r in reps), "kev_cves": dict(kev.most_common()),
        "images_with_shell": sum(bool(r.shells) for r in reps),
        "base_os": dict(oses.most_common()),
        "blast_radius_by_base": [{"base": b, "workloads": len(w), "examples": w[:6]} for b, w in bases[:10]],
        "per_image": sorted(({"ref": r.ref, "os": r.os, "packages": r.packages, **{s: r.vulns.get(s, 0) for s in SEVS},
                              "kev": r.kev, "shells": r.shells} for r in reps), key=lambda x: -x["CRITICAL"]),
    }


def markdown(r: dict) -> str:
    v = r["vulns_by_severity"]
    lines = [f"### Trivy scans of {r['images_scanned']} real images (+ CISA KEV join)", "",
             "| critical | high | medium | low | images w/ critical | images w/ KEV CVE | images shipping a shell |",
             "|---:|---:|---:|---:|---:|---:|---:|",
             f"| {v['CRITICAL']} | {v['HIGH']} | {v['MEDIUM']} | {v['LOW']} | {r['images_with_critical']} | "
             f"{r['images_with_kev']} | {r['images_with_shell']} |", "",
             "Blast radius by base OS release as reported by Trivy (workloads whose image is built on it; grouped by OS family + version, not by layer digest):", "",
             "| base | workloads | examples |", "|---|---:|---|"]
    for b in r["blast_radius_by_base"]:
        lines.append(f"| `{b['base']}` | {b['workloads']} | {', '.join(x.split(':', 1)[1] for x in b['examples'])} |")
    if r["kev_cves"]:
        lines += ["", "KEV-listed CVEs present: " + ", ".join(f"{c} ({n})" for c, n in r["kev_cves"].items())]
    return "\n".join(lines)
