"""Runtime case study on real Tetragon events: STRATUM rules vs the v0.1 rule set.

Labels are our per-file annotation (benchmarks/labels/tetragon.json) of the
public Tetragon sample events. n is small (tens of events): this is a
case study of coverage on a real attack chain, not a statistical benchmark.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ..detect import legacy_rule_detect, rule_detect
from ..ingest import tetragon_events
from .metrics import confusion, wilson

LABELS = Path(__file__).resolve().parents[2] / "benchmarks" / "labels" / "tetragon.json"


def run(root: Path) -> dict:
    labels = {k: v for k, v in json.loads(LABELS.read_text()).items() if not k.startswith("_")}
    evs = [e for e in tetragon_events(sorted((root / "tetragon").rglob("*.json"))) if e.source in labels]
    y = [labels[e.source] == "attack" for e in evs]
    ours = [rule_detect(e) for e in evs]
    legacy = [legacy_rule_detect(e) for e in evs]
    rows = [{"source": e.source, "kind": e.kind, "pod": f"{e.namespace}/{e.pod}" if e.namespace else e.pod,
             "process": e.process.rsplit("/", 1)[-1], "label": labels[e.source],
             "stratum": d.rule if d else "", "control": d.control_id if d else "",
             "v0.1": ld.rule if ld else "", "image_digest": e.image_digest[:19]}
            for e, d, ld in zip(evs, ours, legacy)]
    traced = [e for e, d in zip(evs, ours) if d and e.image_digest]

    def scored(pred):
        c = confusion(y, pred)
        c["precision_wilson95"] = wilson(c["tp"], c["tp"] + c["fp"])
        c["recall_wilson95"] = wilson(c["tp"], c["tp"] + c["fn"])
        return c
    return {
        "events": len(evs), "attack_events": sum(y),
        "stratum": scored([d is not None for d in ours]),
        "legacy_v0.1": scored([d is not None for d in legacy]),
        "rules_fired": dict(Counter(d.rule for d in ours if d)),
        "detections_traced_to_image_digest": f"{len(traced)}/{sum(d is not None for d in ours)}",
        "rows": rows,
    }


def _ci(c: dict, k: str) -> str:
    w = c.get(f"{k}_wilson95")
    return f" [{w[0]:.2f}, {w[1]:.2f}]" if w else ""


def markdown(r: dict) -> str:
    s, lg = r["stratum"], r["legacy_v0.1"]
    lines = [f"### Runtime rules on real Tetragon events ({r['events']} security-relevant events, "
             f"{r['attack_events']} labelled attack)", "",
             "In-sample: the rules were written with these events in view. Brackets: Wilson 95% CIs.", "",
             "| rule set | TP | FP | FN | precision | recall |", "|---|---:|---:|---:|---:|---:|",
             f"| STRATUM v0.2 (9 rules) | {s['tp']} | {s['fp']} | {s['fn']} | {s['precision']:.2f}{_ci(s, 'precision')} | "
             f"{s['recall']:.2f}{_ci(s, 'recall')} |",
             f"| v0.1 rules (shell / SA token / egress) | {lg['tp']} | {lg['fp']} | {lg['fn']} | "
             f"{lg['precision']:.2f}{_ci(lg, 'precision')} | {lg['recall']:.2f}{_ci(lg, 'recall')} |", "",
             f"Detections traced to the exact running image digest: {r['detections_traced_to_image_digest']}.", "",
             "| event file | pod | process | label | STRATUM rule -> control | v0.1 |", "|---|---|---|---|---|---|"]
    for x in r["rows"]:
        lines.append(f"| {x['source']} | {x['pod']} | {x['process']} | {x['label']} | "
                     f"{(x['stratum'] + ' -> ' + x['control']) if x['stratum'] else '-'} | {x['v0.1'] or '-'} |")
    return "\n".join(lines)
