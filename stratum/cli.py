"""STRATUM command-line interface."""
from __future__ import annotations

import argparse
import json
import sys

from .dataset import Dataset
from .incident import analyze, metrics, replay_with_policy
from .models import to_dict
from .synth import generate


def _load(path: str | None, seed: int) -> Dataset:
    return Dataset.load(path) if path else generate(seed)


def _print_incident(inc) -> None:
    d = inc.detection
    print(f"\n[{inc.id}] {d.severity.upper()} {d.rule}: {d.reason}")
    print(f"  pod        : {d.event.namespace}/{d.event.pod}")
    print(f"  trace      : {' -> '.join(inc.chain)}")
    print(f"  root commit: {inc.root_commit or 'NONE (image not from trusted pipeline)'}"
          + (f"  author={inc.author} PR#{inc.pr}" if inc.author else ""))
    for f in inc.failed_controls[:4]:
        print(f"  failed ctl : {f.control_id} [{f.severity}] {f.message}")
    print(f"  blast radius: {', '.join(inc.blast_radius) or '-'}")
    print(f"  fix        : {inc.recommendations[0] if inc.recommendations else '-'}")


def cmd_generate(a) -> int:
    generate(a.seed).save(a.out)
    print(f"wrote {a.out}")
    return 0


def cmd_analyze(a) -> int:
    ds = _load(a.data, a.seed)
    res = analyze(ds)
    if a.json:
        print(json.dumps({"findings": [to_dict(f) for f in res.findings],
                          "incidents": [to_dict(i) for i in res.incidents],
                          "metrics": metrics(ds, res)}, indent=2))
        return 0
    g = res.graph
    print(f"graph: {len(g.nodes)} nodes, {g.edge_count()} edges")
    print(f"posture findings: {len(res.findings)}")
    for f in res.findings:
        print(f"  {f.control_id:10} {f.severity:8} {f.message}")
    print(f"incidents: {len(res.incidents)}")
    for inc in res.incidents:
        _print_incident(inc)
    print("\nmetrics:", json.dumps(metrics(ds, res)))
    return 0


def cmd_trace(a) -> int:
    ds = _load(a.data, a.seed)
    g = analyze(ds).graph
    ns, _, pod = a.pod.partition("/")
    print(" -> ".join(g.trace_upstream(f"pod:{ns}/{pod}")))
    return 0


def cmd_blast(a) -> int:
    ds = _load(a.data, a.seed)
    g = analyze(ds).graph
    for w in g.blast_radius(f"base:{a.base}"):
        print(w)
    return 0


def cmd_prevent(a) -> int:
    ds = _load(a.data, a.seed)
    r = replay_with_policy(ds, a.namespace)
    print(r.pop("policy_yaml"))
    print(json.dumps(r))
    return 0


def cmd_demo(a) -> int:
    ds = generate(a.seed)
    print("== STRATUM demo (synthetic cluster, no live K8s) ==")
    cmd_analyze(argparse.Namespace(data=None, seed=a.seed, json=False))
    print("\n== Scenario 4: policy-as-prevention on namespace 'shop' ==")
    r = replay_with_policy(ds, "shop")
    print(r.pop("policy_yaml"))
    print(json.dumps(r))
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="stratum", description="code-to-runtime lifecycle defense (mini-CNAPP)")
    p.add_argument("--seed", type=int, default=7)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("generate"); s.add_argument("--out", default="scenario.json"); s.set_defaults(fn=cmd_generate)
    s = sub.add_parser("analyze"); s.add_argument("--data"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_analyze)
    s = sub.add_parser("trace"); s.add_argument("pod", help="namespace/pod"); s.add_argument("--data"); s.set_defaults(fn=cmd_trace)
    s = sub.add_parser("blast"); s.add_argument("base", help="base image ref"); s.add_argument("--data"); s.set_defaults(fn=cmd_blast)
    s = sub.add_parser("prevent"); s.add_argument("namespace"); s.add_argument("--data"); s.set_defaults(fn=cmd_prevent)
    s = sub.add_parser("demo"); s.set_defaults(fn=cmd_demo)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
