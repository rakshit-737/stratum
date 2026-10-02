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
    if path == "real":
        from .realdata import real_dataset
        return real_dataset()
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


def cmd_collect(a) -> int:
    from .k8s import collect_files
    ds = collect_files(a.files, source=a.source, default_ns=a.namespace)
    if a.tetragon:
        from .ingest import runtime_inventory, tetragon_events
        ds.events = tetragon_events(a.tetragon)
        wl, imgs = runtime_inventory(ds.events, {(w.namespace, p) for w in ds.workloads for p in w.pods})
        ds.workloads += wl
        ds.images += imgs
    ds.save(a.out)
    print(f"wrote {a.out}: {len(ds.workloads)} workloads, {len(ds.service_accounts)} service accounts, "
          f"{len(ds.network_policies)} network policies, {len(ds.events)} events")
    return 0


def cmd_pss(a) -> int:
    from .k8s import WORKLOAD_KINDS, load_docs, pod_template
    from .pss import evaluate_pod, highest_level
    rc = 0
    for d in load_docs(a.files):
        if d.get("kind") not in WORKLOAD_KINDS or (pod := pod_template(d)) is None:
            continue
        name = f"{d['kind']}/{(d.get('metadata') or {}).get('name')}"
        v = evaluate_pod(pod, a.level)
        print(f"{highest_level(pod):10} {name}")
        for cid, msgs in v.items():
            print(f"    {cid}: {'; '.join(msgs)}")
        rc |= bool(v)
    return int(rc) if a.strict else 0


def cmd_export(a) -> int:
    ds = _load(a.data, a.seed)
    res = analyze(ds)
    if a.format == "cypher":
        from .graph import attach_findings
        from .neo4j import to_cypher
        text = to_cypher(attach_findings(res.graph, res.findings))
    elif a.format == "rego-input":
        from .opa import rego_input
        text = json.dumps(rego_input(ds), indent=1)
    else:
        text = ds.to_json()
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {a.out}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_opa_check(a) -> int:
    from .opa import diff
    d = diff(_load(a.data, a.seed))
    print(json.dumps(d, indent=1))
    return 0 if d["equivalent"] else 1


def cmd_gatekeeper(a) -> int:
    from .gatekeeper import export_yaml
    text = export_yaml(a.level, a.action, tuple(a.exclude_namespace))
    if a.out:
        from pathlib import Path
        Path(a.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_bench(a) -> int:
    from pathlib import Path

    from .bench.runner import run
    done = run(a.names or None, Path(a.data_dir) if a.data_dir else None, Path(a.out))
    return 0 if done else 1


def cmd_live_check(a) -> int:
    from pathlib import Path

    from .live import build_dataset, check, markdown
    from .sigstore import parse_cosign_verify
    sigs = parse_cosign_verify(a.cosign_json) if a.cosign_json else []
    ds = build_dataset(a.manifests, a.pods, a.events, signatures=sigs, author=a.author)
    gk = json.loads(Path(a.gatekeeper).read_text(encoding="utf-8")) if a.gatekeeper else None
    cos = None if a.cosign_ok is None else a.cosign_ok == "true"
    r = check(ds, namespace=a.namespace, workload=a.workload, image_digest=a.digest, commit=a.expect_commit,
              gatekeeper=gk, cosign_ok=cos, drift=a.drift,
              prevention=json.loads(Path(a.prevention).read_text(encoding="utf-8")) if a.prevention else None)
    Path(a.out).write_text(json.dumps(r, indent=1), encoding="utf-8")
    print(markdown(r))
    return 0 if r["passed"] else 1


def cmd_serve(a) -> int:  # pragma: no cover - blocking server
    import os

    import uvicorn
    os.environ["STRATUM_SOURCE"] = a.source
    uvicorn.run("stratum.api:app", host=a.host, port=a.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="stratum", description="code-to-runtime lifecycle defense (mini-CNAPP)")
    p.add_argument("--seed", type=int, default=7)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("generate"); s.add_argument("--out", default="scenario.json"); s.set_defaults(fn=cmd_generate)
    s = sub.add_parser("analyze"); s.add_argument("--data", help="dataset JSON, or 'real' for the $STRATUM_DATA corpus")
    s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_analyze)
    s = sub.add_parser("trace"); s.add_argument("pod", help="namespace/pod"); s.add_argument("--data"); s.set_defaults(fn=cmd_trace)
    s = sub.add_parser("blast"); s.add_argument("base", help="base image ref"); s.add_argument("--data"); s.set_defaults(fn=cmd_blast)
    s = sub.add_parser("prevent"); s.add_argument("namespace"); s.add_argument("--data"); s.set_defaults(fn=cmd_prevent)
    s = sub.add_parser("demo"); s.set_defaults(fn=cmd_demo)
    s = sub.add_parser("collect", help="real K8s manifests (+ Tetragon JSON) -> dataset JSON")
    s.add_argument("files", nargs="+"); s.add_argument("--out", default="cluster.json")
    s.add_argument("--source", default=""); s.add_argument("--namespace", default="default")
    s.add_argument("--tetragon", nargs="*", default=[]); s.set_defaults(fn=cmd_collect)
    s = sub.add_parser("pss", help="Pod Security Standards check of manifest files")
    s.add_argument("files", nargs="+"); s.add_argument("--level", default="restricted",
                                                       choices=["baseline", "restricted"])
    s.add_argument("--strict", action="store_true", help="exit 1 on any violation"); s.set_defaults(fn=cmd_pss)
    s = sub.add_parser("export", help="dataset / graph export")
    s.add_argument("--data"); s.add_argument("--format", choices=["json", "cypher", "rego-input"], default="cypher")
    s.add_argument("--out"); s.set_defaults(fn=cmd_export)
    s = sub.add_parser("opa-check", help="diff Python policy engine vs stratum/policies/stratum.rego (needs opa)")
    s.add_argument("--data"); s.set_defaults(fn=cmd_opa_check)
    s = sub.add_parser("gatekeeper", help="export PSS Rego as a Gatekeeper ConstraintTemplate + Constraint")
    s.add_argument("--level", choices=["baseline", "restricted"], default="restricted")
    s.add_argument("--action", choices=["dryrun", "warn", "deny"], default="dryrun")
    s.add_argument("--exclude-namespace", nargs="*", default=["kube-system"])
    s.add_argument("--out"); s.set_defaults(fn=cmd_gatekeeper)
    s = sub.add_parser("bench", help="run real-data benchmarks into results/")
    s.add_argument("names", nargs="*"); s.add_argument("--data-dir"); s.add_argument("--out", default="results")
    s.set_defaults(fn=cmd_bench)
    s = sub.add_parser("live-check", help="assert on live kind + Tetragon evidence (CI)")
    s.add_argument("--manifests", nargs="+", required=True); s.add_argument("--pods", required=True)
    s.add_argument("--events", nargs="+", required=True)
    s.add_argument("--cosign-json", help="`cosign verify -o json` output: the only source of image->build->commit")
    s.add_argument("--digest", default="", help="digest of the pushed demo image (expected in the events)")
    s.add_argument("--expect-commit", required=True, help="commit the trace must reach (e.g. github.sha)")
    s.add_argument("--drift", help="unsigned workload used as negative control (must not reach a commit)")
    s.add_argument("--prevention", help="JSON with observed before/after connect results of the egress policy")
    s.add_argument("--author", default=""); s.add_argument("--namespace", default="stratum-live")
    s.add_argument("--workload", default="web"); s.add_argument("--gatekeeper")
    s.add_argument("--cosign-ok", choices=["true", "false"]); s.add_argument("--out", default="live-result.json")
    s.set_defaults(fn=cmd_live_check)
    s = sub.add_parser("serve", help="API + incident console")
    s.add_argument("--source", default="synthetic"); s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000); s.set_defaults(fn=cmd_serve)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
