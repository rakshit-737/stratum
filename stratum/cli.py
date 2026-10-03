"""STRATUM command-line interface."""
from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

from . import __version__
from .dataset import Dataset
from .incident import analyze, metrics, replay_with_policy
from .models import to_dict
from .synth import generate


class NoMatch(Exception):
    """A wildcard argument matched no file."""


def _expand(files: list[str]) -> list[str]:
    """Expand wildcard arguments ourselves (Windows shells pass ``*.yaml`` through unexpanded)."""
    out: list[str] = []
    for f in files:
        if any(c in f for c in "*?["):
            hits = sorted(glob.glob(f, recursive=True))
            if not hits:
                raise NoMatch(f)
            out += hits
        else:
            out.append(f)
    return out


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
    node = f"pod:{ns}/{pod}"
    if node not in g.nodes:
        print(f"stratum: unknown pod {a.pod!r} (use namespace/pod)", file=sys.stderr)
        return 2
    print(" -> ".join(g.trace_upstream(node)))
    return 0


def cmd_blast(a) -> int:
    ds = _load(a.data, a.seed)
    g = analyze(ds).graph
    if f"base:{a.base}" not in g.nodes:
        print(f"stratum: unknown base image {a.base!r}; known: {', '.join(sorted(g.of_type('base_image')))[:400]}",
              file=sys.stderr)
        return 2
    for w in g.blast_radius(f"base:{a.base}"):
        print(w)
    return 0


def cmd_prevent(a) -> int:
    from .policy import valid_namespace
    if not valid_namespace(a.namespace):
        print(f"stratum: {a.namespace[:80]!r} is not a valid namespace name (RFC 1123 label, at most 63 characters)",
              file=sys.stderr)
        return 2
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
    ds = collect_files(_expand(a.files), source=a.source, default_ns=a.namespace)
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
    for d in load_docs(_expand(a.files)):
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
        Path(a.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_bench(a) -> int:
    from .bench.runner import run
    done = run(a.names or None, Path(a.data_dir) if a.data_dir else None, Path(a.out))
    return 0 if done else 1


def cmd_live_check(a) -> int:
    from .live import ablation, build_dataset, check, markdown
    from .sigstore import parse_cosign_verify
    sigs = parse_cosign_verify(a.cosign_json) if a.cosign_json else []
    ds = build_dataset(a.manifests, a.pods, a.events, signatures=sigs, author=a.author)
    gk = json.loads(Path(a.gatekeeper).read_text(encoding="utf-8")) if a.gatekeeper else None
    cos = None if a.cosign_ok is None else a.cosign_ok == "true"
    r = check(ds, namespace=a.namespace, workload=a.workload, image_digest=a.digest, commit=a.expect_commit,
              gatekeeper=gk, cosign_ok=cos, drift=a.drift, forged=a.forged, expect_build=a.expect_build,
              prevention=json.loads(Path(a.prevention).read_text(encoding="utf-8")) if a.prevention else None,
              signatures=sigs, sink=a.sink or None)
    if a.labels:
        labels = json.loads(Path(a.labels).read_text(encoding="utf-8"))
        r["ablation"] = ablation(a.manifests, a.pods, a.events, signatures=sigs, labels=labels,
                                 commit=a.expect_commit, namespace=a.namespace, workload=a.workload,
                                 controls=tuple(x for x in (a.drift, a.forged) if x))
    Path(a.out).write_text(json.dumps(r, indent=1), encoding="utf-8")
    print(markdown(r))
    return 0 if r["passed"] else 1


SOURCES = ("synthetic", "real", "live")


def cmd_serve(a) -> int:  # pragma: no cover - blocking server
    import os

    if a.source not in SOURCES and not Path(a.source).is_file():
        print(f"stratum: --source must be one of {', '.join(SOURCES)} or a dataset JSON file; got {a.source!r}",
              file=sys.stderr)
        return 2
    try:
        import uvicorn
    except ImportError:
        print('stratum: the API needs the [api] extra: pip install -e ".[api]" in a checkout, or '
              '"<release wheel>[api]" (the PyPI name "stratum" is an unrelated project)', file=sys.stderr)
        return 2
    os.environ["STRATUM_SOURCE"] = a.source
    uvicorn.run("stratum.api:app", host=a.host, port=a.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="stratum", description="code-to-runtime lifecycle defense (mini-CNAPP)",
                                epilog="example: stratum demo | stratum pss deploy/k8s/*.yaml --strict")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    seed = argparse.ArgumentParser(add_help=False)
    seed.add_argument("--seed", type=int, default=argparse.SUPPRESS, help="synthetic scenario seed (default 7)")
    p.add_argument("--seed", type=int, default=7, help="synthetic scenario seed (default 7)")
    data_help = "dataset JSON (from `collect`), or 'real' for the $STRATUM_DATA corpus; default: synthetic scenario"
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("generate", parents=[seed], help="write the synthetic 5-scenario cluster as dataset JSON")
    s.add_argument("--out", default="scenario.json", help="output path"); s.set_defaults(fn=cmd_generate)
    s = sub.add_parser("analyze", parents=[seed], help="posture findings + runtime incidents traced to commits")
    s.add_argument("--data", help=data_help)
    s.add_argument("--json", action="store_true", help="machine-readable output"); s.set_defaults(fn=cmd_analyze)
    s = sub.add_parser("trace", parents=[seed], help="pod -> workload -> image -> build -> commit chain")
    s.add_argument("pod", help="namespace/pod"); s.add_argument("--data", help=data_help); s.set_defaults(fn=cmd_trace)
    s = sub.add_parser("blast", parents=[seed], help="workloads built on a base image")
    s.add_argument("base", help="base image ref, e.g. 'alpine 3.24.1'"); s.add_argument("--data", help=data_help)
    s.set_defaults(fn=cmd_blast)
    s = sub.add_parser("prevent", parents=[seed], help="egress NetworkPolicy for a namespace + replayed effect")
    s.add_argument("namespace", help="namespace to protect (RFC 1123 label)"); s.add_argument("--data", help=data_help)
    s.set_defaults(fn=cmd_prevent)
    s = sub.add_parser("demo", parents=[seed], help="run the synthetic end-to-end demo (no cluster needed)")
    s.set_defaults(fn=cmd_demo)
    s = sub.add_parser("collect", help="real K8s manifests (+ Tetragon JSON) -> dataset JSON")
    s.add_argument("files", nargs="+", help="manifest files (YAML/JSON, multi-doc, or kubectl get -o json); "
                                            "wildcards are expanded")
    s.add_argument("--out", default="cluster.json", help="output dataset JSON")
    s.add_argument("--source", default="", help="label recorded on the workloads")
    s.add_argument("--namespace", default="default", help="namespace for objects that have none")
    s.add_argument("--tetragon", nargs="*", default=[], help="Tetragon JSON export files"); s.set_defaults(fn=cmd_collect)
    s = sub.add_parser("pss", help="Pod Security Standards check of manifest files")
    s.add_argument("files", nargs="+", help="manifest files (wildcards are expanded)")
    s.add_argument("--level", default="restricted", choices=["baseline", "restricted"],
                   help="PSS level to check against (default restricted)")
    s.add_argument("--strict", action="store_true", help="exit 1 on any violation"); s.set_defaults(fn=cmd_pss)
    s = sub.add_parser("export", help="dataset / graph export")
    s.add_argument("--data", help=data_help)
    s.add_argument("--format", choices=["json", "cypher", "rego-input"], default="cypher", help="output format")
    s.add_argument("--out", help="output path (default stdout)"); s.set_defaults(fn=cmd_export)
    s = sub.add_parser("opa-check", help="diff Python policy engine vs stratum/policies/stratum.rego (needs opa)")
    s.add_argument("--data", help=data_help); s.set_defaults(fn=cmd_opa_check)
    s = sub.add_parser("gatekeeper", help="export PSS Rego as a Gatekeeper ConstraintTemplate + Constraint")
    s.add_argument("--level", choices=["baseline", "restricted"], default="restricted", help="PSS level to enforce")
    s.add_argument("--action", choices=["dryrun", "warn", "deny"], default="dryrun", help="Gatekeeper enforcementAction")
    s.add_argument("--exclude-namespace", nargs="*", default=["kube-system"], help="namespaces the constraint skips")
    s.add_argument("--out", help="output YAML (default stdout)"); s.set_defaults(fn=cmd_gatekeeper)
    s = sub.add_parser("bench", help="run real-data benchmarks into results/")
    s.add_argument("names", nargs="*", help="pss posture provenance scans runtime adfa opa perf (default: all)")
    s.add_argument("--data-dir", help="corpus directory (default $STRATUM_DATA or ./data)")
    s.add_argument("--out", default="results", help="output directory")
    s.set_defaults(fn=cmd_bench)
    s = sub.add_parser("live-check", help="assert on live kind + Tetragon evidence (CI)")
    s.add_argument("--manifests", nargs="+", required=True, help="the workload manifests that were applied")
    s.add_argument("--pods", required=True, help="`kubectl get pods -o json` of the demo namespace")
    s.add_argument("--events", nargs="+", required=True, help="Tetragon JSON export (one event per line)")
    s.add_argument("--cosign-json", help="`cosign verify -o json` output: the only source of image->build->commit")
    s.add_argument("--digest", default="", help="digest of the pushed demo image (expected in the events)")
    s.add_argument("--expect-commit", required=True, help="commit the trace must reach (e.g. github.sha)")
    s.add_argument("--drift", help="unsigned workload used as negative control (must not reach a commit)")
    s.add_argument("--prevention", help="JSON with observed before/after connect results of the egress policy")
    s.add_argument("--forged", help="unsigned workload whose image carries the right revision label (negative control)")
    s.add_argument("--expect-build", help="CI run id the certificate must name (e.g. github.run_id)")
    s.add_argument("--labels", help="JSON {digest: OCI revision label} for the A0-A4 ablation")
    s.add_argument("--sink", default="sink", help="benign workload whose detections count as false positives")
    s.add_argument("--author", default="", help="commit author recorded on the commit node")
    s.add_argument("--namespace", default="stratum-live", help="demo namespace (default stratum-live)")
    s.add_argument("--workload", default="web", help="workload whose incidents must trace to the commit")
    s.add_argument("--gatekeeper", help="JSON {privileged_denied, demo_admitted} observed in the cluster")
    s.add_argument("--cosign-ok", choices=["true", "false"], help="outcome of the `cosign verify` step")
    s.add_argument("--out", default="live-result.json", help="result JSON (default live-result.json)")
    s.set_defaults(fn=cmd_live_check)
    s = sub.add_parser("serve", help="API + incident console")
    s.add_argument("--source", default="synthetic",
                   help="synthetic | real ($STRATUM_DATA corpus) | live (packaged replay of a live CI run) | "
                        "path to a dataset JSON")
    s.add_argument("--host", default="127.0.0.1", help="bind address (default localhost only)")
    s.add_argument("--port", type=int, default=8000, help="port"); s.set_defaults(fn=cmd_serve)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except NoMatch as e:
        print(f"stratum: no file matches {e.args[0]!r}", file=sys.stderr)
        return 2
    except (FileNotFoundError, IsADirectoryError) as e:
        print(f"stratum: no such file: {e.filename or e}", file=sys.stderr)
        return 2
    except OSError as e:
        if e.filename and any(c in str(e.filename) for c in "*?["):
            print(f"stratum: no file matches {e.filename!r}", file=sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
