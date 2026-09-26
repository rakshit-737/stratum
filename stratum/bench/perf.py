"""End-to-end latency on the real corpus: load -> graph -> policy -> detect/trace every workload."""
from __future__ import annotations

import statistics
import time
from pathlib import Path

from ..graph import build_graph
from ..incident import analyze
from ..policy import evaluate
from ..realdata import real_dataset


def run(root: Path, repeats: int = 5) -> dict:
    t0 = time.perf_counter()
    ds = real_dataset(root)
    t_load = time.perf_counter() - t0
    tb, tp, tt, ta = [], [], [], []
    for _ in range(repeats):
        t = time.perf_counter()
        g = build_graph(ds)
        tb.append(time.perf_counter() - t)
        t = time.perf_counter()
        evaluate(ds, g)
        tp.append(time.perf_counter() - t)
        pods = [f"pod:{w.namespace}/{p}" for w in ds.workloads for p in w.pods]
        t = time.perf_counter()
        for p in pods:
            g.trace_upstream(p)
        tt.append((time.perf_counter() - t) / max(len(pods), 1))
        t = time.perf_counter()
        a = analyze(ds)
        ta.append(time.perf_counter() - t)
    ms = lambda xs: round(1000 * statistics.median(xs), 3)  # noqa: E731
    return {"nodes": len(g.nodes), "edges": g.edge_count(), "workloads": len(ds.workloads),
            "events": len(ds.events), "incidents": len(a.incidents), "load_ms": round(1000 * t_load, 1),
            "graph_build_ms": ms(tb), "policy_eval_ms": ms(tp), "trace_per_pod_ms": ms(tt),
            "full_analyze_ms": ms(ta)}


def markdown(r: dict) -> str:
    return (f"### Performance (real corpus: {r['nodes']} nodes / {r['edges']} edges, {r['workloads']} workloads, "
            f"{r['events']} runtime events; median of 5)\n\n"
            "| load corpus | build graph | evaluate policy | trace one pod to commit | full analyze |\n"
            "|---:|---:|---:|---:|---:|\n"
            f"| {r['load_ms']} ms | {r['graph_build_ms']} ms | {r['policy_eval_ms']} ms | {r['trace_per_pod_ms']} ms | "
            f"{r['full_analyze_ms']} ms |")
