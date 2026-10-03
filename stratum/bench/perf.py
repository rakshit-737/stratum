"""End-to-end latency on the real corpus: load -> graph -> policy -> detect/trace every workload.

Timings are wall-clock on whatever machine runs the bench (recorded in the result), so they describe
that machine only: median and min-max over ``repeats`` runs; the corpus load is timed ``loads`` times
(the first one reads from a cold OS file cache).
"""
from __future__ import annotations

import os
import platform
import statistics
import time
from pathlib import Path

from ..graph import build_graph
from ..incident import analyze
from ..policy import evaluate
from ..realdata import real_dataset


def _summary(xs: list[float]) -> dict:
    ms = [1000 * x for x in xs]
    return {"median": round(statistics.median(ms), 3), "min": round(min(ms), 3), "max": round(max(ms), 3), "n": len(ms)}


def run(root: Path, repeats: int = 20, loads: int = 3) -> dict:
    tl = []
    for _ in range(loads):
        t0 = time.perf_counter()
        ds = real_dataset(root)
        tl.append(time.perf_counter() - t0)
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
    return {"nodes": len(g.nodes), "edges": g.edge_count(), "workloads": len(ds.workloads),
            "events": len(ds.events), "incidents": len(a.incidents),
            "machine": {"platform": platform.platform(), "python": platform.python_version(),
                        "processor": platform.processor() or platform.machine(), "cpus": os.cpu_count()},
            "load_ms": _summary(tl), "graph_build_ms": _summary(tb), "policy_eval_ms": _summary(tp),
            "trace_per_pod_ms": _summary(tt), "full_analyze_ms": _summary(ta)}


def markdown(r: dict) -> str:
    def c(k: str) -> str:
        v = r[k]
        return f"{v['median']} ({v['min']}-{v['max']})" if isinstance(v, dict) else str(v)
    m = r.get("machine") or {}
    return (f"### Performance (real corpus: {r['nodes']} nodes / {r['edges']} edges, {r['workloads']} workloads, "
            f"{r['events']} runtime events)\n\n"
            f"Milliseconds, median (min-max): corpus load over {r['load_ms']['n']} loads (the first from a cold file "
            f"cache), the rest over {r['full_analyze_ms']['n']} repeats. Machine: {m.get('platform', '?')}, "
            f"Python {m.get('python', '?')}, {m.get('cpus', '?')} logical CPUs, shared with other jobs while measured.\n\n"
            "| load corpus | build graph | evaluate policy | trace one pod to commit | full analyze |\n"
            "|---:|---:|---:|---:|---:|\n"
            f"| {c('load_ms')} | {c('graph_build_ms')} | {c('policy_eval_ms')} | {c('trace_per_pod_ms')} | "
            f"{c('full_analyze_ms')} |")
