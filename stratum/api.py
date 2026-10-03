"""FastAPI service + lifecycle incident console.

Run: ``uvicorn stratum.api:app`` (or ``python -m stratum serve``). The data
source is chosen with ``STRATUM_SOURCE``: ``synthetic`` (default, no downloads
needed), ``real`` (the $STRATUM_DATA corpus), ``live`` (replay of a committed live CI run) or a path to a Dataset JSON.
"""
from __future__ import annotations

import os
from collections import Counter
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, PlainTextResponse

from . import __version__
from .dataset import Dataset
from .incident import analyze, replay_with_policy
from .live import replay_info
from .models import to_dict
from .neo4j import to_cypher
from .policy import CONTROLS, SEV, valid_namespace
from .synth import generate

WEB = Path(__file__).parent / "web"
app = FastAPI(title="STRATUM", version=__version__,
              description="Open mini-CNAPP: code -> CI -> image -> pod -> runtime lifecycle graph")


@app.middleware("http")
async def _security_headers(request, call_next):
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


def _source() -> str:
    return os.environ.get("STRATUM_SOURCE", "synthetic")


@lru_cache(maxsize=4)
def _load(src: str) -> Dataset:
    if src == "synthetic":
        return generate(7)
    if src == "real":
        from .realdata import real_dataset
        return real_dataset()
    if src == "live":   # packaged replay of one live kind + Tetragon CI job (stratum/data/live)
        from .live import replay_dataset
        return replay_dataset()
    return Dataset.load(src)


@lru_cache(maxsize=4)
def _analysis(src: str):
    return analyze(_load(src))


def _a():
    return _analysis(_source())


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Serve the incident console."""
    return FileResponse(WEB / "index.html")


@app.get("/api/summary")
def summary() -> dict:
    """Counts of nodes, findings and incidents for the loaded dataset."""
    a, ds = _a(), _load(_source())
    return {
        "source": _source(), "version": __version__,
        "nodes": len(a.graph.nodes), "edges": a.graph.edge_count(),
        "workloads": len(ds.workloads), "namespaces": len(ds.namespaces), "images": len(ds.images),
        "commits": len(ds.commits), "events": len(ds.events), "findings": len(a.findings),
        "incidents": len(a.incidents),
        "findings_by_control": dict(Counter(f.control_id for f in a.findings).most_common()),
        "pss_levels": dict(Counter(w.pss_level or "n/a" for w in ds.workloads)),
        **({"replay": replay_info()} if _source() == "live" else {}),
    }


@app.get("/api/controls")
def controls() -> list[dict]:
    """The Zero-Trust control catalogue."""
    counts = Counter(f.control_id for f in _a().findings)
    return [dict(to_dict(c), severity=SEV[c.id], findings=counts.get(c.id, 0)) for c in CONTROLS.values()]


@app.get("/api/findings")
def findings(control: str | None = None, limit: int = Query(500, ge=1, le=10000)) -> list[dict]:
    """Posture findings, optionally filtered by control id."""
    fs = [f for f in _a().findings if control in (None, f.control_id)]
    return [to_dict(f) for f in fs[:limit]]


@app.get("/api/workloads")
def workloads() -> list[dict]:
    """Workloads with their images and failed controls."""
    a, ds = _a(), _load(_source())
    per = Counter(f.subject for f in a.findings)
    return [{"id": f"workload:{w.namespace}/{w.name}", "namespace": w.namespace, "name": w.name, "kind": w.kind,
             "image": w.image_digest, "pss_level": w.pss_level, "source": w.source,
             "findings": per.get(f"workload:{w.namespace}/{w.name}", 0),
             "trace": a.graph.trace_upstream(f"workload:{w.namespace}/{w.name}")} for w in ds.workloads]


@app.get("/api/incidents")
def incidents() -> list[dict]:
    """Runtime incidents traced to commits."""
    return [to_dict(i) for i in _a().incidents]


@app.get("/api/trace")
def trace(node: str) -> dict:
    """Upstream chain (pod -> ... -> commit) of a graph node."""
    g = _a().graph
    if node not in g.nodes:
        raise HTTPException(404, f"unknown node {node}")
    chain = g.trace_upstream(node)
    return {"chain": chain, "nodes": {n: g.nodes[n] for n in chain}}


@app.get("/api/blast")
def blast(base: str) -> dict:
    """Workloads built on the given base image."""
    g = _a().graph
    nid = base if base.startswith(("base:", "image:", "commit:", "build:")) else f"base:{base}"
    if nid not in g.nodes:
        raise HTTPException(404, f"unknown node {nid}")
    return {"start": nid, "workloads": g.blast_radius(nid)}


@app.get("/api/bases")
def bases() -> list[dict]:
    """Base images and how many workloads use each."""
    g = _a().graph
    return sorted(({"id": b, "workloads": len(g.blast_radius(b))} for b in g.of_type("base_image")),
                  key=lambda x: -x["workloads"])


@app.post("/api/prevent/{namespace}")
def prevent(namespace: str) -> dict:
    """Generated egress NetworkPolicy for a namespace (422 unless the name is an RFC 1123 label)."""
    if not valid_namespace(namespace):
        raise HTTPException(422, "namespace must be an RFC 1123 label of at most 63 characters")
    ds = Dataset.from_json(_load(_source()).to_json())  # copy: replay mutates
    return replay_with_policy(ds, namespace)


@app.get("/api/export/cypher", response_class=PlainTextResponse)
def cypher() -> str:
    """The graph as Neo4j Cypher statements."""
    return to_cypher(_a().graph)
