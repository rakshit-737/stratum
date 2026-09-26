"""Unified lifecycle graph (in-memory adjacency; exported to Neo4j by stratum.neo4j).

Node ids are typed: commit:<sha>, build:<id>, image:<digest>, base:<ref>,
workload:<ns>/<name>, pod:<ns>/<pod>, ns:<name>, sa:<ns>/<name>, netpol:<ns>/<name>.
Edges point downstream along the lifecycle (commit -> build -> image -> workload -> pod).
"""
from __future__ import annotations

from collections import defaultdict, deque

from .dataset import Dataset

SPINE = ("runs", "deploys", "produces", "builds")


class LifecycleGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict] = {}
        self.out: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.inc: dict[str, list[tuple[str, str]]] = defaultdict(list)

    def add_node(self, nid: str, ntype: str, **attrs) -> None:
        self.nodes.setdefault(nid, {"type": ntype}).update(attrs)

    def add_edge(self, src: str, dst: str, rel: str) -> None:
        if (dst, rel) not in self.out[src]:
            self.out[src].append((dst, rel))
            self.inc[dst].append((src, rel))

    def parents(self, nid: str, rel: str | None = None) -> list[str]:
        return [s for s, r in self.inc.get(nid, []) if rel is None or r == rel]

    def children(self, nid: str, rel: str | None = None) -> list[str]:
        return [d for d, r in self.out.get(nid, []) if rel is None or r == rel]

    def of_type(self, ntype: str) -> list[str]:
        return [n for n, a in self.nodes.items() if a["type"] == ntype]

    def edge_count(self) -> int:
        return sum(len(v) for v in self.out.values())

    # ---- queries -------------------------------------------------------
    def pod_workload(self, ns: str, pod: str) -> str | None:
        p = self.parents(f"pod:{ns}/{pod}", "runs")
        return p[0] if p else None

    def trace_upstream(self, nid: str) -> list[str]:
        """Follow the lifecycle spine upstream: pod -> workload -> image -> build -> commit."""
        chain, cur, seen = [nid], nid, {nid}
        while True:
            nxt = next((ps[0] for rel in SPINE if (ps := self.parents(cur, rel))), None)
            if nxt is None or nxt in seen:
                return chain
            chain.append(nxt)
            seen.add(nxt)
            cur = nxt

    def blast_radius(self, start: str) -> list[str]:
        """All workloads reachable downstream of a commit/build/image/base-image node."""
        hits, q, seen = set(), deque([start]), {start}
        while q:
            n = q.popleft()
            if self.nodes.get(n, {}).get("type") == "workload":
                hits.add(n)
            for d, rel in self.out.get(n, []):
                if rel in ("runs",) or d in seen:
                    continue
                seen.add(d)
                q.append(d)
        return sorted(hits)


def build_graph(ds: Dataset) -> LifecycleGraph:
    g = LifecycleGraph()
    for c in ds.commits:
        g.add_node(f"commit:{c.sha}", "commit", repo=c.repo, author=c.author, message=c.message, pr=c.pr)
    for b in ds.builds:
        g.add_node(f"build:{b.id}", "build", pipeline=b.pipeline, signed=b.signed)
        g.add_edge(f"commit:{b.commit_sha}", f"build:{b.id}", "builds")
    for i in ds.images:
        g.add_node(f"image:{i.digest}", "image", ref=i.ref, trusted=i.build_id is not None, layers=i.layers)
        if i.build_id:
            g.add_edge(f"build:{i.build_id}", f"image:{i.digest}", "produces")
        if i.base_image:
            g.add_node(f"base:{i.base_image}", "base_image")
            g.add_edge(f"base:{i.base_image}", f"image:{i.digest}", "base_of")
    for n in ds.namespaces:
        g.add_node(f"ns:{n.name}", "namespace")
    for sa in ds.service_accounts:
        g.add_node(f"sa:{sa.namespace}/{sa.name}", "service_account", cluster_admin=sa.cluster_admin)
    for np in ds.network_policies:
        g.add_node(f"netpol:{np.namespace}/{np.name}", "netpol")
        g.add_edge(f"netpol:{np.namespace}/{np.name}", f"ns:{np.namespace}", "guards")
    for w in ds.workloads:
        wid = f"workload:{w.namespace}/{w.name}"
        g.add_node(wid, "workload", namespace=w.namespace, privileged=w.privileged,
                   run_as_root=w.run_as_root, service_account=w.service_account, kind=w.kind,
                   pss_level=w.pss_level, source=w.source)
        if f"image:{w.image_digest}" not in g.nodes:
            g.add_node(f"image:{w.image_digest}", "image", ref="?", trusted=False, layers=[])
        g.add_edge(f"image:{w.image_digest}", wid, "deploys")
        for ref in w.images:
            if ref != w.image_digest:
                if f"image:{ref}" not in g.nodes:
                    g.add_node(f"image:{ref}", "image", ref=ref, trusted=False, layers=[])
                g.add_edge(f"image:{ref}", wid, "deploys_sidecar")
        g.add_edge(f"ns:{w.namespace}", wid, "contains")
        g.add_node(f"sa:{w.namespace}/{w.service_account}", "service_account")
        g.add_edge(f"sa:{w.namespace}/{w.service_account}", wid, "identity_of")
        for p in w.pods:
            g.add_node(f"pod:{w.namespace}/{p}", "pod")
            g.add_edge(wid, f"pod:{w.namespace}/{p}", "runs")
    for r in ds.image_reports:
        nid = f"image:{r.ref}"
        if nid in g.nodes:
            g.nodes[nid].update(os=r.os, vulns=r.vulns, kev=r.kev, critical=len(r.critical), shells=r.shells)
    return g


def attach_findings(g: LifecycleGraph, findings) -> LifecycleGraph:
    """Add control nodes and VIOLATES edges (subject -> control) for export/visualisation."""
    for f in findings:
        cid = f"control:{f.control_id}"
        g.add_node(cid, "control")
        if f.subject in g.nodes:
            g.add_edge(f.subject, cid, "violates")
    return g
