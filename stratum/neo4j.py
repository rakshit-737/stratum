"""Export the lifecycle graph to Neo4j.

* :func:`to_cypher` renders an idempotent Cypher script (``MERGE`` by node id),
  loadable with ``cypher-shell -f graph.cypher`` or the Neo4j browser.
* :func:`push` sends the same statements over Bolt when the optional ``neo4j``
  Python driver is installed (``pip install neo4j``; see docker-compose.yml).

Node labels are the graph node types in CamelCase (Commit, Build, Image,
BaseImage, Workload, Pod, Namespace, ServiceAccount, Netpol) and relationship
types are the upper-cased edge labels (BUILDS, PRODUCES, DEPLOYS, RUNS, ...).
"""
from __future__ import annotations

import json

from .graph import LifecycleGraph

_LABELS = {"base_image": "BaseImage", "service_account": "ServiceAccount", "netpol": "NetworkPolicy"}


def _label(t: str) -> str:
    return _LABELS.get(t, t[:1].upper() + t[1:])


def _props(attrs: dict) -> str:
    out = {}
    for k, v in attrs.items():
        if k == "type" or v is None:
            continue
        out[k] = v if isinstance(v, str | int | float | bool) else json.dumps(v)
    return json.dumps(out, ensure_ascii=False)


def _lit(obj: str) -> str:
    return json.dumps(obj, ensure_ascii=False)


def statements(g: LifecycleGraph) -> list[str]:
    st = ["CREATE CONSTRAINT stratum_id IF NOT EXISTS FOR (n:Stratum) REQUIRE n.id IS UNIQUE"]
    for nid, attrs in sorted(g.nodes.items()):
        st.append(f"MERGE (n:Stratum {{id: {_lit(nid)}}}) SET n:{_label(attrs['type'])} "
                  f"SET n += {_cypher_map(_props(attrs))}")
    for src, outs in sorted(g.out.items()):
        for dst, rel in outs:
            st.append(f"MATCH (a:Stratum {{id: {_lit(src)}}}), (b:Stratum {{id: {_lit(dst)}}}) "
                      f"MERGE (a)-[:{rel.upper()}]->(b)")
    return st


def _cypher_map(js: str) -> str:
    """JSON object -> Cypher map literal (keys unquoted, values JSON-escaped)."""
    d = json.loads(js)
    return "{" + ", ".join(f"`{k}`: {json.dumps(v, ensure_ascii=False)}" for k, v in d.items()) + "}"


def to_cypher(g: LifecycleGraph) -> str:
    return ";\n".join(statements(g)) + ";\n"


def push(g: LifecycleGraph, uri: str = "bolt://localhost:7687", user: str = "neo4j",
         password: str = "stratum-lab") -> int:  # pragma: no cover - needs a running Neo4j
    from neo4j import GraphDatabase

    st = statements(g)
    with GraphDatabase.driver(uri, auth=(user, password)) as drv, drv.session() as s:
        for q in st:
            s.run(q)
    return len(st)


# Example queries shipped in docs/neo4j.md
QUERIES = {
    "trace_pod_to_commit": "MATCH p=(c:Commit)-[:BUILDS]->(:Build)-[:PRODUCES]->(:Image)-[:DEPLOYS]->(:Workload)"
                           "-[:RUNS]->(:Pod {id: $pod}) RETURN p",
    "blast_radius_of_base": "MATCH (b:BaseImage {id: $base})-[:BASE_OF]->(:Image)-[:DEPLOYS]->(w:Workload) "
                            "RETURN w.id ORDER BY w.id",
    "unguarded_namespaces": "MATCH (n:Namespace) WHERE NOT (:NetworkPolicy)-[:GUARDS]->(n) RETURN n.id",
}
