# ADR 0001: In-memory lifecycle graph, Neo4j as an export target

- Status: accepted (v0.2); still in force in v1.x
- Date: 2026-09-26

## Context

The spec names Neo4j as the graph unifier. The queries STRATUM needs are narrow:

- walk the lifecycle spine upstream (pod -> workload -> image -> build -> commit),
- walk it downstream from a base image or a commit (blast radius), and
- join policy findings to nodes.

The real corpus is a few hundred nodes.

## Decision

The graph stays a small typed adjacency structure in Python (`stratum/graph.py`). Neo4j is an export target:

- `stratum export --format cypher` produces an idempotent `MERGE` script.
- Nodes get typed labels: `Commit`, `Build`, `Image`, `BaseImage`, `Workload`, `Pod`, `Namespace`, `ServiceAccount`, `NetworkPolicy` and `Control`.
- Edges get relationship types: `BUILDS`, `PRODUCES`, `DEPLOYS`, `RUNS`, `BASE_OF`, `GUARDS`, `IDENTITY_OF` and `VIOLATES`.
- `stratum.neo4j.push` sends the script over Bolt when the optional `neo4j` driver is installed.
- `docker-compose.yml` starts Neo4j 5 for the lab.

## Consequences

- Tests, CI and benchmarks need no database. A full analysis of the real corpus takes milliseconds (`results/perf.md`).
- Neo4j stays available for ad-hoc exploration and for larger estates. The Cypher export is the contract, so a Neo4j-native backend can be added later without changing the collectors.
- The in-memory graph does not implement multi-hop analytics beyond the spine, such as path-finding across RBAC. Run those in Neo4j.
