# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-09-26

The project moves from a synthetic MVP to a real-data pipeline.

### Added

**Data pipeline**
- Checksum-verified data scripts (`scripts/`) for:
  - Pod Security Admission fixtures
  - 21 upstream install manifests
  - 10 Helm charts rendered with default values
  - image provenance for 86 images (registry + GitHub)
  - Trivy scans joined with CISA KEV
  - Tetragon sample events
  - ADFA-LD
- `download_all.py` runs the whole pipeline.

**Collection and ingestion**
- `stratum.k8s`, a real-manifest collector. It covers every workload kind and records RBAC risk (cluster-admin, cluster-wide secret read, wildcard, bind/escalate), NetworkPolicies and the effective token automount.
- `stratum.pss`, a pure-Python port of all 19 Kubernetes Pod Security Standards checks (v1.37 semantics).
- `stratum.registry` and `stratum.provenance`. They resolve image tag -> digest -> OCI source/revision labels -> verified GitHub commit, author and PR, and record whether cosign signature and attestation artefacts exist. No layers are pulled.
- `stratum.ingest`: parsers for Tetragon JSON and Trivy JSON, a CISA KEV join, and runtime-only workload discovery.

**Policy and detection**
- Four new Zero-Trust controls:
  - `ZT-WL-02` PSS restricted
  - `ZT-ID-04` cluster-wide secret read / RBAC escalation
  - `ZT-PROV-03` digest pinning
  - `ZT-IMG-03` CISA KEV
- New runtime rules:
  - container escape (`nsenter -t 1`)
  - credential-file read
  - system-file write
  - unmanaged container
  - exec from temp dirs
  - network tools
- `stratum.syscall`: syscall anomaly models (STIDE baseline, n-gram surprisal, Isolation Forest) and an ADFA-LD loader.
- `policies/stratum.rego`, a Rego v1 mirror of the policy engine. `stratum opa-check` diffs it against the Python engine; both produce 292 identical findings on the real corpus.

**Interfaces**
- Neo4j Cypher export with control nodes and `VIOLATES` edges; `docker-compose.yml` with Neo4j 5.
- FastAPI service and a dependency-free incident console (`stratum serve`).
- New CLI commands: `collect`, `pss`, `export`, `opa-check`, `bench`, `serve`, and `analyze --data real`.

**Evaluation and project hygiene**
- Benchmark suite (`python -m stratum bench`): PSS conformance, posture, provenance coverage, scans/blast radius, runtime rules, ADFA-LD and latency. Results and figures are in `results/`.
- Tests with small real fixtures, plus `realdata`-marked tests that skip without the corpus.
- CI now also runs ruff and an OPA equivalence job.
- MIT licence, CONTRIBUTING, ADRs 0001-0006, architecture and dataset docs, Dockerfile.

### Changed
- `ZT-NET-01` only fires for namespaces that actually run workloads.
- The novelty model only runs when a baseline window exists.
- Policy findings are de-duplicated.

## [0.1.0] - 2026-06

### Added
- Synthetic MVP with:
  - a lifecycle graph (commit -> build -> image -> workload -> pod)
  - 9 Zero-Trust controls
  - 3 runtime rules and a novelty model
  - trace-to-commit, blast radius, policy-as-prevention replay
  - a CLI and a demo covering the five spec scenarios
