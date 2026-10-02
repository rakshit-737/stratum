# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-10-02

### Added
- Live CI job (`live.yml`): kind + Tetragon + OPA Gatekeeper on a GitHub runner. A demo image is pushed to GHCR and signed keyless with cosign; benign attack-shaped actions run in a pod; `stratum live-check` asserts detection and trace-to-commit on the real Tetragon events. Committed result: one signed image replayed in 5 clusters, 5/5 pass (`results/live.md`).
- Live job: per-run nonce-tagged image signed in each cluster, `--expect-build` check, unsigned forged-label negative control, A0-A4 join ablation (code only; no aggregated result committed yet).
- `syscalls.yml`: container syscall traces (Tetragon raw syscalls) recorded in Actions with leave-one-run-out evaluation (results not yet committed).
- Docs: novelty statement, ADR 0007 (certificate-derived provenance), mermaid parse check in docs CI, API docstrings.
- `stratum/sigstore.py`: the `image -> build -> commit` edges for the live check are read from the verified Fulcio certificate (commit OID .1.3, run-invocation URI), not from workflow variables. Negative control: an unsigned digest-pinned `drift` workload never reaches a commit and names ZT-PROV-01.
- Policy-as-prevention measured live: the `stratum prevent` NetworkPolicy blocks egress to an external sink and keeps in-cluster traffic.
- Reproduction of Kim et al. 2016 (LSTM language-model ensemble on ADFA-LD) as a per-seed Actions workflow (`repro-kim.yml`, extra `lstm`); results in `results/kim_lstm.md`. The reproduction falls well short of the paper (AUC 0.709 vs 0.928).
- ADFA-LD: paired bootstrap of detector differences, tie-aware operating points, false-alarm rate at 90% detection compared with published figures, 10 random re-splits with Nadeau-Bengio corrected CIs.
- Scans report corpus-wide unique CVE x package pairs next to per-image sums; posture reports distinct namespaces for ZT-NET-01; Wilson CIs on proportions; OPA equivalence written to `results/opa.json`.
- `--source live` for `stratum serve` and the static demo (`/demo-live/`); docs pages How it works, Evaluation, Reproduce; CITATION.cff, Dependabot, CODEOWNERS, issue/PR templates.
- CI: wheel/sdist build and clean-venv smoke test, Docker image smoke test, pip-audit, Python 3.10-3.14, SHA-pinned actions.

### Fixed
- **The Gatekeeper ConstraintTemplate exported by 1.0.0 does not load**: Gatekeeper parses template Rego as v0 and rejected `import rego.v1`. The export now uses `future.keywords`.
- The 1.0.0 wheel omitted the Rego policies, so `stratum gatekeeper` and `opa-check` crashed after `pip install`. Policies now live in `stratum/policies/` and ship as package data.
- R-SA-TOKEN now matches the projected token path (`.../serviceaccount/..<timestamp>/token`) seen by the kernel.
- Live demo Dockerfile: a stray literal `
` in the LABEL instruction broke the per-run image build in `live.yml`.
- Release notes were empty (awk regex); the release image is now cosign-signed; registry token realms must be https; the GitHub token for provenance is opt-in (`STRATUM_GITHUB_TOKEN`).
- Documentation: live trace-to-commit result now states it rests on one certificate reused across 5 clusters (no run-level CI); STIDE published figure cited as quoted by Kim et al.
- Documentation: STIDE n=6 has a small but significant AUC edge over novelty n=5 (paired bootstrap), not "indistinguishable"; scan totals are per-image sums (unique pairs 10/156/157/98); 26 of 29 namespaces lack an egress policy.

## [1.0.0] - 2026-09-26

### Added
- `stratum gatekeeper`: exports `policies/pss/pss.rego` (8 field-test Pod Security Standards checks in Rego v1) as an OPA Gatekeeper `ConstraintTemplate` + `Constraint` (dryrun by default). Tests diff the Rego against the Python PSS engine with `opa`, on the committed fixtures, on workload templates (Deployment, CronJob), and on every Pod in the upstream PSA v0.37.1 testdata when the corpus is present. There were no disagreements.
- ADFA-LD benchmark: 95% stratified bootstrap confidence intervals for AUC and TPR at 1% and 5% FPR. The Isolation Forest now runs over 5 seeds (mean ± sd).
- MkDocs Material documentation site on GitHub Pages, with a mkdocstrings API reference and a static snapshot of the incident console on the real-data corpus (`/demo/`, built by `scripts/build_static_demo.py`).
- Release workflow: on a `v*` tag it pushes a container image to `ghcr.io/rakshit-737/stratum` and creates a GitHub Release with the wheel and sdist attached.

### Changed
- The Isolation Forest ADFA-LD result is corrected. With seed variance counted, its AUC is 0.483 ± 0.068 (seeds 0-4); the single-seed 0.568 reported in 0.2.0 was a favourable seed. Novelty n=5 and STIDE n=6 have overlapping AUC CIs.
- The Dockerfile now carries OCI labels, and `docker-compose.yml` references the published image.

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
