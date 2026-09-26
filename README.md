# STRATUM

[![ci](https://github.com/rakshit-737/stratum/actions/workflows/ci.yml/badge.svg)](https://github.com/rakshit-737/stratum/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue)
[![license: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![policy: OPA/Rego](https://img.shields.io/badge/policy-OPA%2FRego%20v1-7d4cdb)

**An open mini-CNAPP.** STRATUM puts `commit → CI build → image → Kubernetes workload → pod → runtime event` into one graph and checks 13 Zero-Trust controls against it. The controls are written in Python and mirrored in Rego. When a runtime alert fires, STRATUM traces it back to the commit and PR that shipped the code and names the control that should have stopped it. It also lists every other workload built on the same base OS release (the blast radius).

v0.2 runs on real public data:

- 31 real open-source install manifests and Helm charts (87 workloads)
- 86 real container images, resolved to verified GitHub commits and scanned with Trivy and CISA KEV
- the upstream Kubernetes Pod Security Admission conformance fixtures
- real Cilium Tetragon events from a container-escape and C2 attack chain
- the ADFA-LD syscall benchmark

> Lab-only, defensive tool. It reads public manifests, registry metadata and published event logs, and it never changes a cluster. See [Safety](#safety).

## Headline results (real data)

| What | Result | Baseline |
|---|---|---|
| Policy engine vs upstream PSS conformance fixtures (148 pods, v1.37) | **F1 1.000** at baseline and restricted | v0.1 heuristic: recall 0.147 / 0.105 |
| Posture of 31 real projects in their default configuration | **32 / 87** workloads not PSS-restricted (7 privileged); 29 namespaces with no egress policy; 24 workloads with cluster-wide secret read or RBAC escalation | v0.1 heuristic flags 7 / 87 |
| Rego mirror vs Python engine on the full corpus | **292 / 292 identical findings** (OPA 1.21), including scan-derived controls | n/a |
| Trace pod → verified commit (86 real images) | 25 images (29%) carry a revision that GitHub confirms; **23 / 87 workloads** traced end-to-end, 19 of them on to the merged PR (21 of the 25 images link to a PR) | `tag == git tag` heuristic: right for 21 of those 25; no answer for the other 4 |
| Runtime rules on real Tetragon events (30 events, 20 attack) | **recall 0.80, precision 0.89**; container escape, unmanaged C2 container and credential read are named with their control | v0.1 rules: recall 0.40, precision 0.80 |
| Syscall anomaly model on ADFA-LD (4,372 normal / 746 attack) | n-gram novelty n=5: ROC-AUC 0.822, TPR 0.08 at 1% FPR; n=3: AUC 0.799, TPR 0.18 at 1% FPR | STIDE n=6: AUC 0.827, TPR 0.00 at 1% FPR; STIDE n=3: AUC 0.695, TPR 0.17 at 1% FPR |
| Trivy + CISA KEV on 49 real images | 15 critical / 432 high; 7 images with a critical, 18 ship a shell, **0** KEV hits; one base OS release (Alpine 3.24.1) → 8 workloads blast radius | n/a |
| Latency, full analysis of the real corpus (470 nodes, 504 edges) | **14 ms**; one pod → commit trace takes 0.04 ms | n/a |

The full tables are in [`results/RESULTS.md`](results/RESULTS.md) and are regenerated with `python -m stratum bench`.

<p>
<img src="results/figures/pss_conformance.png" width="49%" alt="PSS conformance: STRATUM F1 1.0 vs v0.1 heuristic">
<img src="results/figures/posture_controls.png" width="49%" alt="Zero-Trust findings across 31 real projects">
</p>
<p>
<img src="results/figures/provenance_funnel.png" width="49%" alt="Provenance coverage funnel for 86 real images">
<img src="results/figures/adfa_roc.png" width="49%" alt="ADFA-LD ROC curves">
</p>

## Architecture

```mermaid
flowchart LR
  subgraph Inputs
    MAN[Manifests / helm template / kubectl -o yaml]
    REG[OCI registries: digest, labels, cosign]
    GH[GitHub API: commit, PR]
    TRV[Trivy JSON + CISA KEV]
    TET[Tetragon JSON events]
  end
  MAN --> K8S[collector: workloads, RBAC risk, NetworkPolicies, PSS level]
  REG --> PROV[provenance resolver]
  GH --> PROV
  TRV --> ING[scan + runtime ingest]
  TET --> ING
  K8S --> G[(Lifecycle graph)]
  PROV --> G
  ING --> G
  G --> POL[Zero-Trust policy engine, 13 controls]
  POL -. identical findings, diffed in CI .-> REGO[policies/stratum.rego on OPA]
  G --> DET[runtime rules + anomaly scoring]
  DET --> INC[Incident: root commit, PR, failed control, blast radius, fix]
  POL --> INC
  INC --> UI[FastAPI + incident console]
  G --> NEO[Neo4j Cypher export]
```

| Module | File | What it does |
|---|---|---|
| Cluster collector | `stratum/k8s.py` | Multi-doc YAML → workloads (all kinds), effective SA token automount, RBAC risk from (Cluster)Role(Binding)s, NetworkPolicies |
| Pod Security Standards | `stratum/pss.py` | All 19 baseline/restricted checks, v1.37 semantics |
| Build provenance | `stratum/registry.py`, `stratum/provenance.py` | tag → digest → OCI source/revision → verified GitHub commit + PR; cosign `.sig`/`.att` presence; no layer pulls |
| Scan + runtime ingest | `stratum/ingest.py` | Trivy JSON (CVEs, shells, base OS), CISA KEV join, Tetragon `process_exec/connect/kprobe`, runtime-only pods |
| Lifecycle graph | `stratum/graph.py`, `stratum/neo4j.py` | Typed graph, upstream trace, downstream blast radius; Cypher export with `VIOLATES` edges |
| Zero-Trust policy | `stratum/policy.py`, `policies/stratum.rego`, `stratum/opa.py` | 13 named controls (NIST 800-207, CIS K8s, SLSA, CISA BOD 22-01); a Rego v1 mirror and an OPA diff |
| Runtime detection | `stratum/detect.py`, `stratum/syscall.py` | 9 rules that name controls, a per-workload novelty model, STIDE / n-gram / Isolation Forest syscall models |
| Incidents | `stratum/incident.py` | Trace-to-commit, failed controls, blast radius, fix, policy-as-prevention replay |
| Interfaces | `stratum/cli.py`, `stratum/api.py`, `stratum/web/` | CLI, FastAPI, and a no-build incident console |
| Benchmarks | `stratum/bench/` | PSS, posture, provenance, scans, runtime, ADFA, perf → `results/` |

More detail: [docs/architecture.md](docs/architecture.md) and the ADRs in [docs/adr/](docs/adr/).

## Quickstart

```bash
pip install -e ".[dev,api,bench]"
python -m stratum demo                  # synthetic 5-scenario walkthrough, no downloads
python -m pytest -q                     # 47 tests on small real fixtures (50 with the corpus)
python -m stratum serve                 # console on http://127.0.0.1:8000
```

Check your own manifests:

```bash
python -m stratum pss deploy/*.yaml --level restricted --strict            # PSS gate for CI
python -m stratum collect deploy/*.yaml --out cluster.json                 # -> dataset JSON
python -m stratum analyze --data cluster.json                              # findings + incidents
kubectl get deploy,ds,sts,job,cronjob,pod,sa,netpol,clusterrole,clusterrolebinding,role,rolebinding -A -o yaml > live.yaml
python -m stratum collect live.yaml --tetragon tetragon-events.json --out live.json
python -m stratum export --data live.json --format cypher --out graph.cypher   # Neo4j
python -m stratum opa-check --data live.json                               # Rego == Python?
```

## Reproducing the results

`make` targets are listed. On machines without `make`, run the command in the comment.

```bash
export STRATUM_DATA=$PWD/data           # anywhere outside git; ~3 GB with the Trivy cache
make data        # python scripts/download_all.py   (tools, datasets, provenance, Trivy scans)
make bench       # python -m stratum bench          (writes results/*.json|md, results/figures/*.png)
make test        # python -m pytest -q              (realdata tests run automatically when data is present)
make serve SOURCE=real   # python -m stratum serve --source real
```

The scripts pin versions and verify SHA-256 against `scripts/checksums.json` or the upstream checksum files. Image scans run smallest image first under a download budget (`--budget-mb 1500`). Skipped images are listed in `scans/index.json`.

## Datasets

| Dataset | Used for | Size | Licence |
|---|---|---:|---|
| [kubernetes/pod-security-admission](https://github.com/kubernetes/pod-security-admission) v0.37.1 test fixtures | PSS ground truth (4,537 labelled pods; v1.37 subset = 148) | 0.3 MB | Apache-2.0 |
| 21 upstream release manifests (argo-cd, flux2, cert-manager, kyverno, gatekeeper, ingress-nginx, calico, flannel, metallb, longhorn, knative, tekton, keda, cloudnative-pg, prometheus-operator, kube-state-metrics, metrics-server, sealed-secrets, dashboard, local-path, Online Boutique) | cluster state | 19 MB | Apache-2.0 |
| 10 Helm charts via `helm template` with default values (vault, falco, tetragon, traefik, external-secrets, trivy-operator, bitnami redis/postgresql, jenkins, harbor) | cluster state | 3 MB | Apache-2.0 / MPL-2.0 |
| Registry + GitHub metadata for the 86 referenced images | build provenance | 0.3 MB | metadata |
| Trivy 0.74 scans + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | vulnerabilities, shells, base OS, blast radius | ~1.5 GB cache | Apache-2.0 / public domain |
| [Cilium Tetragon](https://github.com/cilium/tetragon) sample events (*Security Observability with eBPF*, 2022) | real runtime events | 0.1 MB | Apache-2.0 |
| [ADFA-LD](https://research.unsw.edu.au/projects/adfa-ids-datasets) (Creech & Hu, 2013) | syscall anomaly model | 2.4 MB | UNSW, free for research |

Citations, pins and usage notes are in [docs/datasets.md](docs/datasets.md).

## Results in detail

### 1. Policy engine: Pod Security Standards conformance

The upstream PSA fixtures are Pods that the reference admission plugin must accept or reject.

| level | engine | fixtures | precision | recall | F1 |
|---|---|---:|---:|---:|---:|
| baseline | **STRATUM** | 49 | 1.000 | 1.000 | **1.000** |
| baseline | v0.1 heuristic | 49 | 1.000 | 0.147 | 0.256 |
| restricted | **STRATUM** | 99 | 1.000 | 1.000 | **1.000** |
| restricted | v0.1 heuristic | 99 | 1.000 | 0.105 | 0.191 |

Every failing fixture is also attributed to the right check (100%). A faithful port *should* reach 1.0, so this result is a conformance and regression gate, not a skill claim ([ADR 0003](docs/adr/0003-pss-reimplementation-and-conformance.md)).

### 2. Posture of real open-source projects (default configuration)

| control | findings | observation |
|---|---:|---|
| ZT-PROV-03 digest pinning | 76 | Only ingress-nginx, knative and tekton pin images by `@sha256` |
| ZT-ID-02 token automount on privileged identity | 47 | Operators mount tokens for SAs that hold cluster-wide rights |
| ZT-NET-01 default-deny egress | 29 | Only flux2 and the Bitnami charts ship NetworkPolicies by default |
| ZT-ID-04 cluster-wide secret read / escalation | 24 | 50 service-account grants include secret read; 9 have `*` verbs on `*` resources |
| ZT-WL-02 not PSS-restricted | 24 | Online Boutique (12/12), Vault, Jenkins, dashboard, trivy-operator |
| ZT-ID-01 default service account | 10 | Harbor (7 workloads) |
| ZT-WL-01 privileged / PSS-baseline violation | 8 | CNI and storage daemons (calico, flannel, metallb, longhorn), falco, tetragon |
| ZT-ID-03 cluster-admin | 2 | flux2's kustomize/helm controllers (by design) |

Of the 87 workloads, 55 reach PSS *restricted*, 25 *baseline* and 7 only *privileged*. The v0.1 heuristic would have flagged 7 workloads; PSS flags 32. The per-project table is in [`results/posture.md`](results/posture.md).

### 3. Build provenance: can a running pod be traced to a commit?

| hop (86 real images) | images | % |
|---|---:|---:|
| tag resolved to a linux/amd64 digest | 86 | 100 |
| OCI `source` label names a GitHub repo | 43 | 50 |
| revision present (label or SHA in the source URL) | 27 | 31 |
| commit verified via the GitHub API | 25 | 29 |
| commit linked to a merged PR | 21 | 24 |
| cosign signature artefact published | 32 | 37 |
| cosign attestation artefact published | 28 | 33 |

23 of 87 workloads trace end to end. For example: `pod flux-system/kustomize-controller → image ghcr.io/fluxcd/kustomize-controller:v1.9.5 → commit d5d5d2b (PR #1732)`. For the 25 images with a verified embedded commit, the naive `image tag == git tag` heuristic agreed on 21 and had no matching tag for 4. The heuristic is right when it answers, but it cannot tell you when it is guessing. STRATUM only draws an edge that GitHub confirms ([ADR 0004](docs/adr/0004-provenance-sources.md)).

### Image scans (Trivy + CISA KEV)

49 of the 86 images were scanned: 1.45 GB pulled, smallest image first. The 37 larger images were skipped by the download budget; the largest are Falco driver-loader, Jenkins, argo-cd, Vault and Harbor. Counts are unique CVE × package pairs.

| critical | high | medium | low | images with a critical | images with a CISA KEV CVE | images that ship a shell |
|---:|---:|---:|---:|---:|---:|---:|
| 15 | 432 | 342 | 326 | 7 / 49 | **0 / 49** (KEV 2026.09.25, 1,726 CVEs) | 18 / 49 |

- **Most exposed:**
  - `kubernetesui/metrics-scraper:v1.0.8` (5 critical, 68 high). It is still referenced by the Dashboard v2.7.0 manifest.
  - `ghcr.io/dexidp/dex:v2.45.1` (4 critical, 66 high).
  - `redis:8.2.3-alpine` (2 critical), bundled by argo-cd.
- **Blast radius from the graph:**
  - The `alpine 3.24.1` base OS release (as reported by Trivy, not a shared layer digest) sits under 8 workloads in three projects (flannel, Online Boutique, a Jenkins chart test pod), so a single Alpine 3.24.1 advisory reaches all 8.
  - `debian 13.6` (distroless) sits under cert-manager, kube-state-metrics and sealed-secrets.
- **Distroless:** 6 images have no OS package database at all.
- **Shells:** 18 images still ship `busybox` or `bash`. That is what `ZT-IMG-02` flags and what the `R-SHELL` rule then catches at runtime.

<img src="results/figures/scans_top_images.png" width="60%" alt="Most-exposed scanned images">

### 4. Runtime: real Tetragon events

The events come from the attack chain in *Security Observability with eBPF*:

1. a privileged pod,
2. `nsenter -t 1` into the host,
3. a Merlin C2 agent in an unmanaged container,
4. 7z, scp and an ssh-tunnel exfiltration,

plus benign workload events. Labels are ours ([`benchmarks/labels/tetragon.json`](benchmarks/labels/tetragon.json)).

| rule set | TP | FP | FN | precision | recall |
|---|---:|---:|---:|---:|---:|
| **STRATUM v0.2** (9 rules) | 16 | 2 | 4 | **0.89** | **0.80** |
| v0.1 (shell / SA token / egress) | 8 | 2 | 12 | 0.80 | 0.40 |

```text
[INC-0003] CRITICAL R-ESCAPE: 'nsenter -t 1 -m -u -n -i -p bash' entered the host namespaces (container escape)
  trace      : pod:default/privileged-pod -> workload:default/privileged-pod -> image:nginx:latest@sha256:0d17b565...
  root commit: NONE (image not from trusted pipeline)
  failed ctl : ZT-WL-01 [high] workload:default/privileged-pod violates PSS baseline (privileged=True)
  failed ctl : ZT-NET-01 [high] namespace 'default' has no default-deny egress policy
  fix        : set securityContext privileged=false, runAsNonRoot=true
```

The two false positives are `curl www.google.com` (external egress) and `sh lifecycle.sh` (a benign shell). The misses are:

- the `cat` exec that precedes the keystore read (the read itself is caught),
- the `cat` used to write a static-pod manifest,
- the host-level `containerd-shim`/`runc` starts.

**Caveat:** there are only 30 events, and the rules were written with these events in view. Read this as a coverage demonstration, not a held-out evaluation ([ADR 0006](docs/adr/0006-runtime-rules-plus-novelty.md)).

### 5. Syscall anomaly model on ADFA-LD

The models were fit on the 833 normal training traces and scored on 4,372 normal and 746 attack traces. No attack data was used for fitting or tuning.

| detector | ROC-AUC | TPR @1% FPR | TPR @5% FPR | TPR @15% FPR |
|---|---:|---:|---:|---:|
| STIDE n=6 (Forrest et al. 1996), baseline | **0.827** | 0.000 | 0.218 | **0.627** |
| STRATUM n-gram novelty n=5 | 0.822 | 0.082 | 0.241 | 0.564 |
| STRATUM n-gram novelty n=3 | 0.799 | **0.176** | 0.265 | 0.537 |
| STIDE n=3 | 0.695 | 0.170 | **0.318** | 0.576 |
| Isolation Forest, TF-IDF 1..3-grams | 0.568 | 0.001 | 0.039 | 0.172 |

**Honest read:**

- The frequency-weighted novelty model does not beat STIDE on AUC.
- At 1% FPR the n=3 variant detects 0.18 vs 0.00 for STIDE n=6, but STIDE n=3 gets 0.17 there, so the low-FPR edge comes mostly from the shorter window, not the frequency weighting. No single configuration wins on both AUC and low-FPR TPR.
- Neither comes close to the ~90% detection at ~15% FAR that Creech & Hu (2014) report with semantic features.

This is why STRATUM alerts on rules and uses anomaly scores only as `medium` context.

## Prior art and how this differs

| Existing | What it does well | Gap STRATUM explores |
|---|---|---|
| Falco / Falcosidekick | Runtime rules on syscalls | No build lineage and no control mapping |
| Cilium Tetragon | eBPF runtime observability and enforcement | Not fused with CI provenance or control coverage (STRATUM ingests its events) |
| Kubescape / kube-bench / Polaris | Posture and config scanning | No runtime → code trace |
| Kyverno / Gatekeeper / PSA | Admission enforcement (including PSS) | Enforces, but does not explain incidents across the lifecycle |
| Trivy / Grype / Syft | Image CVEs and SBOMs | Image-centric, with no workload identity or runtime link |
| Sigstore / SLSA | Signing and provenance formats | Formats, not an incident graph |
| Wiz / Prisma / Sysdig (CNAPP) | This exact space, commercially | Closed, agent-heavy and expensive |

STRATUM does not compete with commercial CNAPPs. It is a small, readable, graph-centric slice of the idea: every runtime alert is joined to verified build provenance and to the specific Zero-Trust control that failed.

## Limitations

- **Static cluster state.** v0.2 reads manifests (or `kubectl get -o yaml` output). There is no live watcher yet. Helm charts are rendered with default values.
- **Provenance trust.** cosign signatures and attestations are checked for presence, not verified cryptographically. An image → commit edge requires the commit to exist in the named repo, but the labels themselves could be forged. The fix is to verify SLSA provenance (roadmap).
- **Small runtime set.** The runtime evaluation has only 30 labelled events, and the rules were written with them in view. No public, labelled, container-native runtime dataset was downloadable here: LID-DS is behind an interactive file host.
- **Weak syscall models on ADFA-LD.** They are also not container workloads.
- **Scan budget.** Image scans are budget-limited because of bandwidth. The largest images (for example Jenkins, argo-cd and the Falco driver loader) were skipped; see the scans section.
- **Simulated egress enforcement.** It models CIDR only (no DNS, ports or L7).
- **PSS semantics.** Only the latest (v1.37) semantics are implemented.

## Roadmap

- [ ] Live collectors: a kube API watch plus Tetragon gRPC streaming
- [ ] Verify cosign signatures and SLSA/in-toto provenance (sigstore-python); parse BuildKit attestations
- [ ] Container-native runtime evaluation (LID-DS 2021, CB-DS) and sequence models
- [ ] Mean-time-to-root-cause user study: STRATUM vs siloed tools (the spec's research question)
- [ ] Rego for the PSS checks; Gatekeeper `ConstraintTemplate` export
- [ ] Per-version PSS semantics; RBAC path analysis in Neo4j

## Safety

STRATUM is defensive and analytical:

- The analysis path makes no network calls and never mutates a cluster. Generated NetworkPolicies are printed for review.
- The data scripts only make anonymous reads of public registries, GitHub and CISA.
- Images are pulled only so that Trivy can read them as files. Nothing is executed.
- No malware or exploit code is downloaded or included. ADFA-LD holds integer syscall traces, and the Tetragon samples are JSON logs.
- The optional `deploy/k8s` manifests are for a local kind/minikube lab only.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).

## Contributing and licence

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md). Licensed under [MIT](LICENSE).
