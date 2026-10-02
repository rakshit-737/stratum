# Evaluation

All numbers come from `python -m stratum bench` on the real corpus, the live CI job and the reproduction workflow; the raw tables are in `results/`. Each subsection states its method, sample size and confidence interval.


| What | Result | Baseline (previous version or naive method) |
|---|---|---|
| **Live cluster (CI): runtime alert → commit from the Sigstore certificate** | **5 / 5** independent kind clusters trace every demo-pod incident (55 incidents) to the commit (Wilson 95% CI over runs 0.57-1.00; incidents within a run share one digest and certificate, so they are not independent); unsigned `drift` control: 0 / 5 traced, ZT-PROV-01 named 5 / 5; Gatekeeper denies the privileged pod 5 / 5; `stratum prevent` egress policy blocks the external sink 5 / 5 | before this round the commit was injected by the workflow (circular) |
| Policy engine vs upstream PSS conformance fixtures (148 pods, v1.37) | **F1 1.000** at baseline and restricted (a conformance gate) | v0.1 heuristic: recall 0.147 / 0.105 |
| Posture of 31 real projects in their default configuration | **32 / 87** workloads not PSS-restricted (7 privileged); 26 of 29 namespaces with no egress policy; 24 workloads with cluster-wide secret read or RBAC escalation | v0.1 heuristic flags 7 / 87 |
| Rego mirror vs Python engine on the full corpus | **292 / 292 identical findings** (OPA 1.21, [`results/opa.md`](https://github.com/rakshit-737/stratum/blob/main/results/opa.md)) | n/a |
| Trace pod → verified commit (86 real images, no runtime event) | 25 images (29%) carry a revision that GitHub confirms; **23 / 87 workloads** (CI 0.18-0.37) traced end to end, 19 of them on to the merged PR | `tag == git tag`: right for 21 of those 25, no answer for 4 |
| Runtime rules on real Tetragon events (30 events, 20 attack; **in-sample**, rules written on these events) | recall 0.80 [0.58, 0.92], precision 0.89 [0.67, 0.97]; **0 of 18 incidents reach a commit** (no provenance on those images) | v0.1 rules: recall 0.40 [0.22, 0.61], precision 0.80 [0.49, 0.94] |
| Syscall anomaly model on ADFA-LD (4,372 normal / 746 attack) | n-gram novelty n=5: AUC 0.822 (0.803-0.841); n=3: TPR 0.18 at 1% FPR | **STIDE n=6 wins on AUC**: 0.827 (0.811-0.844), paired difference +0.005 (0.002-0.009) |
| Reproduction of Kim et al. 2016 (LSTM ensemble, ADFA-LD) | **under-trained, inconclusive**: AUC 0.709 ± 0.003 over 3 seeds (max 12 CPU epochs, still improving); a convergence re-run is in progress | paper: 0.928 |
| Trivy + CISA KEV on 49 real images | 10 critical / 156 high unique CVE × package pairs (15 / 432 summed per image); **0** KEV hits; Alpine 3.24.1 → 8-workload blast radius | n/a |
| Latency, full analysis of the real corpus (470 nodes, 504 edges) | about 10 ms (3.5-14 ms across laptop runs), plus 1-8 s to load the corpus | n/a |

The full tables are in [`results/RESULTS.md`](https://github.com/rakshit-737/stratum/blob/main/results/RESULTS.md) and are regenerated with `python -m stratum bench`.

<p>
![PSS conformance: STRATUM F1 1.0 vs v0.1 heuristic](figures/pss_conformance.png){ width="49%" }
![Zero-Trust findings across 31 real projects](figures/posture_controls.png){ width="49%" }
</p>
<p>
![Provenance coverage funnel for 86 real images](figures/provenance_funnel.png){ width="49%" }
![ADFA-LD ROC curves](figures/adfa_roc.png){ width="49%" }
</p>


## Results in detail


### 1. Policy engine: Pod Security Standards conformance

The upstream PSA fixtures are Pods that the reference admission plugin must accept or reject.

| level | engine | fixtures | precision | recall | F1 |
|---|---|---:|---:|---:|---:|
| baseline | **STRATUM** | 49 | 1.000 | 1.000 | **1.000** |
| baseline | v0.1 heuristic | 49 | 1.000 | 0.147 | 0.256 |
| restricted | **STRATUM** | 99 | 1.000 | 1.000 | **1.000** |
| restricted | v0.1 heuristic | 99 | 1.000 | 0.105 | 0.191 |

Every failing fixture is also attributed to the right check (100%). A faithful port *should* reach 1.0, so this result is a conformance and regression gate, not a skill claim ([ADR 0003](adr/0003-pss-reimplementation-and-conformance.md)).

### 2. Posture of real open-source projects (default configuration)

| control | findings | observation |
|---|---:|---|
| ZT-PROV-03 digest pinning | 76 | Only ingress-nginx, knative and tekton pin images by `@sha256` |
| ZT-ID-02 token automount on privileged identity | 47 | Operators mount tokens for SAs that hold cluster-wide rights |
| ZT-NET-01 default-deny egress | 29 (per-project findings; 26 distinct namespaces) | Only flux2 and the Bitnami charts ship NetworkPolicies by default |
| ZT-ID-04 cluster-wide secret read / escalation | 24 | 50 service-account grants include secret read; 9 have `*` verbs on `*` resources |
| ZT-WL-02 not PSS-restricted | 24 | Online Boutique (12/12), Vault, Jenkins, dashboard, trivy-operator |
| ZT-ID-01 default service account | 10 | Harbor (7 workloads) |
| ZT-WL-01 privileged / PSS-baseline violation | 8 | CNI and storage daemons (calico, flannel, metallb, longhorn), falco, tetragon |
| ZT-ID-03 cluster-admin | 2 | flux2's kustomize/helm controllers (by design) |

Of the 87 workloads, 55 reach PSS *restricted*, 25 *baseline* and 7 only *privileged*. The v0.1 heuristic would have flagged 7 workloads; PSS flags 32. The per-project table is in [`results/posture.md`](https://github.com/rakshit-737/stratum/blob/main/results/posture.md).

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

23 of 87 workloads trace end to end. For example: `pod flux-system/kustomize-controller → image ghcr.io/fluxcd/kustomize-controller:v1.9.5 → commit d5d5d2b (PR #1732)`. For the 25 images with a verified embedded commit, the naive `image tag == git tag` heuristic agreed on 21 and had no matching tag for 4. The heuristic is right when it answers, but it cannot tell you when it is guessing. STRATUM only draws an edge that GitHub confirms ([ADR 0004](adr/0004-provenance-sources.md)).

### Image scans (Trivy + CISA KEV)

49 of the 86 images were scanned: 1.45 GB pulled, smallest image first. The 37 larger images were skipped by the download budget; the largest are Falco driver-loader, Jenkins, argo-cd, Vault and Harbor. The first row sums per-image findings (each image counts a CVE × package pair once); across the corpus there are 10 critical, 156 high, 157 medium and 98 low unique pairs.

| critical | high | medium | low | images with a critical | images with a CISA KEV CVE | images that ship a shell |
|---:|---:|---:|---:|---:|---:|---:|
| 15 | 432 | 342 | 326 | 7 / 49 | **0 / 49** (KEV 2026.09.25, 1,726 CVEs) | 18 / 49 |

- **Most exposed:**
  - `kubernetesui/metrics-scraper:v1.0.8` (5 critical, 68 high). It is still referenced by the Dashboard v2.7.0 manifest.
  - `ghcr.io/dexidp/dex:v2.45.1` (4 critical, 66 high).
  - `redis:8.2.3-alpine` (2 critical), bundled by argo-cd.
- **Blast radius from the graph:**
  - The `alpine 3.24.1` base OS release (as reported by Trivy, not a shared layer digest) sits under 8 workloads in four projects (flannel, Online Boutique, the Vault agent injector, a Jenkins chart test pod), so a single Alpine 3.24.1 advisory reaches all 8.
  - `debian 13.6` (distroless) sits under cert-manager, kube-state-metrics and sealed-secrets.
- **Distroless:** 6 images have no OS package database at all.
- **Shells:** 18 images still ship `busybox` or `bash`. That is what `ZT-IMG-02` flags and what the `R-SHELL` rule then catches at runtime.

![Most-exposed scanned images](figures/scans_top_images.png){ width="60%" }

### 4. Runtime: real Tetragon events

The events come from the attack chain in *Security Observability with eBPF*:

1. a privileged pod,
2. `nsenter -t 1` into the host,
3. a Merlin C2 agent in an unmanaged container,
4. 7z, scp and an ssh-tunnel exfiltration,

plus benign workload events. Labels are ours ([`benchmarks/labels/tetragon.json`](https://github.com/rakshit-737/stratum/blob/main/benchmarks/labels/tetragon.json)).

| rule set | TP | FP | FN | precision | recall |
|---|---:|---:|---:|---:|---:|
| **STRATUM** (9 rules) | 16 | 2 | 4 | **0.89** [0.67, 0.97] | **0.80** [0.58, 0.92] |
| v0.1 (shell / SA token / egress) | 8 | 2 | 12 | 0.80 [0.49, 0.94] | 0.40 [0.22, 0.61] |

Brackets are Wilson 95% CIs. None of the 18 incidents reaches a commit: the images in this sample (`nginx:latest`, an Isovalent demo image, two unmanaged containers) carry no provenance. Runtime → commit is shown on the live cluster (section 6).

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

**Caveat:** there are only 30 events, and the rules were written with these events in view. Read this as a coverage demonstration, not a held-out evaluation ([ADR 0006](adr/0006-runtime-rules-plus-novelty.md)).

### 5. Syscall anomaly model on ADFA-LD

The models were fit on the 833 normal training traces and scored on 4,372 normal and 746 attack traces. No attack data was used for fitting or tuning.

95% confidence intervals come from a stratified percentile bootstrap over the test traces (500 resamples). The Isolation Forest is the only stochastic model; its AUC is also given as mean ± sd over seeds 0-4.

| detector | ROC-AUC [95% CI] | TPR @1% FPR [95% CI] | TPR @5% FPR [95% CI] | TPR @15% FPR |
|---|---:|---:|---:|---:|
| STIDE n=6 (Forrest et al. 1996), baseline | **0.827** [0.811, 0.844] | 0.000 [0.000, 0.000] | 0.218 [0.186, 0.251] | **0.627** |
| STRATUM n-gram novelty n=5 | 0.822 [0.803, 0.841] | 0.082 [0.055, 0.133] | 0.241 [0.205, 0.275] | 0.564 |
| STRATUM n-gram novelty n=3 | 0.799 [0.780, 0.818] | **0.176** [0.107, 0.214] | 0.265 [0.232, 0.306] | 0.537 |
| STIDE n=3 | 0.695 [0.672, 0.721] | 0.170 [0.110, 0.209] | **0.318** [0.271, 0.359] | 0.576 |
| Isolation Forest, TF-IDF 1..3-grams (seed 0) | 0.568 [0.547, 0.588] | 0.001 [0.000, 0.005] | 0.039 [0.024, 0.062] | 0.172 |
| Isolation Forest, seeds 0-4 | 0.483 ± 0.068 | | | |

**Honest read:**

- STIDE n=6 has a slightly but significantly higher AUC than novelty n=5: a paired, stratified bootstrap on the same traces gives +0.005 (95% CI 0.002-0.009, p≈0.002). Their separate CIs overlap, but that is not a test of the difference. In practice the gap is negligible.
- On 10 random re-splits (fresh 833-trace training sets, Nadeau-Bengio corrected CIs) the order flips: novelty n=5 0.808 [0.785, 0.831] vs STIDE n=6 0.784 [0.750, 0.819]. Neither result is robust enough to claim a winner.
- STIDE n=6's "0.000 at 1% FPR" is a tie artefact: 69 normal and 28 attack traces score exactly 1.0. With ties broken at random, its TPR at exactly 1% FPR is 0.024 [0.015, 0.035]. The n=3 variants detect about 0.17-0.18 there; the paired difference novelty n=3 minus STIDE n=3 is +0.004 [-0.021, +0.027], so the low-FPR edge comes from the shorter window, not the frequency weighting.
- The Isolation Forest is no better than chance once seed variance is counted (0.483 ± 0.068; the figure shows seed 0, the best of five).

**Against published ADFA-LD results** (false-alarm rate at 90% detection; published figures as summarised by Kim et al. 2016 from Creech & Hu 2014, whose full text we could not access):

| system | FAR @ 90% DR |
|---|---:|
| STIDE (published) | 0.23 |
| STIDE n=6 (this repo, partial reproduction) | 0.267 [0.248, 0.306] |
| STRATUM novelty n=5 | 0.278 [0.248, 0.338] |
| HMM (published) | 0.42 |
| ELM with semantic features (published) | 0.13 |

Our STIDE is close to the published STIDE but a few points worse; ELM uses semantic features and a different decision engine.

**Reproduction of Kim et al. 2016** ("LSTM-based system-call language modeling and robust ensemble method", arXiv:1611.01726). Same split (833 / 4,372 / 746), architectures (1×200, 1×400, 2×400 LSTMs), optimiser and ensemble rule; run per seed in GitHub Actions on CPU (`repro-kim.yml`).

| method | paper AUC | reproduction AUC (3 seeds, mean ± sd) |
|---|---:|---:|
| leaky-ReLU ensemble (proposed) | 0.928 | **0.709 ± 0.003** |
| averaging ensemble | 0.890 | 0.634 ± 0.010 |
| single LSTM 1×200 | figure only | 0.731 ± 0.018 |

The result is **under-trained, inconclusive**, not a failed reproduction: it does not yet test the published setup. A re-run with early stopping to convergence (max 200 epochs, 3 seeds) is queued in [`repro-kim.yml`](https://github.com/rakshit-737/stratum/blob/main/.github/workflows/repro-kim.yml). Known deviations: 12 epochs on CPU (every model was still improving at the last epoch, so they are under-trained), 750 traces for fitting with 83 held out for early stopping, batch 32, voting ensemble not reproduced. Full table: [`results/kim_lstm.md`](https://github.com/rakshit-737/stratum/blob/main/results/kim_lstm.md). This is why STRATUM alerts on rules and uses anomaly scores only as `medium` context.

### 6. Live cluster in CI: kind + Tetragon + Gatekeeper + cosign

[`live.yml`](https://github.com/rakshit-737/stratum/blob/main/.github/workflows/live.yml) runs on every push and on demand with N independent clusters. It builds and pushes a demo image, signs it keyless with cosign (GitHub OIDC), deploys it to kind with Tetragon and Gatekeeper (using STRATUM's exported ConstraintTemplate), runs benign attack-shaped actions in the pod (a shell, a read of the pod's own service-account token, `nc` to an in-cluster sink), and runs STRATUM on the real Tetragon events. The image → CI run → commit edges are read from the verified Fulcio certificate; `github.sha` is only the expected value. Walkthrough: [docs/how-it-works.md](how-it-works.md).

| check (run [37005766853](https://github.com/rakshit-737/stratum/actions/runs/37005766853), 5 clusters) | result |
|---|---:|
| runs passing every assertion | 5 / 5 (Wilson 0.57-1.00) |
| R-SHELL, R-SA-TOKEN, R-NETTOOL raised for their scripted action | 5 / 5 each |
| demo-pod incidents traced to the expected commit, from the certificate | **5 / 5 runs** (Wilson 0.57-1.00); 55 / 55 incidents, count only |
| detections on the benign sink pod | 0 |
| unsigned `drift` workload (same command, digest-pinned busybox): traced to a commit / names ZT-PROV-01 | 0 / 5, 5 / 5 |
| external egress allowed before, blocked after the `stratum prevent` policy; in-cluster sink kept | 5 / 5, 5 / 5 |
| Gatekeeper (exported template) denies the privileged `hostPID` pod | 5 / 5 |
| cosign verify: right identity passes, wrong identity fails | 5 / 5 |

This is a scripted pipeline check on real sensor output, not a detection-rate study. The live run also found two real bugs, both fixed: Gatekeeper rejected 1.0.0's template (`import rego.v1`), and the kernel reports the projected token path `..<timestamp>/token`, which the old R-SA-TOKEN rule missed. Details: [`results/live.md`](https://github.com/rakshit-737/stratum/blob/main/results/live.md), [docs/live.md](live.md).


## Prior art

| Existing | What it does well | Gap STRATUM explores |
|---|---|---|
| Falco / Falcosidekick | Runtime rules on syscalls | No build lineage and no control mapping |
| Cilium Tetragon | eBPF runtime observability and enforcement | Not fused with CI provenance or control coverage (STRATUM ingests its events) |
| Kubescape / kube-bench / Polaris | Posture and config scanning | No runtime → code trace |
| Kyverno / Gatekeeper / PSA | Admission enforcement (including PSS) | Enforces, but does not explain incidents across the lifecycle |
| Trivy / Grype / Syft | Image CVEs and SBOMs | Image-centric, with no workload identity or runtime link |
| Sigstore / SLSA | Signing and provenance formats | Formats, not an incident graph |
| Wiz / Prisma / Sysdig (CNAPP) | This exact space, commercially | Closed and commercial; Prisma and Sysdig rely on agents, Wiz is mainly agentless with an optional sensor |

STRATUM does not compete with commercial CNAPPs. It is a small, readable, graph-centric slice of the idea: every runtime alert is joined to build provenance that can be checked (a Sigstore certificate or a GitHub-confirmed commit) and to the specific Zero-Trust control that failed.

