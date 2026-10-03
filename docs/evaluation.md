# Evaluation

The numbers come from `python -m stratum bench` on the real corpus (`results/RESULTS.md`), the live CI job (`results/live.md`), the Kim et al. reproduction (`results/kim_lstm.md`) and the container syscall workflow (`results/container_syscalls.md`); each result file records the run and commit that produced it. Proportions carry Wilson 95% intervals and model scores bootstrap or corrected-t intervals; counts that are deterministic or fully observed (posture findings, scan totals, the provenance funnel) are reported as counts.


STRATUM's syscall configuration is fixed in advance as n-gram novelty n=5; other variants appear only in the detail tables.

| What | Result | Baseline or comparison |
|---|---|---|
| **Live (CI): demo-pod alerts → commit read from each job's own Sigstore certificate** | **5 / 5 runs** fully traced (Wilson 95% CI 0.57-1.00), 55 / 55 incidents; 5 distinct certificates over 5 distinct digests ([`results/live.md`](https://github.com/rakshit-737/stratum/blob/main/results/live.md), run 37085766270) | 1.0.0: commit injected by the workflow (circular); 1.1.0's published run: one certificate reused in 5 clusters, no run-level CI |
| **Live negative controls**: unsigned upstream `drift` image; unsigned `forged` image with the right revision label | 0 / 5 and 0 / 5 incidents traced; ZT-PROV-01 named in 5 / 5 runs each (0.57-1.00) | label provenance (A2) and a repository join (A4) trace `forged` to the commit in 5 / 5 runs; A3 (STRATUM) in 0 / 5 |
| Live Gatekeeper and prevention | exported template denies the privileged pod 5 / 5; `stratum prevent` policy blocks the external sink and keeps in-cluster traffic 5 / 5 (each 0.57-1.00); 0 detections on the benign sink pod | n/a |
| Policy engine vs upstream PSS conformance fixtures (148 pods, v1.37) | **F1 1.000** at baseline and restricted (a conformance gate, deterministic) | v0.1 heuristic: recall 0.147 / 0.105 |
| Posture of 31 real projects in their default configuration | **32 / 87** workloads not PSS-restricted (7 privileged); 26 of 29 namespaces with no egress policy; 24 workloads with cluster-wide secret read or RBAC escalation (counts over the whole corpus) | v0.1 heuristic flags 7 / 87 |
| Rego mirror vs Python engine on the full corpus | **290 / 290 identical findings** (OPA 1.21, [`results/opa.md`](https://github.com/rakshit-737/stratum/blob/main/results/opa.md)) | n/a |
| Trace pod → verified commit (86 real images, no runtime event) | 25 / 86 images (Wilson 0.21-0.39) carry a revision GitHub confirms; 23 / 87 workloads (0.18-0.37) from **11 / 31 projects** (0.21-0.53) traced end to end | `tag == git tag` answers for 36 / 86 images (0.32-0.52) and agrees 21 / 21 where both answer; its other 15 answers cannot be verified |
| Runtime rules on real Tetragon events (30 events, 20 attack; **in-sample**, rules written on these events) | recall 0.80 [0.58, 0.92], precision 0.89 [0.67, 0.97]; **0 of 18 incidents reach a commit** (no provenance on those images) | v0.1 rules: recall 0.40 [0.22, 0.61], precision 0.80 [0.49, 0.94] |
| Syscall model on ADFA-LD (4,372 normal / 746 attack), novelty n=5 | AUC 0.822 [0.803, 0.841]; TPR 0.082 [0.055, 0.133] at 1% FPR | **split-dependent**: STIDE n=6 ahead on the official split (0.827, paired +0.005 [0.002, 0.009], p ≈ 0.004); novelty n=5 ahead on 10 / 10 random re-splits (+0.023, corrected CI [0.001, 0.046], p ≈ 0.04) |
| Container syscall traces (`strace` in Docker, 5 runs, leave-one-run-out), novelty n=5 | AUC 0.826 (0.820-0.847 over runs; cluster bootstrap 0.67-0.94); separates 4 / 5 scripted action types (0.38-0.96) | **STIDE n=6 is better**: 0.900 (0.820-0.960); one action (`cat` of the token) is syscall-identical to a routine `cat` ([run 37089906503](https://github.com/rakshit-737/stratum/actions/runs/37089906503)) |
| Reproduction of Kim et al. 2016 (LSTM ensemble, ADFA-LD) | **not reproduced**: AUC 0.812 ± 0.005 over 3 seeds; every per-seed bootstrap CI (0.790-0.838) excludes 0.928 ([run 37007358324](https://github.com/rakshit-737/stratum/actions/runs/37007358324), max 200 epochs) | paper: 0.928 |
| Trivy + CISA KEV on 49 real images | 10 critical / 156 high unique CVE × package pairs (15 / 432 summed per image); **0** KEV hits; Alpine 3.24.1 → 8-workload blast radius (counts) | n/a |
| Latency, full analysis of the real corpus (470 nodes, 504 edges) | median 21 ms (12-82 ms over 20 repeats) plus 4.8 s (4.7-5.4 s) to load the corpus, on a shared Windows laptop ([`results/perf.md`](https://github.com/rakshit-737/stratum/blob/main/results/perf.md)) | n/a |

The corpus tables are in [`results/RESULTS.md`](https://github.com/rakshit-737/stratum/blob/main/results/RESULTS.md) (regenerated with `python -m stratum bench`; each section names its commit and dataset manifest). The live, Kim et al. and container syscall results come from GitHub Actions runs: [`results/live.md`](https://github.com/rakshit-737/stratum/blob/main/results/live.md), [`results/kim_lstm.md`](https://github.com/rakshit-737/stratum/blob/main/results/kim_lstm.md), [`results/container_syscalls.md`](https://github.com/rakshit-737/stratum/blob/main/results/container_syscalls.md).

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
| signature artefact published (cosign `.sig` tag 32, Sigstore bundle referrer 7) | 39 | 45 |
| attestation artefact published (cosign `.att`, Sigstore bundle or in-toto referrer) | 44 | 51 |
| BuildKit attestation manifest in the image index (unsigned) | 31 | 36 |

Signature and attestation rows count published artefacts; none is verified for third-party images. Until this release only the legacy cosign tags were probed, which missed cosign v3 bundles: 22 images changed on re-check (signatures 32 → 39, attestations 28 → 44), and STRATUM's own signed v1.1.0 image had been reported as unsigned.

23 of 87 workloads trace end to end (Wilson 0.18-0.37). They come from 11 of 31 projects (0.21-0.53) and 22 images, so the workload interval treats correlated workloads as independent; the project-level rate is the safer figure. For example: `pod flux-system/kustomize-controller → image ghcr.io/fluxcd/kustomize-controller:v1.9.5 → commit d5d5d2b (PR #1732)`.

**Baseline, the naive `image tag == git tag` heuristic.** It names a commit for 36 / 86 images (Wilson 0.32-0.52) against 25 / 86 (0.21-0.39) for STRATUM's verified embedded revision. Where both answer (21 images) they agree 21 / 21; the heuristic has no answer for 4 of STRATUM's 25, and its other 15 answers cannot be checked against any embedded revision. It covers more images, but a tag is a mutable name, not evidence of what was built: the trade-off is coverage against verifiability. STRATUM only draws an edge that GitHub confirms ([ADR 0004](adr/0004-provenance-sources.md)).

### 4. Image scans (Trivy + CISA KEV)

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

### 5. Runtime: real Tetragon events

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

Brackets are Wilson 95% CIs. None of the 18 incidents reaches a commit: the images in this sample (`nginx:latest`, an Isovalent demo image, two unmanaged containers) carry no provenance. Runtime → commit is shown on the live cluster (section 8).

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

### 6. Syscall anomaly model on ADFA-LD

The models were fit on the 833 normal training traces and scored on 4,372 normal and 746 attack traces. No attack data was used for fitting or tuning.

95% confidence intervals come from a stratified percentile bootstrap over the test traces (500 resamples). The Isolation Forest is the only stochastic model: its row shows the median-AUC seed of five, and its AUC is also given as mean ± sd over seeds 0-4 (per-seed values in [`results/adfa.json`](https://github.com/rakshit-737/stratum/blob/main/results/adfa.json)). Novelty n=5 is STRATUM's configuration; the other rows are reported because they were run.

| detector | ROC-AUC [95% CI] | TPR @1% FPR [95% CI] | TPR @5% FPR [95% CI] | TPR @15% FPR |
|---|---:|---:|---:|---:|
| STIDE n=6 (Forrest et al. 1996), baseline | **0.827** [0.811, 0.844] | 0.000 [0.000, 0.000] | 0.218 [0.186, 0.251] | **0.627** |
| STRATUM n-gram novelty n=5 | 0.822 [0.803, 0.841] | 0.082 [0.055, 0.133] | 0.241 [0.205, 0.275] | 0.564 |
| STRATUM n-gram novelty n=3 | 0.799 [0.780, 0.818] | **0.176** [0.107, 0.214] | 0.265 [0.232, 0.306] | 0.537 |
| STIDE n=3 | 0.695 [0.672, 0.721] | 0.170 [0.110, 0.209] | **0.318** [0.271, 0.359] | 0.576 |
| Isolation Forest, TF-IDF 1..3-grams (median seed, 4) | 0.499 [0.476, 0.522] | 0.008 [0.001, 0.016] | 0.051 [0.034, 0.071] | 0.192 |
| Isolation Forest, seeds 0-4 | 0.483 ± 0.068 | | | |

**Honest read:**

- On the official split STIDE n=6 has a slightly but significantly higher AUC than novelty n=5: a paired, stratified bootstrap on the same traces gives +0.005 (95% CI 0.002-0.009, p ≈ 0.004 with B = 1000). Their separate CIs overlap, but that is not a test of the difference.
- On 10 random re-splits (fresh 833-trace training sets, the same splits for both detectors) the order flips: novelty n=5 minus STIDE n=6 is +0.023, Nadeau-Bengio corrected 95% CI [0.001, 0.046], corrected t p = 0.044, positive in 10 / 10 splits (sign test p = 0.002). Unpaired: novelty n=5 0.808 [0.785, 0.831], STIDE n=6 0.784 [0.750, 0.819]. **The ranking depends on the split**: neither detector wins in general, and the official-split edge of STIDE is the smaller effect.
- STIDE n=6's "0.000 at 1% FPR" is a tie artefact: 69 normal and 28 attack traces score exactly 1.0. With ties broken at random, its TPR at exactly 1% FPR is 0.024 [0.015, 0.035]. The n=3 variants detect about 0.17-0.18 there (novelty n=3 0.176, STIDE n=3 0.171); their paired difference is +0.004 [-0.021, +0.027], so the low-FPR edge comes from the shorter window, not the frequency weighting.
- The Isolation Forest is no better than chance once seed variance is counted (0.483 ± 0.068 over five seeds; the median seed scores 0.499). Earlier versions showed seed 0 (0.568), the best of the five.
- Re-split intervals for TPR at 1% FPR are clipped to [0, 1]; with 10 splits they are too wide to be informative ([`results/adfa.md`](https://github.com/rakshit-737/stratum/blob/main/results/adfa.md)).

**Against published ADFA-LD results** (false-alarm rate at 90% detection; published figures as quoted by Kim et al. 2016, arXiv:1611.01726 p. 8, from Creech & Hu 2014, whose full text we could not access; Kim et al. give them as approximate):

| system | FAR @ 90% DR |
|---|---:|
| STIDE (published, as quoted by Kim et al.; primary source not verified) | ≈ 0.23 |
| STIDE n=6 (this repo; not a reproduction of Creech & Hu) | 0.267 [0.248, 0.306] |
| STRATUM novelty n=5 | 0.278 [0.248, 0.338] |
| HMM (published) | ≈ 0.42 |
| ELM with semantic features (published) | ≈ 0.13 |
| LSTM ensemble (Kim et al., published) | ≈ 0.16 |

Our STIDE is close to the published STIDE but a few points worse; ELM uses semantic features and a different decision engine.

**Reproduction of Kim et al. 2016** (G. Kim, H. Yi, J. Lee, Y. Paek, S. Yoon, "LSTM-Based System-Call Language Modeling and Robust Ensemble Method for Designing Host-Based Intrusion Detection Systems", arXiv:1611.01726). Same split (833 / 4,372 / 746), architectures (1×200, 1×400, 2×400 LSTMs), optimiser and ensemble rule; run per seed in GitHub Actions on CPU (`repro-kim.yml`), early stopping on 83 held-out training normals, at most 200 epochs ([run 37007358324](https://github.com/rakshit-737/stratum/actions/runs/37007358324), commit 0c3983f).

| method | paper AUC | reproduction AUC (3 seeds, mean ± sd, min-max) |
|---|---:|---:|
| leaky-ReLU ensemble (proposed) | 0.928 | **0.812 ± 0.005** (0.808-0.818) |
| averaging ensemble | 0.890 | 0.811 ± 0.006 (0.806-0.818) |
| single LSTM 1×200 / 1×400 / 2×400 | figure only | 0.796 / 0.809 / 0.821 |

**Not reproduced.** Every per-seed bootstrap CI of the ensemble (0.790-0.838) excludes the published 0.928. Unlike in the paper, the proposed ensemble does not beat its best member (2×400, 0.821) or plain averaging (0.811), and it is below STIDE n=6 (0.827) on the same split. The 1×200 model stopped at the 200-epoch cap in 2 of 3 seeds, so it was still improving; 1×400 and 2×400 stopped early (epochs 81-156) in every seed. Remaining deviations: 750 traces for fitting with 83 held out for early stopping (the paper does not say how it stopped), batch 32, voting ensemble not reproduced. An earlier 12-epoch run (36998236982, AUC 0.709) was under-trained. Full table: [`results/kim_lstm.md`](https://github.com/rakshit-737/stratum/blob/main/results/kim_lstm.md). This is why STRATUM alerts on rules and uses anomaly scores only as `medium` context.

### 7. Container syscall traces recorded in CI

LID-DS and CB-DS cannot be fetched non-interactively, so [`syscalls.yml`](https://github.com/rakshit-737/stratum/blob/main/.github/workflows/syscalls.yml) records a small container dataset on 5 GitHub runners ([run 37089906503](https://github.com/rakshit-737/stratum/actions/runs/37089906503), seeds 1-5 = run numbers). Each run starts an Alpine workload container and a sink on an internal Docker network and records, with `strace -f` (syscall names only, not eBPF/Tetragon), 120 traces of 9 routine commands and 8 traces each of 5 benign attack-shaped commands. Protocol: leave-one-run-out, fit on the other runs' normal traces. The 600 normal traces contain only 14 distinct sequences, so intervals resample whole clusters (attack: action × run; normal: identical sequence × run), not traces.

| detector | action types separated (Wilson 95% CI) | AUC mean (min-max over runs) | AUC cluster 95% CI | TPR at 1% FPR mean |
|---|---:|---:|---:|---:|
| STIDE n=6 (baseline) | 4 / 5 [0.38, 0.96] | **0.900** (0.899-0.900) | 0.820-0.960 | 0.802 |
| STIDE n=3 | 4 / 5 [0.38, 0.96] | 0.900 (0.899-0.900) | 0.820-0.960 | 0.802 |
| STRATUM novelty n=3 | 4 / 5 [0.38, 0.96] | 0.848 (0.844-0.853) | 0.707-0.946 | 0.800 |
| STRATUM novelty n=5 | 4 / 5 [0.38, 0.96] | 0.826 (0.820-0.847) | 0.671-0.938 | 0.800 |

**STIDE beats STRATUM's novelty scoring here.** Four action types (shell + recon, `nc`, fetch + `chmod`, `find` + `ps`) use syscalls that never occur in the routine traces, so every detector separates them completely. The fifth, `cat` of the dummy service-account token, has exactly the syscall-name sequence of the routine `cat index.html` (file paths are not recorded). STIDE scores those 20% of attacks like normals, which pins its AUC at 0.8 + 0.2 × 0.5 = 0.900 and its TPR at 1% FPR at about 0.80; novelty ranks them *below* the normals because their n-grams are frequent (per-action AUC 0.24 for n=3, 0.13 for n=5), hence its lower AUC. With five scripted actions the honest unit is the action type, not the trace. The first run of this workflow (37009536038, release 1.1.0) gives the same per-detector means when its traces are re-evaluated. Full tables: [`results/container_syscalls.md`](https://github.com/rakshit-737/stratum/blob/main/results/container_syscalls.md).

### 8. Live cluster in CI: kind + Tetragon + Gatekeeper + cosign

[`live.yml`](https://github.com/rakshit-737/stratum/blob/main/.github/workflows/live.yml) runs on every push and on demand with N jobs, each on its own runner with its own kind cluster. Each job builds and pushes its own demo image (a per-job nonce makes the digest unique) and signs it keyless with cosign (GitHub OIDC), so each job has its own Fulcio certificate. It deploys the image to kind with Tetragon and Gatekeeper (using STRATUM's exported ConstraintTemplate), runs benign attack-shaped actions in the pod (a shell, a read of the pod's own service-account token, `nc` to an in-cluster sink), and runs STRATUM on the real Tetragon events. The image → CI run → commit edges are read from the verified Fulcio certificate; `github.sha` is only the expected value, and the job fails if the certificate names another CI run. Two unsigned control workloads run the same shell: `drift` (upstream busybox) and `forged` (built in the same job from the same Dockerfile, with the right revision label). Walkthrough: [docs/how-it-works.md](how-it-works.md).

| check (run [37085766270](https://github.com/rakshit-737/stratum/actions/runs/37085766270), commit 38cc4a3, 5 jobs) | result | Wilson 95% CI |
|---|---:|---:|
| runs passing every assertion | 5 / 5 | 0.57-1.00 |
| R-SHELL, R-SA-TOKEN, R-NETTOOL raised for their scripted action | 5 / 5 each | 0.57-1.00 |
| runs whose demo-pod incidents all trace to the expected commit, read from the job's own certificate | **5 / 5** | 0.57-1.00 |
| demo-pod incidents traced (the incidents of a run share its certificate: count only) | 55 / 55 | - |
| distinct certificates / distinct image digests / CI run ids named | 5 / 5 / 1 (jobs of one workflow run share its id) | - |
| detections on the benign sink pod | 0 | - |
| unsigned `drift` (upstream busybox): incidents traced to a commit; runs naming ZT-PROV-01 | 0 / 5; 5 / 5 | -; 0.57-1.00 |
| unsigned `forged` (right revision label): incidents traced to a commit; runs naming ZT-PROV-01 | 0 / 5; 5 / 5 | -; 0.57-1.00 |
| external egress allowed before, blocked after the `stratum prevent` policy; in-cluster sink kept | 5 / 5, 5 / 5 | 0.57-1.00 each |
| Gatekeeper (exported template) denies the privileged `hostPID` pod | 5 / 5 | 0.57-1.00 |
| cosign verify: right identity passes, wrong identity fails | 5 / 5 | 0.57-1.00 |

**What each join edge adds (A0-A4, same evidence, k / 5 runs):**

| arm | evidence | demo pod → workload | demo pod → right commit | `forged` wrongly traced | provenance gap named |
|---|---|---:|---:|---:|---:|
| A0 | runtime events only | 0 / 5 | 0 / 5 | 0 / 5 | 0 / 5 |
| A1 | + cluster state (manifests, pods) | 5 / 5 | 0 / 5 | 0 / 5 | 5 / 5 |
| A2 | + label provenance (OCI revision label, unverified) | 5 / 5 | 5 / 5 | **5 / 5** | 5 / 5 |
| A3 | + certificate provenance, digest-exact (**STRATUM**) | 5 / 5 | 5 / 5 | **0 / 5** | 5 / 5 |
| A4 | certificate provenance joined by repository | 5 / 5 | 5 / 5 | **5 / 5** | 0 / 5 |

The arm outcomes are fixed by construction: `forged` carries the right label and sits in the same repository, so A2 and A4 must attribute it to the commit. The table shows the join semantics hold on real sensor output in every run; the Wilson intervals in [`results/live.md`](https://github.com/rakshit-737/stratum/blob/main/results/live.md) only bound the pipeline's repeatability, not a detection rate. A2 is what a scanner or SBOM tool that reads the revision label would conclude; A4 ablates digest-exactness and is not a competing tool.

This is a scripted pipeline check on real sensor output, not a detection-rate study, and all five images come from one commit. The live runs also found real bugs, all fixed: Gatekeeper rejected 1.0.0's template (`import rego.v1`), the kernel reports the projected token path `..<timestamp>/token` that the old R-SA-TOKEN rule missed, and the sink-pod count would have included the `forged` control's incident. Details: [`results/live.md`](https://github.com/rakshit-737/stratum/blob/main/results/live.md), [docs/live.md](live.md).


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

