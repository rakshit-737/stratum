### Live kind + Tetragon: 5 runs (one kind cluster per runner)

Each run built its own demo image (a per-run nonce makes the digest unique), signed it keyless in its own job and read the commit hop from that job's Fulcio certificate: **5 distinct certificates over 5 distinct image digests**. The certificates name CI run 37085766270 (1 workflow run(s); the jobs of one workflow run share its run id by design). Every image was built from the same commit, so the commit itself is one value: the run-level CIs cover detection, capture and the certificate join, not commit diversity.

| Check | Result | Wilson 95% CI |
|---|---:|---:|
| Runs passing every assertion | 5/5 | [0.57, 1.00] |
| R-SHELL raised for its scripted action (kubectl exec ... sh) | 5/5 | [0.57, 1.00] |
| R-SA-TOKEN raised for its scripted action (cat the projected SA token) | 5/5 | [0.57, 1.00] |
| R-NETTOOL raised for its scripted action (nc to the in-cluster sink) | 5/5 | [0.57, 1.00] |
| Runs whose demo-pod incidents all trace to the expected commit (read from the run's own certificate) | 5/5 | [0.57, 1.00] |
| Demo-pod incidents traced (count only; the incidents of one run share its certificate, so no CI) | 55/55 | - |
| Detections on the benign sink pod (count) | 0 | - |
| Unsigned upstream `drift` image: incidents traced to any commit (count, want 0) | 0/5 | - |
| `drift` incidents name ZT-PROV-01 | 5/5 runs | [0.57, 1.00] |
| Unsigned `forged` image with the right revision label: incidents traced to any commit (count, want 0) | 0/5 | - |
| `forged` incidents name ZT-PROV-01 | 5/5 runs | [0.57, 1.00] |
| External egress allowed before, blocked after the `stratum prevent` policy | 5/5 | [0.57, 1.00] |
| In-cluster sink still reachable after the policy | 5/5 | [0.57, 1.00] |
| Gatekeeper denied the privileged pod | 5/5 | [0.57, 1.00] |
| cosign keyless verify (right identity passes, wrong identity fails) | 5/5 | [0.57, 1.00] |

Example trace: `pod:stratum-live/web-5d5dc54ddb-mcspm -> workload:stratum-live/web -> image:ghcr.io/rakshit-737/stratum-live-demo@sha256:ea0dc9928ae5d3b1efe4f75d41d0bb4d36e102ad7ce8ff575cec51e080c63d35 -> build:37085766270 -> commit:38cc4a3747d9d4d026501bc2bc7d72928a925894`

#### Per run: image digest and the certificate the commit hop was read from

| Run | Image digest | Certificate serial | Rekor logIndex | Certificate SHA-256 | CI run (attempt) | Traced |
|---|---|---|---:|---|---|---:|
| live-evidence-1 | `sha256:ea0dc9928ae5…` | `669D3CDCE7D111C6…` | 3065793401 | `12dce9669b866005…` | 37085766270 (1) | 11/11 |
| live-evidence-2 | `sha256:50034e9f64e3…` | `7D8AF7192C458EB8…` | 3065793610 | `83f11437dc0eefb2…` | 37085766270 (1) | 11/11 |
| live-evidence-3 | `sha256:ac208235b30b…` | `4D69DB263B614D93…` | 3065793790 | `83749476167e5e1d…` | 37085766270 (1) | 11/11 |
| live-evidence-4 | `sha256:6b356531f791…` | `685E346113AD4650…` | 3065821833 | `225ffc7e3d7b5f51…` | 37085766270 (1) | 11/11 |
| live-evidence-5 | `sha256:2e01bc918a33…` | `055D42F5EEBBEDBD…` | 3065824450 | `0ca2230df1f0f559…` | 37085766270 (1) | 11/11 |

#### Ablation: what each join edge adds (constructed controls, k/n runs)

Each arm re-joins the same run's evidence with less (or looser) provenance. The negative controls are built so that the arms must differ: `forged` carries the right revision label and lives in the same repository as the signed image, so label provenance (A2) and a repository join (A4) attribute it to the commit by construction. The table shows that the join semantics hold on real sensor output in every run; it does not estimate a rate, and the Wilson intervals only bound the pipeline's repeatability over 5 runs.

| Arm | Evidence | Incident -> workload | Incident -> right commit | Negative control wrongly traced | Provenance gap named |
|---|---|---:|---:|---:|---:|
| A0 | runtime events only (Tetragon) | 0/5 [0.00, 0.43] | 0/5 [0.00, 0.43] | 0/5 [0.00, 0.43] | 0/5 [0.00, 0.43] |
| A1 | + cluster state (manifests, pods): pod -> workload -> image digest | 5/5 [0.57, 1.00] | 0/5 [0.00, 0.43] | 0/5 [0.00, 0.43] | 5/5 [0.57, 1.00] |
| A2 | + label provenance (OCI revision label, unverified) | 5/5 [0.57, 1.00] | 5/5 [0.57, 1.00] | 5/5 [0.57, 1.00] | 5/5 [0.57, 1.00] |
| A3 | + certificate provenance (cosign/Fulcio, digest-exact): STRATUM | 5/5 [0.57, 1.00] | 5/5 [0.57, 1.00] | 0/5 [0.00, 0.43] | 5/5 [0.57, 1.00] |
| A4 | certificate provenance joined by repository instead of digest | 5/5 [0.57, 1.00] | 5/5 [0.57, 1.00] | 5/5 [0.57, 1.00] | 0/5 [0.00, 0.43] |

A2 (label provenance: the OCI revision label that image scanners and SBOM tools read) is the realistic baseline; A4 ablates digest-exactness and is not a competing tool.

Code, images and certificates: commit `38cc4a3` (every certificate names it).
Run: https://github.com/rakshit-737/stratum/actions/runs/37085766270
