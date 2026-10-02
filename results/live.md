### Live kind + Tetragon: 5 independent runs (separate kind clusters, one GitHub Actions run)

| Check | Result | Wilson 95% CI |
|---|---:|---:|
| Runs passing every assertion | 5/5 | [0.57, 1.00] |
| R-SHELL raised for its scripted action (kubectl exec ... sh) | 5/5 | [0.57, 1.00] |
| R-SA-TOKEN raised for its scripted action (cat the projected SA token) | 5/5 | [0.57, 1.00] |
| R-NETTOOL raised for its scripted action (nc to the in-cluster sink) | 5/5 | [0.57, 1.00] |
| Runs whose demo-pod incidents all trace to the expected commit (read from the cosign certificate) | 5/5 | [0.57, 1.00] |
| Demo-pod incidents traced (count only; clustered by run, so no CI) | 55/55 | - |
| Detections on the benign sink pod | 0 | - |
| Unsigned `drift` incidents traced to any commit (negative control, want 0) | 0/5 | - |
| `drift` incidents name ZT-PROV-01 | 5/5 runs | - |
| External egress allowed before, blocked after `stratum prevent` policy | 5/5 | - |
| In-cluster sink still reachable after the policy | 5/5 | - |
| Gatekeeper denied the privileged pod | 5/5 | - |
| cosign keyless verify (right identity passes, wrong identity fails) | 5/5 | - |

Example trace: `pod:stratum-live/web-648f98c58b-2d8pm -> workload:stratum-live/web -> image:ghcr.io/rakshit-737/stratum-live-demo@sha256:0af18ddccb7815d78022f7ab1ea48718d6b0d878441e96eab21740ce20e680b5 -> build:37005473899 -> commit:c863fbc4af6d3a87b6946d84b6459d819e620c68`

Results were produced at commit `c863fbc` (the commit the demo image was built from); later commits changed docs and aggregation only unless noted.

Run: https://github.com/rakshit-737/stratum/actions/runs/37005766853
