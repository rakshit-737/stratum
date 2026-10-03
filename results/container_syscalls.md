### Container syscall traces recorded in CI (5 runs, seeds [1, 2, 3, 4, 5], 600 normal / 200 attack-shaped)

Protocol: leave-one-run-out; fit on normal traces of the other runs. Traces are `strace -f` syscall names from `docker exec` into a container on an internal Docker network on the runner (not eBPF/Tetragon). Attack traces are benign, scripted actions, so this measures separation of a small, known action set, not detection of real intrusions. The 600 normal traces contain 14 distinct sequences; intervals resample whole clusters (attack: action type x run; normal: identical sequence x run), not traces.

| Detector | Action types separated (Wilson 95% CI) | AUC mean (min-max over runs) | AUC cluster 95% CI | TPR at 1% FPR mean (min-max) | cluster 95% CI |
|---|---:|---:|---:|---:|---:|
| STIDE n=6 (baseline) | 4/5 [0.38, 0.96] | 0.900 (0.899-0.900) | 0.820-0.960 | 0.802 (0.800-0.802) | 0.643-0.921 |
| STIDE n=3 | 4/5 [0.38, 0.96] | 0.900 (0.899-0.900) | 0.820-0.960 | 0.802 (0.800-0.802) | 0.643-0.921 |
| STRATUM n-gram novelty n=3 | 4/5 [0.38, 0.96] | 0.848 (0.844-0.853) | 0.707-0.946 | 0.800 (0.800-0.800) | 0.640-0.920 |
| STRATUM n-gram novelty n=5 | 4/5 [0.38, 0.96] | 0.826 (0.820-0.847) | 0.671-0.938 | 0.800 (0.800-0.800) | 0.640-0.920 |

Per attack action, AUC against the fold's normal traces (mean over runs); a dagger marks an action separated from every normal trace in every fold:

| Detector | shell + recon (id, uname, read /etc/passwd) | cat the dummy service-account token | nc to the in-cluster sink | fetch a dummy script and chmod +x it | find token files + ps |
|---|---:|---:|---:|---:|---:|
| STIDE n=6 (baseline) | 1.000 † | 0.499 | 1.000 † | 1.000 † | 1.000 † |
| STIDE n=3 | 1.000 † | 0.499 | 1.000 † | 1.000 † | 1.000 † |
| STRATUM n-gram novelty n=3 | 1.000 † | 0.238 | 1.000 † | 1.000 † | 1.000 † |
| STRATUM n-gram novelty n=5 | 1.000 † | 0.128 | 1.000 † | 1.000 † | 1.000 † |

Source: traces recorded by https://github.com/rakshit-737/stratum/actions/runs/37089906503, evaluated by https://github.com/rakshit-737/stratum/actions/runs/37089906503, at commit `4795f5c`.
