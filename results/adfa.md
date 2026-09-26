### Syscall anomaly detection on ADFA-LD (833 train / 4372 normal test / 746 attack traces)

95% CIs: stratified percentile bootstrap over test traces (500 resamples, seed 0). Isolation Forest: seed 0 shown, AUC mean ± sd over seeds 0-4 in the last column.

| detector | ROC-AUC [95% CI] | TPR @1% FPR [95% CI] | TPR @5% FPR [95% CI] | TPR @15% FPR | seed AUC mean ± sd |
|---|---:|---:|---:|---:|---:|
| STIDE n=6 (baseline, Forrest 1996) | 0.827 [0.811, 0.844] | 0.000 [0.000, 0.000] | 0.218 [0.186, 0.251] | 0.627 | deterministic |
| STIDE n=3 | 0.695 [0.672, 0.721] | 0.170 [0.110, 0.209] | 0.318 [0.271, 0.359] | 0.576 | deterministic |
| STRATUM n-gram novelty n=3 | 0.799 [0.780, 0.818] | 0.176 [0.107, 0.214] | 0.265 [0.232, 0.306] | 0.537 | deterministic |
| STRATUM n-gram novelty n=5 | 0.822 [0.803, 0.841] | 0.082 [0.055, 0.133] | 0.241 [0.205, 0.275] | 0.564 | deterministic |
| Isolation Forest, TF-IDF 1..3-grams | 0.568 [0.547, 0.588] | 0.001 [0.000, 0.005] | 0.039 [0.024, 0.062] | 0.172 | 0.483 ± 0.068 |

Per attack family, TPR at 5% FPR:

| detector | Adduser | Hydra_FTP | Hydra_SSH | Java_Meterpreter | Meterpreter | Web_Shell |
|---|---:|---:|---:|---:|---:|---:|
| STIDE n=6 (baseline, Forrest 1996) | 0.14 | 0.33 | 0.28 | 0.10 | 0.13 | 0.21 |
| STIDE n=3 | 0.33 | 0.40 | 0.28 | 0.25 | 0.25 | 0.37 |
| STRATUM n-gram novelty n=3 | 0.25 | 0.36 | 0.31 | 0.18 | 0.13 | 0.25 |
| STRATUM n-gram novelty n=5 | 0.17 | 0.35 | 0.29 | 0.17 | 0.13 | 0.22 |
| Isolation Forest, TF-IDF 1..3-grams | 0.00 | 0.03 | 0.13 | 0.00 | 0.00 | 0.02 |
