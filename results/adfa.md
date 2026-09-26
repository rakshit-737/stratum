### Syscall anomaly detection on ADFA-LD (833 train / 4372 normal test / 746 attack traces)

| detector | ROC-AUC | TPR @1% FPR | TPR @5% FPR | TPR @15% FPR |
|---|---:|---:|---:|---:|
| STIDE n=6 (baseline, Forrest 1996) | 0.827 | 0.000 | 0.218 | 0.627 |
| STIDE n=3 | 0.695 | 0.170 | 0.318 | 0.576 |
| STRATUM n-gram novelty n=3 | 0.799 | 0.176 | 0.265 | 0.537 |
| STRATUM n-gram novelty n=5 | 0.822 | 0.082 | 0.241 | 0.564 |
| Isolation Forest, TF-IDF 1..3-grams | 0.568 | 0.001 | 0.039 | 0.172 |

Per attack family, TPR at 5% FPR:

| detector | Adduser | Hydra_FTP | Hydra_SSH | Java_Meterpreter | Meterpreter | Web_Shell |
|---|---:|---:|---:|---:|---:|---:|
| STIDE n=6 (baseline, Forrest 1996) | 0.14 | 0.33 | 0.28 | 0.10 | 0.13 | 0.21 |
| STIDE n=3 | 0.33 | 0.40 | 0.28 | 0.25 | 0.25 | 0.37 |
| STRATUM n-gram novelty n=3 | 0.25 | 0.36 | 0.31 | 0.18 | 0.13 | 0.25 |
| STRATUM n-gram novelty n=5 | 0.17 | 0.35 | 0.29 | 0.17 | 0.13 | 0.22 |
| Isolation Forest, TF-IDF 1..3-grams | 0.00 | 0.03 | 0.13 | 0.00 | 0.00 | 0.02 |
