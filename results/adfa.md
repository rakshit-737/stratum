### Syscall anomaly detection on ADFA-LD (833 train / 4372 normal test / 746 attack traces)

95% CIs: stratified percentile bootstrap over test traces (500 resamples, seed 0). Isolation Forest: the median-AUC seed is shown; AUC mean ± sd over seeds 0-4 in the last column (per-seed AUCs in adfa.json).

| detector | ROC-AUC [95% CI] | TPR @1% FPR [95% CI] | TPR @5% FPR [95% CI] | TPR @15% FPR | seed AUC mean ± sd |
|---|---:|---:|---:|---:|---:|
| STIDE n=6 (baseline, Forrest 1996) | 0.827 [0.811, 0.844] | 0.000 [0.000, 0.000] | 0.218 [0.186, 0.251] | 0.627 | deterministic |
| STIDE n=3 | 0.695 [0.672, 0.721] | 0.170 [0.110, 0.209] | 0.318 [0.271, 0.359] | 0.576 | deterministic |
| STRATUM n-gram novelty n=3 | 0.799 [0.780, 0.818] | 0.176 [0.107, 0.214] | 0.265 [0.232, 0.306] | 0.537 | deterministic |
| STRATUM n-gram novelty n=5 | 0.822 [0.803, 0.841] | 0.082 [0.055, 0.133] | 0.241 [0.205, 0.275] | 0.564 | deterministic |
| Isolation Forest, TF-IDF 1..3-grams | 0.499 [0.476, 0.522] | 0.008 [0.001, 0.016] | 0.051 [0.034, 0.071] | 0.192 | 0.483 ± 0.068 |

Per attack family, TPR at 5% FPR:

| detector | Adduser | Hydra_FTP | Hydra_SSH | Java_Meterpreter | Meterpreter | Web_Shell |
|---|---:|---:|---:|---:|---:|---:|
| STIDE n=6 (baseline, Forrest 1996) | 0.14 | 0.33 | 0.28 | 0.10 | 0.13 | 0.21 |
| STIDE n=3 | 0.33 | 0.40 | 0.28 | 0.25 | 0.25 | 0.37 |
| STRATUM n-gram novelty n=3 | 0.25 | 0.36 | 0.31 | 0.18 | 0.13 | 0.25 |
| STRATUM n-gram novelty n=5 | 0.17 | 0.35 | 0.29 | 0.17 | 0.13 | 0.22 |
| Isolation Forest, TF-IDF 1..3-grams | 0.02 | 0.08 | 0.08 | 0.02 | 0.00 | 0.06 |

Tie-aware operating points (ROC interpolated across tied scores, i.e. random tie-breaking). The threshold-based TPR @1% FPR above counts only scores strictly above the 99th normal percentile, so a detector whose top normal scores tie (STIDE n=6: many traces score exactly 1.0) can show 0 with a degenerate [0, 0] interval.

| detector | TPR @ exactly 1% FPR [95% CI] | false-alarm rate @ 90% detection [95% CI] | normal / attack traces tied at the max normal score |
|---|---:|---:|---:|
| STIDE n=6 (baseline, Forrest 1996) | 0.024 [0.015, 0.035] | 0.267 [0.248, 0.306] | 69 / 28 |
| STIDE n=3 | 0.171 [0.110, 0.209] | 0.869 [0.848, 0.885] | 3 / 0 |
| STRATUM n-gram novelty n=3 | 0.176 [0.107, 0.214] | 0.411 [0.334, 0.525] | 3 / 0 |
| STRATUM n-gram novelty n=5 | 0.082 [0.055, 0.133] | 0.278 [0.248, 0.338] | 6 / 5 |
| Isolation Forest, TF-IDF 1..3-grams | 0.008 [0.001, 0.016] | 0.953 [0.946, 0.960] | 1 / 0 |

Paired, stratified bootstrap of the difference (same resampled traces for both detectors, 1000 resamples):

| A | B | metric | A - B [95% CI] | bootstrap p |
|---|---|---|---:|---:|
| STIDE n=6 (baseline, Forrest 1996) | STRATUM n-gram novelty n=5 | auc | +0.0053 [+0.0016, +0.0090] | 0.004 |
| STRATUM n-gram novelty n=3 | STIDE n=3 | tpr@0.01_interp | +0.0042 [-0.0214, +0.0268] | 0.959 |

Comparison with published ADFA-LD results (false-alarm rate at 90% detection). The published figures are taken from Kim et al. 2016's summary of Creech & Hu 2014 (we could not access the primary's full text); ELM uses semantic features and a different decision engine.

| system | FAR @ 90% DR | source |
|---|---:|---|
| STIDE | 0.23 | published |
| HMM | 0.42 | published |
| ELM, semantic features | 0.13 | published |
| STIDE n=6 (baseline, Forrest 1996) | 0.267 | this repo |
| STIDE n=3 | 0.869 | this repo |
| STRATUM n-gram novelty n=3 | 0.411 | this repo |
| STRATUM n-gram novelty n=5 | 0.278 | this repo |

Random re-splits (10 seeds): pool all normals, draw a fresh 833-trace training set per seed, test on the rest. CI = Nadeau-Bengio corrected resampled t.

| detector | AUC mean [corrected 95% CI] | AUC min-max | TPR @1% FPR (interp.) mean [corrected 95% CI] |
|---|---:|---:|---:|
| STIDE n=6 | 0.784 [0.750, 0.819] | 0.774-0.796 | 0.103 [0.000, 0.262] |
| STIDE n=3 | 0.712 [0.669, 0.756] | 0.699-0.724 | 0.155 [0.000, 0.381] |
| STRATUM n-gram novelty n=3 | 0.754 [0.708, 0.801] | 0.739-0.770 | 0.138 [0.000, 0.326] |
| STRATUM n-gram novelty n=5 | 0.808 [0.785, 0.831] | 0.801-0.816 | 0.107 [0.000, 0.293] |

TPR intervals are clipped to [0, 1]; with 10 re-splits the corrected interval for TPR at 1% FPR is too wide to be informative.

Paired over the same 10 re-splits, STRATUM n-gram novelty n=5 minus STIDE n=6 (auc): +0.0233, corrected 95% CI [+0.0006, +0.0460], corrected t = 2.342 (df 9, p = 0.044); positive in 10/10 splits (sign test p = 0.002).
