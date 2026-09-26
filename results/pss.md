### Pod Security Standards conformance (upstream PSA fixtures, v1.37)

| level | engine | fixtures | precision | recall | F1 | accuracy | FP | FN |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| baseline | STRATUM | 49 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0 |
| baseline | v0.1 heuristic (baseline) | 49 | 1.000 | 0.147 | 0.256 | 0.408 | 0 | 29 |
| restricted | STRATUM | 99 | 1.000 | 1.000 | 1.000 | 1.000 | 0 | 0 |
| restricted | v0.1 heuristic (baseline) | 99 | 1.000 | 0.105 | 0.191 | 0.313 | 0 | 68 |

Check attribution (the violated check named in the fixture is among the checks STRATUM reports): baseline 100%, restricted 100%
