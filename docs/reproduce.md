# Reproduce

Every published number comes from one of three places. Times are wall-clock on a 4-core laptop or a
standard GitHub-hosted runner.

## 1. Real-data corpus and benchmarks (local)

```bash
git clone https://github.com/rakshit-737/stratum && cd stratum
pip install -e ".[dev,api,bench]"
export STRATUM_DATA=$HOME/stratum-data      # anywhere outside git
python scripts/download_all.py              # ~1.5 GB (mostly the Trivy cache); exits non-zero if a step fails
python -m stratum bench                     # ~6 min (ADFA-LD bootstrap ~5 min); writes results/*.json|md
```

| step | output | size / time |
|---|---|---|
| `download_all.py` | `$STRATUM_DATA/{pss,manifests,helm,provenance,scans,kev,tetragon,adfa}` | ~1.5 GB, 20-40 min (bandwidth-bound) |
| `stratum bench pss posture provenance scans runtime` | `results/{pss,posture,provenance,scans,runtime}.{json,md}` | < 30 s |
| `stratum bench adfa` | `results/adfa.{json,md}`, `results/figures/adfa_roc.png` | ~5 min, < 1 GB RAM |
| `stratum opa-check --data real` (needs `opa`) | `results/opa.{json,md}` | < 10 s |

Sample row, `results/provenance.md`: `| commit verified on GitHub | 25 | 29.1 |`.
Skipped images (download budget) are listed in `$STRATUM_DATA/scans/index.json`.
The non-ADFA benchmarks reproduce the committed JSON byte for byte; `perf` timings vary by machine.

## 2. Live kind + Tetragon + Gatekeeper + cosign (GitHub Actions)

```bash
gh workflow run live.yml -f runs=5           # 5 independent kind clusters, ~8 min
gh run download <run-id> -D live-runs
python scripts/aggregate_live.py live-runs --run-url https://github.com/rakshit-737/stratum/actions/runs/<run-id>
```

Writes `results/live.{json,md}`. Each job uploads `live-evidence-N` (Tetragon events for the demo namespace,
`cosign verify` JSON, Gatekeeper status, prevention result), kept 90 days. A trimmed copy of one run's evidence
is committed under `tests/fixtures/live/` and replayed offline by `tests/test_live.py`.

## 3. Kim et al. (2016) LSTM reproduction (GitHub Actions)

```bash
gh workflow run repro-kim.yml                # 3 seeds in parallel, CPU torch, ~20 min
gh run download <run-id> -n kim-lstm-results -D results
```

Writes `results/kim_lstm.{json,md}`. Locally: `pip install -e ".[lstm]"` and
`python -m stratum.bench.kim_lstm 12 0` (one seed; needs about 2 GB RAM and over an hour on CPU).
