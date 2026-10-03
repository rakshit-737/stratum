# Reproduce

Every published number comes from one of four places, and every result file records the run and commit that
produced it (a `provenance` block, or `run_url` / `source_runs` for the live result). Times are wall-clock on a
4-core laptop or a standard GitHub-hosted runner.

## 1. Real-data corpus and benchmarks (local)

```bash
git clone https://github.com/rakshit-737/stratum && cd stratum
pip install -e ".[dev,api,bench]"
export STRATUM_DATA=$HOME/stratum-data      # anywhere outside git
python scripts/download_all.py              # about 2 GB (mostly the Trivy cache); exits non-zero if a step fails
python -m stratum bench                     # ~6 min (ADFA-LD bootstrap and re-splits ~5 min); writes results/*.json|md
```

| step | output | size / time |
|---|---|---|
| `download_all.py` | `$STRATUM_DATA/{pss,manifests,helm,provenance,scans,kev,tetragon,adfa}` | about 2 GB, 20-40 min (bandwidth-bound) |
| `stratum bench pss posture provenance scans runtime` | `results/{pss,posture,provenance,scans,runtime}.{json,md}` | < 30 s |
| `stratum bench adfa` | `results/adfa.{json,md}`, `results/figures/adfa_roc.png` | ~5 min, < 1 GB RAM |
| `stratum bench opa` (needs `opa`) | `results/opa.{json,md}` | < 10 s |
| `stratum bench perf` | `results/perf.{json,md}` (timings of this machine) | ~1 min |

Sample row, `results/provenance.md`: `| commit verified on GitHub | 25 | 29.1 |`.
Skipped images (download budget) are listed in `$STRATUM_DATA/scans/index.json`.
The signature columns of the provenance funnel depend on what registries publish today; re-check them with
`python scripts/recheck_signatures.py` (registry requests only) before `stratum bench provenance`.
Apart from the `provenance` block and `perf` timings, the non-ADFA benchmarks reproduce the committed JSON.

## 2. Live kind + Tetragon + Gatekeeper + cosign (GitHub Actions)

```bash
gh workflow run live.yml -f runs=5           # 5 jobs, each its own kind cluster, image and certificate; ~10 min
gh run watch <run-id>
gh run download <run-id> -D live-runs
python scripts/aggregate_live.py live-runs --run-url https://github.com/rakshit-737/stratum/actions/runs/<run-id>
```

Writes `results/live.{json,md}` (only the aggregator writes them). Expected: 5/5 runs pass, 5 distinct
certificates over 5 distinct digests, `drift` and `forged` 0 traced, A0-A4 as in the committed table. Each job
uploads `live-evidence-N` (Tetragon events for the demo namespace, `cosign verify` JSON, revision labels,
Gatekeeper status, prevention result), kept 90 days. Job 1 of the committed run is packaged under
`stratum/data/live/` (with `source.json` naming the run); it backs `stratum serve --source live`, the
`/demo-live/` console and the offline replay tests in `tests/test_live.py`.

## 3. Kim et al. (2016) LSTM reproduction (GitHub Actions)

```bash
gh workflow run repro-kim.yml -f epochs=400  # 3 seeds in parallel, CPU torch, early stopping; ~3-3.5 h per seed job
gh run download <run-id> -n kim-lstm-results -D results
```

Writes `results/kim_lstm.{json,md}` with the run URL and commit. The default `epochs=12` is a smoke run
(about 20 min) that leaves every model under-trained. With a 200-epoch cap (run 37007358324, 2h11-3h02 per
seed) the 1x200 model still stopped at the cap in 2 of 3 seeds. Locally: `pip install -e ".[lstm]"` and
`python -m stratum.bench.kim_lstm 400 0` (one seed; about 2 GB RAM and several hours on CPU).

## 4. Container syscall traces (GitHub Actions)

```bash
gh workflow run syscalls.yml -f runs=5       # 5 recording jobs (strace in Docker on the runner) + evaluate; ~5 min
gh run download <run-id> -n container-syscalls-results -D results
```

Writes `results/container_syscalls.{json,md}`. Each recording job (`scripts/record_syscalls.sh <dir> <seed>`,
seed = job number) starts an Alpine workload container and a sink on an internal Docker network and records
120 traces of 9 routine commands and 8 traces each of 5 benign attack-shaped commands with `strace -f`
(syscall names only). The evaluate job runs leave-one-run-out. The raw traces (`syscalls-run-N` artefacts) can be
re-evaluated locally with
`python -m stratum.bench.container_syscalls <dir with run-N/> results --traces-run <recording run URL>`.
