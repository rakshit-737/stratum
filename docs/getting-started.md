# Getting started

## Install and first run

```bash
pip install -e ".[dev,api,bench]"
python -m stratum demo                  # synthetic 5-scenario walkthrough, no downloads
python -m pytest -q                     # runs on small committed fixtures; tests that need opa or the corpus skip
python -m stratum serve                 # console on http://127.0.0.1:8000
```

Check your own manifests:

```bash
python -m stratum pss deploy/k8s/*.yaml --level restricted --strict        # PSS gate for CI (exit 1 here: 3 violations)
python -m stratum collect deploy/k8s/*.yaml --out cluster.json                 # -> dataset JSON
python -m stratum analyze --data cluster.json                              # findings + incidents
kubectl get deploy,ds,sts,job,cronjob,pod,sa,netpol,clusterrole,clusterrolebinding,role,rolebinding -A -o yaml > live.yaml
python -m stratum collect live.yaml --tetragon tests/fixtures/tetragon/events.json --out live.json
python -m stratum export --data live.json --format cypher --out graph.cypher   # Neo4j
python -m stratum opa-check --data live.json                               # Rego == Python?
python -m stratum gatekeeper --level restricted --out stratum-pss.yaml     # Gatekeeper ConstraintTemplate
```

## Reproducing the results

`make` targets are listed. On machines without `make`, run the command in the comment.

```bash
export STRATUM_DATA=$PWD/data           # anywhere outside git; ~3 GB with the Trivy cache
make data        # python scripts/download_all.py   (tools, datasets, provenance, Trivy scans)
make bench       # python -m stratum bench          (writes results/*.json|md, results/figures/*.png)
make test        # python -m pytest -q              (realdata tests run automatically when data is present)
make serve SOURCE=real   # python -m stratum serve --source real
```

The scripts pin versions and verify SHA-256 against `scripts/checksums.json` or the upstream checksum files. Image scans run smallest image first under a download budget (`--budget-mb 1500`). Skipped images are listed in `$STRATUM_DATA/scans/index.json`. Step-by-step commands, outputs and timings: [docs/reproduce.md](reproduce.md).

## Docker

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/stratum:latest   # synthetic source
docker compose up                                              # API + Neo4j 5
```
