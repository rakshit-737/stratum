# Getting started

## Install and first run

The Python distribution is named `stratum-cnapp` (the PyPI name `stratum` belongs to an unrelated project, so do not `pip install stratum`); the import package and the CLI are `stratum`. Install from a checkout or from the wheel attached to a GitHub release.

```bash
pip install -e ".[dev,api,bench]"
python -m stratum demo                  # synthetic 5-scenario walkthrough, no downloads
python -m pytest -q                     # runs on small committed fixtures; tests that need opa or the corpus skip
python -m stratum serve                 # console on http://127.0.0.1:8000
```

Check your own manifests (wildcards are expanded by STRATUM, so the commands also work in PowerShell):

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

`live.yaml` is a full cluster dump and can contain secrets from pod environment variables: keep it out of version control (`live.yaml`, `live.json`, `stratum-pss.yaml`, `cluster.json` and `*.cypher` are in `.gitignore`) and delete it when done.

## Reproducing the results

`make` targets are listed. On machines without `make`, run the command in the comment.

```bash
export STRATUM_DATA=$PWD/data           # anywhere outside git; about 2 GB with the Trivy cache
make data        # python scripts/download_all.py   (tools, datasets, provenance, Trivy scans)
make bench       # python -m stratum bench          (writes results/*.json|md, results/figures/*.png)
make test        # python -m pytest -q              (realdata tests run automatically when data is present)
make serve SOURCE=real   # python -m stratum serve --source real
```

The scripts pin versions and verify SHA-256 against `scripts/checksums.json` or the upstream checksum files. Image scans run smallest image first under a download budget (`--budget-mb 1500`). Skipped images are listed in `$STRATUM_DATA/scans/index.json`. Step-by-step commands, outputs and timings: [docs/reproduce.md](reproduce.md).

## Docker

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/stratum-cloud-security:latest   # synthetic source
docker build -t stratum . && docker run --rm -p 127.0.0.1:8000:8000 -e STRATUM_SOURCE=live stratum  # live CI replay (main)
NEO4J_PASSWORD='choose-one' docker compose up                  # API + Neo4j 5 (compose refuses to start without it)
```

The image is built for linux/amd64 only; on ARM hosts (Apple silicon, Graviton) add `--platform linux/amd64`. `NEO4J_PASSWORD` can also go in a `.env` file next to `docker-compose.yml`.
