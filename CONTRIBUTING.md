# Contributing to STRATUM

Thanks for helping. STRATUM is a small, readable, defensive project. Please keep changes in that spirit.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev,api,bench]"
python -m pytest -q                                   # fixtures only, no downloads needed
python -m ruff check .
```

Real-data work needs the corpus (see README → *Datasets*):

```bash
export STRATUM_DATA=$PWD/data                         # or any disk with ~3 GB free
python scripts/download_all.py --no-scan              # ~60 MB; drop --no-scan to also run Trivy
python -m pytest -q -m realdata                       # tests against the corpus
python -m stratum bench                               # regenerate results/
```

## Ground rules

- **Tests first.** Every new rule, check or parser needs a test. Use a small *real* fixture under `tests/fixtures/` (a trimmed upstream manifest or event) rather than a hand-invented one. Keep each fixture under ~50 KB.
- **CI must pass without the big datasets.** Tests that need the corpus must carry `@pytest.mark.realdata`. `tests/conftest.py` skips them automatically when `$STRATUM_DATA` is absent.
- **Policy changes go in two places.** A change to `stratum/policy.py` needs the same change in `policies/stratum.rego`. `stratum opa-check` (run in CI) fails if the two diverge.
- **Every control must be traceable.** A new control needs an id, a severity, an external reference (CIS, NIST, SLSA, ...) and a fix string in `stratum/incident.py`.
- **No datasets or large files in git.** Add a `scripts/download_*.py` step that pins versions and verifies SHA-256 (see `scripts/_common.py`). Only small derived artefacts go in `results/`.
- **Safety.** No malware, exploit code or offensive tooling. Never scan or connect to anything except public registries, public APIs and your own lab cluster.

## Commits and PRs

Use Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`, `data:`, `perf:`, `refactor:`), one logical change per commit. In the PR, describe how you validated the change, and include benchmark deltas if it affects `results/`.

## Architecture decisions

Significant design changes need an ADR in `docs/adr/` (copy an existing one). Examples: a new data source, a new graph backend, or a change to how provenance is trusted.
