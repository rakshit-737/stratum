PY ?= python
# Where the real-data corpus lives (outside git). Override: make data STRATUM_DATA=/big/disk/stratum
STRATUM_DATA ?= $(CURDIR)/data
export STRATUM_DATA

.PHONY: install data data-lite bench demo serve test lint opa-check clean

install:
	$(PY) -m pip install -e ".[dev,api,bench]"

data:            ## download + verify everything, scan images (~1.5 GB budget)
	$(PY) scripts/download_all.py

data-lite:       ## everything except pulling image layers for Trivy (~60 MB)
	$(PY) scripts/download_all.py --no-scan

bench:           ## regenerate results/ from the corpus
	$(PY) -m stratum bench

demo:
	$(PY) -m stratum demo

serve:           ## API + console on http://127.0.0.1:8000 (SOURCE=real for the corpus)
	$(PY) -m stratum serve --source $(or $(SOURCE),synthetic)

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

opa-check:
	$(PY) -m stratum opa-check --data real

clean:
	rm -rf .pytest_cache .ruff_cache scenario.json cluster.json
