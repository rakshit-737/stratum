PY ?= python

.PHONY: demo test install clean

install:
	$(PY) -m pip install -r requirements.txt

demo:
	$(PY) -m stratum demo

test:
	$(PY) -m pytest -q

clean:
	rm -rf .pytest_cache scenario.json
