"""Reproducible benchmarks on the real-data corpus (``python -m stratum bench``).

Each module exposes ``run(root) -> dict`` and writes nothing itself; the runner
(:mod:`stratum.bench.runner`) stores JSON + Markdown under ``results/``.
"""
