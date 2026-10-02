"""Smoke test of the Kim et al. 2016 reproduction code on the tiny ADFA fixture (needs torch)."""
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")


def test_kim_lstm_smoke(monkeypatch):
    from stratum.bench import kim_lstm
    monkeypatch.setattr(kim_lstm, "CONFIGS", [(8, 1), (8, 2)])
    real = kim_lstm.load_adfa

    def small(root):  # keep the smoke test fast: 60 calls per trace
        d = real(root)
        return {"train": [t[:60] for t in d["train"]], "val": [t[:60] for t in d["val"]],
                "attack": [(f, t[:60]) for f, t in d["attack"]]}
    monkeypatch.setattr(kim_lstm, "load_adfa", small)
    r = kim_lstm.run(Path(__file__).parent / "fixtures", seeds=(0,), epochs=1, log=lambda m: None)
    assert 0.0 <= r["ensemble"]["mean"] <= 1.0 and r["per_seed"][0]["best_epoch"]
    assert "held out for early stopping" in kim_lstm.markdown(r)
