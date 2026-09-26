"""Tests against the downloaded corpus; skipped automatically when $STRATUM_DATA is absent."""
import pytest
from conftest import DATA

pytestmark = pytest.mark.realdata


def test_pss_conformance_is_perfect():
    from stratum.bench import pss
    r = pss.run(DATA)
    for lvl in ("baseline", "restricted"):
        assert r["levels"][lvl]["stratum"]["f1"] == 1.0
        assert r["levels"][lvl]["legacy_mvp"]["recall"] < 0.5


def test_real_dataset_builds_and_traces():
    from stratum.incident import analyze
    from stratum.realdata import real_dataset
    ds = real_dataset(DATA)
    a = analyze(ds)
    assert len(ds.workloads) > 50 and a.findings
    esc = [i for i in a.incidents if i.detection.rule == "R-ESCAPE"]
    assert esc and esc[0].chain[1] == "workload:default/privileged-pod"
