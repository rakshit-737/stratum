import json
from pathlib import Path

from stratum.bench.metrics import confusion
from stratum.bench.runner import BENCHES, NEEDS, run

LABELS = Path(__file__).resolve().parents[1] / "benchmarks" / "labels" / "tetragon.json"


def test_confusion():
    m = confusion([True, True, False, False], [True, False, True, False])
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == m["recall"] == m["f1"] == m["accuracy"] == 0.5
    assert confusion([], [])["f1"] == 0.0


def test_runner_skips_missing_data(tmp_path, capsys):
    out = tmp_path / "results"
    assert run(list(BENCHES), root=tmp_path / "nothing", out=out) == {}
    assert (out / "RESULTS.md").exists()
    assert set(NEEDS) == set(BENCHES)
    capsys.readouterr()


def test_tetragon_labels_cover_fixture_events(fix):
    labels = json.loads(LABELS.read_text())
    assert set(labels.values()) - {labels["_about"]} <= {"attack", "benign"}
    for f in (fix / "tetragon").glob("*.json"):
        if f.name != "process_exit.json":
            assert f.name in labels, f.name


def test_result_provenance(monkeypatch, tmp_path):
    from stratum.bench.meta import provenance
    (tmp_path / "MANIFEST.json").write_text("{}")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    monkeypatch.setenv("GITHUB_SHA", "c0ffee")
    p = provenance(tmp_path)
    assert p["source_run"] == "https://github.com/o/r/actions/runs/42" and p["commit"] == "c0ffee"
    assert len(p["dataset_manifest_sha256"]) == 64 and "code_modified" not in p
    monkeypatch.delenv("GITHUB_RUN_ID")
    monkeypatch.delenv("GITHUB_SHA")
    assert provenance()["source_run"] is None
