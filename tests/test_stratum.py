import json

import pytest

from stratum.cli import main
from stratum.dataset import Dataset
from stratum.detect import NoveltyModel, rule_detect
from stratum.graph import build_graph
from stratum.incident import analyze, metrics, replay_with_policy
from stratum.models import RuntimeEvent
from stratum.policy import egress_allowed, evaluate, recommend_egress_policy, render_netpol_yaml
from stratum.synth import BAD_BASE, generate


@pytest.fixture
def ds():
    return generate(seed=7)


def test_generator_is_deterministic():
    assert generate(3).to_json() == generate(3).to_json()
    assert generate(3).to_json() != generate(4).to_json()


def test_dataset_json_roundtrip(ds, tmp_path):
    p = tmp_path / "s.json"
    ds.save(p)
    ds2 = Dataset.load(p)
    assert ds2.to_json() == ds.to_json()


def test_trace_pod_to_commit(ds):
    g = build_graph(ds)
    w = ds.workloads[1]
    chain = g.trace_upstream(f"pod:{w.namespace}/{w.pods[0]}")
    assert [c.split(":")[0] for c in chain] == ["pod", "workload", "image", "build", "commit"]
    img = next(i for i in ds.images if i.digest == w.image_digest)
    build = next(b for b in ds.builds if b.id == img.build_id)
    assert chain[-1] == f"commit:{build.commit_sha}"


def test_drift_image_has_no_commit(ds):
    g = build_graph(ds)
    chain = g.trace_upstream("pod:shop/debug-tools")
    assert not any(c.startswith("commit:") for c in chain)


def test_blast_radius_of_bad_base(ds):
    g = build_graph(ds)
    assert g.blast_radius(f"base:{BAD_BASE}") == [
        "workload:legacy/worker", "workload:shop/cart", "workload:shop/frontend"]


def test_policy_findings(ds):
    fs = evaluate(ds, build_graph(ds), (BAD_BASE,))
    ids = {(f.control_id, f.subject) for f in fs}
    assert ("ZT-NET-01", "ns:shop") in ids
    assert ("ZT-NET-01", "ns:payments") not in ids
    assert ("ZT-PROV-01", "workload:shop/debug-tools") in ids
    assert ("ZT-ID-03", "workload:legacy/worker") in ids
    assert ("ZT-WL-01", "workload:legacy/worker") in ids


def test_rules():
    e = RuntimeEvent(1, "p", "ns", "exec", "/bin/bash")
    assert rule_detect(e).rule == "R-SHELL"
    e = RuntimeEvent(1, "p", "ns", "connect", "x", dest_ip="10.1.2.3", dest_port=80)
    assert rule_detect(e) is None
    e = RuntimeEvent(1, "p", "ns", "connect", "x", dest_ip="203.0.113.5", dest_port=80)
    assert rule_detect(e).control_id == "ZT-NET-01"


def test_novelty_model():
    base = [("w", RuntimeEvent(0, "p", "n", "exec", "node")) for _ in range(10)]
    m = NoveltyModel().fit(base)
    assert m.score("w", RuntimeEvent(0, "p", "n", "exec", "node")) == 0.0
    assert m.score("w", RuntimeEvent(0, "p", "n", "exec", "xmrig")) == 1.0


def test_end_to_end_metrics(ds):
    a = analyze(ds)
    m = metrics(ds, a)
    assert m["detection_rate"] == 1.0
    assert m["trace_to_commit_accuracy"] == 1.0
    assert m["false_positives"] == 0


def test_incident_names_failed_control(ds):
    a = analyze(ds)
    c2 = next(i for i in a.incidents if i.detection.event.label == "c2")
    assert c2.failed_controls[0].control_id == "ZT-NET-01"
    assert c2.author == "bob" and c2.pr == 214
    assert "workload:shop/frontend" in c2.blast_radius
    miner = next(i for i in a.incidents if i.detection.event.label == "miner")
    assert miner.root_commit is None
    assert any(f.control_id == "ZT-PROV-01" for f in miner.failed_controls)


def test_policy_as_prevention(ds):
    assert egress_allowed(ds, "shop", "203.0.113.50")
    r = replay_with_policy(ds, "shop")
    assert r["blocked_malicious"] == 2 and r["blocked_benign"] == 0
    assert not egress_allowed(ds, "shop", "203.0.113.50")
    assert egress_allowed(ds, "shop", "10.0.1.1")


def test_netpol_yaml():
    y = render_netpol_yaml(recommend_egress_policy("shop"))
    assert "kind: NetworkPolicy" in y and "namespace: shop" in y and "10.0.0.0/8" in y


def test_cli(tmp_path, capsys):
    out = tmp_path / "d.json"
    assert main(["generate", "--out", str(out)]) == 0
    assert main(["analyze", "--data", str(out), "--json"]) == 0
    data = json.loads(capsys.readouterr().out.split("\n", 1)[1])
    assert data["metrics"]["detected"] == 5
    assert main(["blast", BAD_BASE]) == 0
    assert main(["demo"]) == 0


def test_netpol_yaml_rejects_injection():
    import pytest
    import yaml

    for bad in ("shop\n---\nkind: ConfigMap", "Shop", "a" * 64, "", "shop}", "-x"):
        with pytest.raises(ValueError):
            recommend_egress_policy(bad)
    docs = list(yaml.safe_load_all(render_netpol_yaml(recommend_egress_policy("a" * 63))))
    assert len(docs) == 1 and docs[0]["metadata"] == {"name": "stratum-default-deny-egress", "namespace": "a" * 63}
    assert docs[0]["spec"]["egress"][0]["to"][0]["ipBlock"]["cidr"] == "10.0.0.0/8"


def test_cli_version_validation_and_globs(capsys):
    import re
    from pathlib import Path

    import pytest

    import stratum
    root = Path(__file__).resolve().parents[1]
    want = re.search(r'^version = "([^"]+)"', (root / "pyproject.toml").read_text(), re.M).group(1)
    with pytest.raises(SystemExit) as e:
        main(["--version"])
    assert e.value.code == 0 and capsys.readouterr().out.strip() == f"stratum {want}" == f"stratum {stratum.__version__}"
    assert main(["prevent", "bad\n---\nkind: ConfigMap"]) == 2
    assert main(["serve", "--source", "no-such-source"]) == 2
    assert main(["pss", str(root / "deploy" / "k8s" / "*.yaml")]) == 0
    assert "Deployment/" in capsys.readouterr().out
    assert main(["pss", str(root / "no-such-dir" / "*.yaml")]) == 2
