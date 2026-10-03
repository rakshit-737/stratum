import pytest
from fastapi.testclient import TestClient

from stratum.api import app
from stratum.cli import main
from stratum.graph import attach_findings
from stratum.incident import analyze
from stratum.k8s import collect_files
from stratum.neo4j import to_cypher
from stratum.opa import diff, find_opa
from stratum.synth import generate

client = TestClient(app)


def test_api_endpoints():
    s = client.get("/api/summary").json()
    assert s["source"] == "synthetic" and s["incidents"] == 5
    assert client.get("/").status_code == 200
    assert len(client.get("/api/controls").json()) >= 13
    inc = client.get("/api/incidents").json()
    assert any(i["root_commit"] is None for i in inc)
    assert client.get("/api/blast", params={"base": "alpine:3.14.0"}).json()["workloads"]
    assert client.get("/api/trace", params={"node": "nope"}).status_code == 404
    assert client.post("/api/prevent/shop").json()["blocked_malicious"] == 2
    assert "MERGE" in client.get("/api/export/cypher").text


def test_cypher_export():
    a = analyze(generate(7))
    cy = to_cypher(attach_findings(a.graph, a.findings))
    assert "SET n:Commit" in cy and "[:BUILDS]" in cy and "[:VIOLATES]" in cy
    assert cy.count("MERGE (n:Stratum") == len(a.graph.nodes)


def test_cli_new_commands(tmp_path, fix, capsys):
    out = tmp_path / "c.json"
    assert main(["collect", str(fix / "manifests" / "metrics-server.yaml"), "--out", str(out),
                 "--tetragon", *map(str, sorted((fix / "tetragon").glob("*.json")))]) == 0
    assert main(["analyze", "--data", str(out)]) == 0
    assert main(["pss", str(fix / "manifests" / "local-path-provisioner.yaml"), "--strict"]) == 1
    assert main(["export", "--format", "rego-input", "--out", str(tmp_path / "i.json")]) == 0
    capsys.readouterr()


@pytest.mark.skipif(find_opa() is None, reason="opa binary not available")
def test_rego_matches_python(fix):
    d = diff(generate(7), ("alpine:3.14.0",))
    assert d["equivalent"], d
    ds = collect_files([fix / "manifests" / "local-path-provisioner.yaml", fix / "manifests" / "metrics-server.yaml"])
    d = diff(ds)
    assert d["equivalent"], d


def test_api_input_validation():
    assert client.get("/api/findings", params={"limit": -5}).status_code == 422
    assert client.get("/api/findings", params={"limit": 0}).status_code == 422
    assert len(client.get("/api/findings", params={"limit": 3}).json()) == 3
    from urllib.parse import quote
    for bad in ("Shop", "a" * 64, "x\n---\nkind: ConfigMap", "-shop"):
        assert client.post("/api/prevent/" + quote(bad, safe="")).status_code == 422, bad
    assert client.post("/api/prevent/" + "a" * 5000).status_code == 422

