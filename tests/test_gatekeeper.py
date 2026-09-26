from pathlib import Path

import pytest
import yaml

from stratum.gatekeeper import KIND, REGO_CHECKS, constraint_template, export_yaml, rego_violations
from stratum.opa import find_opa
from stratum.pss import evaluate_pod

PSS = Path(__file__).parent / "fixtures" / "pss"
needs_opa = pytest.mark.skipif(find_opa() is None, reason="opa binary not available")


def _pods():
    pods = [yaml.safe_load(p.read_text()) for p in sorted(PSS.glob("*.yaml"))]
    pods.append({"kind": "Pod", "metadata": {"name": "x"}, "spec": {
        "hostNetwork": True, "securityContext": {"runAsUser": 0},
        "volumes": [{"name": "h", "hostPath": {"path": "/"}}],
        "containers": [{"name": "c", "ports": [{"containerPort": 80, "hostPort": 80}],
                        "securityContext": {"capabilities": {"add": ["SYS_ADMIN", "CHOWN"]}, "runAsNonRoot": False}}]}})
    return pods


def _python(pod):
    return {k for k in evaluate_pod(pod, "restricted") if k in REGO_CHECKS}


def test_export_shape():
    docs = list(yaml.safe_load_all(export_yaml("baseline", "deny")))
    assert docs[0]["kind"] == "ConstraintTemplate" and docs[0]["spec"]["crd"]["spec"]["names"]["kind"] == KIND
    assert docs[0]["spec"]["targets"][0]["rego"].startswith("#") and f"package {KIND.lower()}" in docs[0]["spec"]["targets"][0]["rego"]
    assert docs[1]["kind"] == KIND and docs[1]["spec"]["parameters"]["level"] == "baseline"
    assert docs[1]["spec"]["enforcementAction"] == "deny"
    assert "violation contains" in constraint_template()["spec"]["targets"][0]["rego"]


@needs_opa
def test_rego_matches_python_on_fixtures():
    pods = _pods()
    for pod, got in zip(pods, rego_violations(pods)):
        assert got == _python(pod), pod["metadata"].get("name")


@needs_opa
def test_rego_handles_workload_templates():
    pod = _pods()[-1]
    dep = {"kind": "Deployment", "metadata": {"name": "d"}, "spec": {"template": {"spec": pod["spec"]}}}
    cj = {"kind": "CronJob", "metadata": {"name": "j"}, "spec": {"jobTemplate": {"spec": {"template": {"spec": pod["spec"]}}}}}
    cm = {"kind": "ConfigMap", "metadata": {"name": "c"}, "data": {}}
    got = rego_violations([dep, cj, cm])
    assert got[0] == got[1] == _python(pod) and got[2] == set()


@pytest.mark.realdata
@needs_opa
def test_rego_matches_python_on_upstream_testdata():
    from conftest import DATA
    files = sorted((DATA / "pss" / "testdata").rglob("*.yaml"))
    if not files:
        pytest.skip("PSS testdata missing")
    pods = [yaml.safe_load(p.read_text()) for p in files]
    pods = [p for p in pods if isinstance(p, dict) and p.get("kind") == "Pod"]
    got = rego_violations(pods)
    bad = [p["metadata"]["name"] for p, g in zip(pods, got) if g != _python(p)]
    assert not bad, bad[:10]
