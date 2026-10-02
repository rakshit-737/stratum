"""stratum.live on hand-built Tetragon-shaped events (the real run is .github/workflows/live.yml)."""
import json
from pathlib import Path

from stratum.detect import rule_detect
from stratum.live import build_dataset, check
from stratum.models import RuntimeEvent
from stratum.sigstore import SignedImage, parse_cosign_verify

ROOT = Path(__file__).resolve().parents[1]
DIG = "sha256:" + "ab" * 32
REF = f"ghcr.io/rakshit-737/stratum-live-demo@{DIG}"


def _proc(binary, args="", pod="web-5d9c7b-x1"):
    return {"binary": binary, "arguments": args, "uid": 65534,
            "pod": {"namespace": "stratum-live", "name": pod,
                    "container": {"id": "containerd://c1", "image": {"id": REF, "name": REF}}}}


def _events():
    t = "2026-09-27T10:00:0{}.000000000Z"
    return [
        {"time": t.format(1), "process_exec": {"process": _proc("/bin/sh", "-c id")}},
        {"time": t.format(2), "process_kprobe": {"process": _proc("/bin/cat"), "function_name": "fd_install",
         "args": [{"int_arg": 3}, {"file_arg": {"path": "/var/run/secrets/kubernetes.io/serviceaccount/"
                                                        "..2026_09_27_10_00_00.1/token"}}]}},
        {"time": t.format(3), "process_exec": {"process": _proc("/bin/nc", "-w 3 sink 8080")}},
        {"time": t.format(4), "process_kprobe": {"process": _proc("/bin/nc"), "function_name": "tcp_connect",
         "args": [{"sock_arg": {"daddr": "10.96.12.3", "dport": 8080}}]}},
    ]


def test_projected_token_path_detected():
    e = RuntimeEvent(0, "p", "n", "open", "/bin/cat", path="/..2026_09_27_10_00_00.123/token")
    assert rule_detect(e).rule == "R-SA-TOKEN"


def test_live_check_end_to_end(tmp_path):
    man = tmp_path / "w.yaml"
    man.write_text((ROOT / "deploy/live/workloads.yaml").read_text().replace("IMAGE", REF))
    ev = tmp_path / "ev.json"
    ev.write_text("\n".join(json.dumps(x) for x in _events()))
    pods = tmp_path / "pods.json"
    pods.write_text(json.dumps({"items": [{"metadata": {"name": "web-5d9c7b-x1", "namespace": "stratum-live",
                                                        "ownerReferences": [{"kind": "ReplicaSet",
                                                                             "name": "web-5d9c7b"}]}}]}))
    sig = SignedImage(DIG, "ghcr.io/rakshit-737/stratum-live-demo", "c0ffee", "r", "refs/heads/main", "i", "42", None)
    ds = build_dataset([man], pods, [ev], signatures=[sig])
    r = check(ds, namespace="stratum-live", workload="web", image_digest=DIG, commit="c0ffee",
              gatekeeper={"privileged_denied": True, "demo_admitted": True}, cosign_ok=True)
    assert r["passed"], r["failures"]
    assert r["example_chain"][-1] == "commit:c0ffee"
    r = check(ds, namespace="stratum-live", workload="web", image_digest=DIG, commit="other")
    assert not r["passed"]


FIX = ROOT / "tests/fixtures/live"
LIVE_DIG = "sha256:a1e2a762c940879b79e09773574759805b898a89b914062949948f262c972ff1"
LIVE_SHA = "6dd4b9b30f2404a974b0198a021ced3963a55516"


def test_cosign_certificate_provenance():
    (s,) = parse_cosign_verify(FIX / "cosign-verify.json")
    assert (s.digest, s.commit, s.run_id, s.source_repo) == (LIVE_DIG, LIVE_SHA, "36319470255", "rakshit-737/stratum")
    assert s.run_url.endswith("/actions/runs/36319470255/attempts/1")


def _replay(sigs):
    return build_dataset([FIX / "workloads.yaml"], FIX / "pods.json", [FIX / "tetragon-events.json"], signatures=sigs)


def test_replay_real_live_run():
    ds = _replay(parse_cosign_verify(FIX / "cosign-verify.json"))
    r = check(ds, namespace="stratum-live", workload="web", image_digest=LIVE_DIG, commit=LIVE_SHA,
              gatekeeper={"privileged_denied": True, "demo_admitted": True}, cosign_ok=True)
    assert r["passed"], r["failures"]
    assert r["traced_to_commit"] == r["incidents_on_target"] == 5
    assert not check(ds, namespace="stratum-live", workload="web", image_digest=LIVE_DIG, commit="0" * 40)["passed"]


def test_replay_without_signature_cannot_reach_commit():
    r = check(_replay([]), namespace="stratum-live", workload="web", image_digest=LIVE_DIG, commit=LIVE_SHA)
    assert r["traced_to_commit"] == 0 and not r["passed"]


def test_registry_refuses_non_https_token_realm():
    import pytest

    from stratum.registry import Registry
    for realm in ("file:///etc/passwd", "http://169.254.169.254/token", "ftp://x/y"):
        with pytest.raises(ValueError):
            Registry()._token(f'Bearer realm="{realm}",service="x",scope="y"')


def test_aggregate_counts_runs():
    from stratum.live import aggregate, aggregate_markdown
    r = {"incidents_on_target": 4, "traced_to_commit": 4, "incidents_other_pods_in_namespace": 1,
         "rules_on_target": ["R-SHELL", "R-SA-TOKEN"], "passed": False, "example_chain": ["pod:x"],
         "drift": {"incidents": 1, "traced_to_any_commit": 0, "failed_controls": ["ZT-PROV-01"]},
         "prevention": {"observed": {"before": True, "after": False, "in_cluster_after": True}},
         "gatekeeper": {"privileged_denied": True}, "cosign_verified": True}
    a = aggregate([r, r])
    assert a["runs"] == 2 and a["traced_to_commit"] == 8 and a["sink_detections"] == 0
    assert a["runs_fully_traced"] == 2 and "traced_ci95" not in a and a["traced_runs_ci95"][1] == 1.0
    assert a["rule_capture"]["R-NETTOOL"]["runs"] == 0 and a["rule_capture"]["R-SHELL"]["runs"] == 2
    assert "8/8" in aggregate_markdown(a)
