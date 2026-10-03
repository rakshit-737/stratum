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


FIX = ROOT / "stratum/data/live"
LIVE_DIG = "sha256:ea0dc9928ae5d3b1efe4f75d41d0bb4d36e102ad7ce8ff575cec51e080c63d35"
LIVE_SHA = "38cc4a3747d9d4d026501bc2bc7d72928a925894"
LIVE_RUN = "37085766270"
FORGED_DIG = "sha256:e30815bf8a15820fa57ef2d95b6673d0afffd67d87688850bca3638e9ec16a90"


def test_cosign_certificate_provenance():
    (s,) = parse_cosign_verify(FIX / "cosign-verify.json")
    assert (s.digest, s.commit, s.run_id, s.source_repo) == (LIVE_DIG, LIVE_SHA, LIVE_RUN, "rakshit-737/stratum")
    assert s.run_url.endswith(f"/actions/runs/{LIVE_RUN}/attempts/1") and s.run_attempt == "1"
    # the certificate itself: SHA-256 of the DER, serial number and the Rekor entry
    assert len(s.cert_sha256) == 64 and s.cert_serial and int(s.cert_serial, 16) > 0
    assert isinstance(s.rekor_log_index, int) and s.rekor_log_index > 0
    assert s.certificate()["cert_sha256"] == s.cert_sha256


def test_check_records_certificate_and_sink():
    sigs = parse_cosign_verify(FIX / "cosign-verify.json")
    r = check(_replay(sigs), namespace="stratum-live", workload="web", image_digest=LIVE_DIG, commit=LIVE_SHA,
              signatures=sigs)
    (c,) = r["certificates_on_target"]
    assert c["cert_sha256"] == sigs[0].cert_sha256 and c["run_id"] == LIVE_RUN
    assert r["sink_incidents"] == 0


def test_packaged_replay_matches_its_source_record():
    from stratum.live import replay_dataset, replay_info
    info = replay_info()
    assert info["run_id"] == LIVE_RUN and info["commit"] == LIVE_SHA
    assert replay_dataset().events


def _replay(sigs):
    return build_dataset([FIX / "workloads.yaml"], FIX / "pods.json", [FIX / "tetragon-events.json"], signatures=sigs)


def test_replay_real_live_run():
    sigs = parse_cosign_verify(FIX / "cosign-verify.json")
    ds = _replay(sigs)
    r = check(ds, namespace="stratum-live", workload="web", image_digest=LIVE_DIG, commit=LIVE_SHA,
              gatekeeper={"privileged_denied": True, "demo_admitted": True}, cosign_ok=True,
              drift="drift", forged="forged", expect_build=LIVE_RUN, signatures=sigs)
    assert r["passed"], r["failures"]
    assert r["traced_to_commit"] == r["incidents_on_target"] == 11 and r["sink_incidents"] == 0
    for ctl in ("drift", "forged"):   # both unsigned controls are detected but reach no commit
        assert r[ctl]["incidents"] and not r[ctl]["traced_to_any_commit"] and "ZT-PROV-01" in r[ctl]["failed_controls"]
    # the certificate of another CI run would fail the --expect-build check
    assert not check(ds, namespace="stratum-live", workload="web", image_digest=LIVE_DIG, commit=LIVE_SHA,
                     expect_build="1")["passed"]
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


def _run(cert="c1", digest="sha256:d1", **kw):
    r = {"incidents_on_target": 4, "traced_to_commit": 4, "incidents_other_pods_in_namespace": 1,
         "rules_on_target": ["R-SHELL", "R-SA-TOKEN"], "passed": True, "example_chain": ["pod:x", "commit:abc1234"],
         "drift": {"workload": "drift", "incidents": 1, "traced_to_any_commit": 0, "failed_controls": ["ZT-PROV-01"]},
         "prevention": {"observed": {"before": True, "after": False, "in_cluster_after": True}},
         "gatekeeper": {"privileged_denied": True}, "cosign_verified": True, "builds_on_target": ["42"],
         "target_image_digests": [digest],
         "certificates_on_target": [{"digest": digest, "cert_sha256": cert, "cert_serial": cert.upper(),
                                     "rekor_log_index": 7, "run_id": "42", "run_attempt": "1"}]}
    r.update(kw)
    return r


def test_aggregate_shared_certificate_gets_no_trace_ci():
    from stratum.live import aggregate, aggregate_markdown
    a = aggregate([_run(), _run()])
    assert a["runs"] == 2 and a["traced_to_commit"] == 8 and a["sink_detections"] == 0
    assert a["runs_fully_traced"] == 2 and not a["per_run_signed"]
    assert a["traced_runs_ci95"] is None and a["passed_ci95"] is None and a["cosign_ci95"] is None
    assert a["distinct_certificates"] == ["c1"] and a["distinct_digests"] == ["sha256:d1"]
    md = aggregate_markdown(a)
    assert "8/8" in md and "- (shared certificate)" in md and "docs and aggregation only" not in md
    assert a["rule_capture"]["R-NETTOOL"]["runs"] == 0 and a["rule_capture"]["R-SHELL"]["runs"] == 2


def test_aggregate_per_run_certificates_get_trace_ci():
    from stratum.live import aggregate, aggregate_markdown
    a = aggregate([_run("c1", "sha256:d1"), _run("c2", "sha256:d2"), _run("c3", "sha256:d3")],
                  "https://example/runs/42")
    assert a["per_run_signed"] and a["traced_runs_ci95"][1] == 1.0 and a["passed_ci95"]
    assert a["distinct_certificate_run_ids"] == ["42"] and len(a["distinct_certificates"]) == 3
    md = aggregate_markdown(a)
    assert "3 distinct certificates over 3 distinct image digests" in md and "1 workflow run" in md
    assert "Run: https://example/runs/42" in md and md.count("| 4/4 |") == 3


def test_sink_count_excludes_both_negative_controls():
    from stratum.live import aggregate, markdown, sink_incidents
    forged = {"workload": "forged", "incidents": 1, "traced_to_any_commit": 0, "failed_controls": ["ZT-PROV-01"]}
    old = _run(incidents_other_pods_in_namespace=2, forged=forged)   # pre-sink_incidents result file
    assert sink_incidents(old) == 0
    assert sink_incidents(_run(sink_incidents=3)) == 3
    assert aggregate([old] * 5)["sink_detections"] == 0
    r = dict(old, events_total=1, events_in_namespace=1, event_kinds={}, failures=[], gatekeeper={})
    assert "| Detections on the benign sink pod | 0 |" in markdown(r)


def test_ablation_arms_on_real_replay():
    from stratum.live import ablation
    sigs = parse_cosign_verify(FIX / "cosign-verify.json")
    labels = json.loads((FIX / "labels.json").read_text(encoding="utf-8"))
    assert labels == {LIVE_DIG: LIVE_SHA, FORGED_DIG: LIVE_SHA}   # the forged image carries the right label
    ab = ablation([FIX / "workloads.yaml"], FIX / "pods.json", [FIX / "tetragon-events.json"],
                  signatures=sigs, labels=labels, commit=LIVE_SHA)
    assert not ab["A0"]["workload_attributed"] and not ab["A0"]["traced"]
    assert ab["A1"]["workload_attributed"] and not ab["A1"]["traced"] and not ab["A1"]["false_attribution"]
    assert ab["A2"]["traced"] and ab["A2"]["false_attribution"]        # label provenance trusts the forged label
    assert ab["A3"]["traced"] and not ab["A3"]["false_attribution"] and ab["A3"]["prov_named"]
    assert ab["A4"]["traced"] and ab["A4"]["false_attribution"] and not ab["A4"]["prov_named"]


def test_repository_join_ignores_tag_and_digest():
    from stratum.live import _repo
    assert _repo("ghcr.io/a/b:t@sha256:1") == "ghcr.io/a/b" == _repo("ghcr.io/a/b@sha256:1")
    assert _repo("localhost:5000/a/b:t") == "localhost:5000/a/b"
