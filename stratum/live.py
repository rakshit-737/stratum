"""Live-cluster check: real Tetragon events from a kind cluster -> STRATUM detection + trace-to-commit.

Used by ``.github/workflows/live.yml``. The workflow builds a demo image, pushes it to GHCR, signs it with
cosign (keyless, GitHub OIDC), deploys it to kind with Tetragon and Gatekeeper, runs scripted
attack-shaped actions inside the pod and exports Tetragon's JSON. This module joins that evidence into
one :class:`Dataset` (manifests + the CI build that produced the image + the live events), runs the
normal analysis, and asserts on the result.
"""
from __future__ import annotations

import json
from pathlib import Path

from .dataset import Dataset
from .incident import analyze
from .ingest import tetragon_events
from .k8s import collect_files
from .models import Build, Commit, Image
from .sigstore import SignedImage

# rule -> what the scripted action inside the pod was
EXPECTED = {"R-SHELL": "kubectl exec ... sh", "R-SA-TOKEN": "cat the projected SA token",
            "R-NETTOOL": "nc to the in-cluster sink"}


def _owner_workload(pod: dict) -> str | None:
    refs = (pod.get("metadata") or {}).get("ownerReferences") or []
    if not refs:
        return None
    name = refs[0].get("name", "")
    return name.rsplit("-", 1)[0] if refs[0].get("kind") == "ReplicaSet" else name


def build_dataset(manifests: list[str | Path], pods_json: str | Path, events: list[str | Path], *,
                  signatures: list[SignedImage], author: str = "") -> Dataset:
    """Join manifests, pod state, Tetragon events and verified signatures into one :class:`Dataset`.

    The ``image -> build -> commit`` edges come only from ``signatures`` (parsed from ``cosign verify``):
    a workload whose image digest has no verified signature gets no build, so its incidents cannot
    reach a commit. Nothing about the expected commit is passed in here.
    """
    ds = collect_files(manifests, source="live")
    pods = json.loads(Path(pods_json).read_text(encoding="utf-8")).get("items", [])
    by_wl: dict[tuple[str, str], list[str]] = {}
    for p in pods:
        meta = p.get("metadata") or {}
        wl = _owner_workload(p)
        if wl:
            by_wl.setdefault((meta.get("namespace", ""), wl), []).append(meta.get("name", ""))
    for w in ds.workloads:
        w.pods = sorted(by_wl.get((w.namespace, w.name), w.pods))
    seen: set[str] = set()
    for sig in signatures:
        build = sig.run_id or f"sig-{sig.digest[7:19]}"
        if sig.commit not in {c.sha for c in ds.commits}:
            ds.commits.append(Commit(sig.commit, sig.source_repo, author, f"signed by {sig.ref}"))
        if build not in {b.id for b in ds.builds}:
            ds.builds.append(Build(build, sig.commit, "github-actions", signed=True))
        for w in ds.workloads:
            if w.image_digest.endswith("@" + sig.digest) and w.image_digest not in seen:
                seen.add(w.image_digest)
                ds.images.append(Image(w.image_digest, w.image_digest, build))
    ds.events = tetragon_events(events)
    return ds


def check(ds: Dataset, *, namespace: str, workload: str, image_digest: str, commit: str,
          gatekeeper: dict | None = None, cosign_ok: bool | None = None, drift: str | None = None,
          prevention: dict | None = None) -> dict:
    """Assert on the joined evidence. ``commit`` is only the expected value (``github.sha``)."""
    a = analyze(ds, deny_bases=())
    ns_events = [e for e in ds.events if e.namespace == namespace]
    target = [e for e in ns_events if e.pod.startswith(workload + "-")]
    incs = [i for i in a.incidents if i.detection.event.namespace == namespace]
    on_target = [i for i in incs if i.detection.event.pod.startswith(workload + "-")]
    rules = sorted({i.detection.rule for i in on_target})
    kinds: dict[str, int] = {}
    for e in ns_events:
        kinds[e.kind] = kinds.get(e.kind, 0) + 1
    res = {
        "events_total": len(ds.events), "events_in_namespace": len(ns_events), "event_kinds": kinds,
        "events_on_target": len(target),
        "target_image_digests": sorted({e.image_digest for e in target if e.image_digest}),
        "connects_on_target": sorted({f"{e.dest_ip}:{e.dest_port}" for e in target if e.kind == "connect"}),
        "rules_on_target": rules,
        "incidents_on_target": len(on_target),
        "incidents_other_pods_in_namespace": len(incs) - len(on_target),
        "traced_to_commit": sum(i.root_commit == commit for i in on_target),
        "example_chain": on_target[0].chain if on_target else [],
        "failed_controls": sorted({f.control_id for i in on_target for f in i.failed_controls}),
        "gatekeeper": gatekeeper or {}, "cosign_verified": cosign_ok,
        "commit_source": "cosign certificate (OID 1.3.6.1.4.1.57264.1.3)",
    }
    if drift:
        d_incs = [i for i in incs if i.detection.event.pod.startswith(drift + "-")]
        res["drift"] = {"workload": drift, "incidents": len(d_incs),
                        "traced_to_any_commit": sum(i.root_commit is not None for i in d_incs),
                        "failed_controls": sorted({f.control_id for i in d_incs for f in i.failed_controls})}
    fails = []
    for rule, action in EXPECTED.items():
        if rule not in rules:
            fails.append(f"{rule} not raised ({action})")
    if not on_target or res["traced_to_commit"] != len(on_target):
        fails.append(f"trace-to-commit {res['traced_to_commit']}/{len(on_target)}")
    if image_digest and image_digest not in res["target_image_digests"]:
        fails.append(f"running image digest {image_digest} not seen in events {res['target_image_digests']}")
    if not any(c.endswith(":8080") for c in res["connects_on_target"]):
        fails.append("no connect to the sink (:8080) captured")
    if gatekeeper is not None and not (gatekeeper.get("privileged_denied") and gatekeeper.get("demo_admitted")):
        fails.append(f"gatekeeper: {gatekeeper}")
    if prevention is not None:
        from .incident import replay_with_policy
        pred = replay_with_policy(ds, namespace)
        pred.pop("policy_yaml", None)
        res["prevention"] = {"observed": prevention, "predicted_by_replay": pred}
        if not (prevention.get("before") is True and prevention.get("after") is False
                and prevention.get("in_cluster_after") is True):
            fails.append(f"prevention: {prevention}")
    if drift:
        d = res["drift"]
        if not d["incidents"]:
            fails.append(f"negative control: no incident on unsigned workload {drift}")
        if d["traced_to_any_commit"]:
            fails.append(f"negative control: unsigned workload {drift} traced to a commit")
        if "ZT-PROV-01" not in d["failed_controls"]:
            fails.append(f"negative control: ZT-PROV-01 not named for {drift}")
    if cosign_ok is False:
        fails.append("cosign verify failed")
    res["failures"] = fails
    res["passed"] = not fails
    return res


def _kv(d: dict) -> str:
    return ", ".join(f"{k} {str(v).lower() if isinstance(v, bool) else v}" for k, v in d.items())


def markdown(r: dict) -> str:
    lines = [
        "### Live kind + Tetragon run (GitHub Actions)", "",
        "| Check | Result |", "|---|---|",
        f"| Tetragon events (total / demo namespace) | {r['events_total']} / {r['events_in_namespace']} ({_kv(r['event_kinds'])}) |",
        f"| Rules raised on the demo pod | {', '.join(r['rules_on_target']) or '-'} |",
        f"| Incidents traced to the expected commit (commit read from the cosign certificate) | "
        f"{r['traced_to_commit']}/{r['incidents_on_target']} |",
        f"| Detections on the sink pod | {r['incidents_other_pods_in_namespace'] - (r.get('drift') or {}).get('incidents', 0)} |",
    ]
    if r.get("drift"):
        d = r["drift"]
        lines.append(f"| Negative control: unsigned `{d['workload']}` incidents traced to a commit | "
                     f"{d['traced_to_any_commit']}/{d['incidents']} (controls: {', '.join(d['failed_controls'])}) |")
    if r.get("prevention"):
        o = r["prevention"]["observed"]
        lines.append(f"| Policy-as-prevention: connect to external sink before / after `stratum prevent` policy | "
                     f"{'allowed' if o.get('before') else 'blocked'} / {'allowed' if o.get('after') else 'blocked'} "
                     f"(in-cluster sink after: {'allowed' if o.get('in_cluster_after') else 'blocked'}) |")
    lines += [f"| Gatekeeper | {_kv(r['gatekeeper'])} |",
              f"| cosign keyless verify | {str(r['cosign_verified']).lower()} |",
              f"| Result | {'PASS' if r['passed'] else 'FAIL: ' + '; '.join(r['failures'])} |", "",
              f"Trace: `{' -> '.join(r['example_chain'])}`"]
    return "\n".join(lines)
