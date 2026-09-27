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
                  image_ref: str, commit: str, repo: str, author: str = "", run_id: str = "live",
                  signed: bool = False) -> Dataset:
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
    ds.commits.append(Commit(commit, repo, author, "live CI build"))
    ds.builds.append(Build(run_id, commit, "github-actions", signed=signed))
    ds.images.append(Image(image_ref, image_ref, run_id))
    ds.events = tetragon_events(events)
    return ds


def check(ds: Dataset, *, namespace: str, workload: str, image_digest: str, commit: str,
          gatekeeper: dict | None = None, cosign_ok: bool | None = None) -> dict:
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
    }
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
    if cosign_ok is False:
        fails.append("cosign verify failed")
    res["failures"] = fails
    res["passed"] = not fails
    return res


def markdown(r: dict) -> str:
    return "\n".join([
        "### Live kind + Tetragon run (GitHub Actions)", "",
        f"- Tetragon events: {r['events_total']} total, {r['events_in_namespace']} in the demo namespace "
        f"({r['event_kinds']})",
        f"- Rules raised on the demo pod: {', '.join(r['rules_on_target']) or '-'}",
        f"- Incidents traced to the CI commit: {r['traced_to_commit']}/{r['incidents_on_target']}",
        f"- Detections on other pods in the namespace (sink): {r['incidents_other_pods_in_namespace']}",
        f"- Trace: {' -> '.join(r['example_chain'])}",
        f"- Gatekeeper: {r['gatekeeper']}", f"- cosign keyless verify: {r['cosign_verified']}",
        f"- Result: {'PASS' if r['passed'] else 'FAIL: ' + '; '.join(r['failures'])}"])
