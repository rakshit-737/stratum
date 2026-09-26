"""Trace detections to commit + failed control + blast radius; policy-as-prevention replay; metrics."""
from __future__ import annotations

from dataclasses import dataclass, field

from .dataset import Dataset
from .detect import detect
from .graph import LifecycleGraph, build_graph
from .models import Detection, Finding, Incident
from .policy import CONTROLS, SEV, egress_allowed, evaluate, recommend_egress_policy, render_netpol_yaml

FIX = {
    "ZT-NET-01": "apply a default-deny egress NetworkPolicy to the namespace",
    "ZT-WL-01": "set securityContext privileged=false, runAsNonRoot=true",
    "ZT-ID-01": "create a dedicated ServiceAccount for the workload",
    "ZT-ID-02": "set automountServiceAccountToken: false",
    "ZT-ID-03": "remove the cluster-admin ClusterRoleBinding; grant namespaced least-privilege Role",
    "ZT-PROV-01": "admission-deny images lacking trusted-pipeline provenance; rebuild via CI",
    "ZT-PROV-02": "sign builds (cosign) and verify at admission",
    "ZT-IMG-01": "rebuild on a patched base image",
    "ZT-IMG-02": "switch to a distroless image without a shell",
    "ZT-WL-02": "meet PSS restricted: runAsNonRoot, drop ALL capabilities, seccomp RuntimeDefault, "
                "allowPrivilegeEscalation=false (and readOnlyRootFilesystem)",
    "ZT-ID-04": "replace cluster-wide secret/RBAC-escalation grants with namespaced, resource-named Roles",
    "ZT-PROV-03": "pin images by @sha256 digest and verify signatures at admission",
    "ZT-IMG-03": "patch the KEV-listed CVE immediately (CISA BOD 22-01) and rebuild",
}


@dataclass
class Analysis:
    graph: LifecycleGraph
    findings: list[Finding]
    detections: list[Detection]
    incidents: list[Incident]
    extra: dict = field(default_factory=dict)


def _related_subjects(g: LifecycleGraph, wid: str | None, ns: str) -> set[str]:
    subs = {f"ns:{ns}"}
    if wid:
        subs.add(wid)
        subs.update(g.trace_upstream(wid))
    return subs


def build_incident(n: int, d: Detection, g: LifecycleGraph, findings: list[Finding]) -> Incident:
    e = d.event
    pod = f"pod:{e.namespace}/{e.pod}"
    wid = g.pod_workload(e.namespace, e.pod)
    chain = g.trace_upstream(pod)
    commit = next((c for c in chain if c.startswith("commit:")), None)
    cattrs = g.nodes.get(commit, {}) if commit else {}
    subs = _related_subjects(g, wid, e.namespace)
    failed = [f for f in findings if f.subject in subs]
    if not any(f.control_id == d.control_id for f in failed):
        # runtime-only control: the detection itself proves the gap
        failed.insert(0, Finding(d.control_id, wid or pod, SEV[d.control_id],
                                 f"runtime evidence: {d.reason}"))
    else:  # put the control that should have stopped *this* event first
        failed.sort(key=lambda f: f.control_id != d.control_id)
    image = next((c for c in chain if c.startswith("image:")), None)
    bases = g.parents(image, "base_of") if image else []
    blast = g.blast_radius(bases[0]) if bases else ([wid] if wid else [])
    recs = []
    for f in failed:
        fix = FIX.get(f.control_id, f"remediate {f.control_id}")
        if fix not in recs:
            recs.append(fix)
    return Incident(f"INC-{n:04d}", d, wid, chain, commit.split(":", 1)[1] if commit else None,
                    cattrs.get("author"), cattrs.get("pr"), failed, blast, recs)


def analyze(ds: Dataset, deny_bases: tuple[str, ...] | None = None) -> Analysis:
    if deny_bases is None:
        deny_bases = (ds.ground_truth["bad_base"],) if "bad_base" in ds.ground_truth else ()
    g = build_graph(ds)
    findings = evaluate(ds, g, deny_bases)
    dets = detect(ds.events, g, ds.ground_truth.get("train_end", 0.0))
    incidents = [build_incident(i + 1, d, g, findings) for i, d in enumerate(dets)]
    return Analysis(g, findings, dets, incidents)


def replay_with_policy(ds: Dataset, namespace: str) -> dict:
    """Apply the recommended egress policy and re-emulate external connects."""
    np = recommend_egress_policy(namespace)
    before = [e for e in ds.events if e.namespace == namespace and e.kind == "connect"]
    ds.network_policies.append(np)
    blocked = [e for e in before if not egress_allowed(ds, namespace, e.dest_ip)]
    return {"policy_yaml": render_netpol_yaml(np), "connects": len(before),
            "blocked": len(blocked), "blocked_malicious": sum(e.label != "benign" for e in blocked),
            "blocked_benign": sum(e.label == "benign" for e in blocked)}


def metrics(ds: Dataset, a: Analysis) -> dict:
    truth = ds.ground_truth.get("attacks", [])
    hits = correct = 0
    for t in truth:
        inc = next((i for i in a.incidents if i.detection.event.pod == t["pod"]
                    and i.detection.event.label == t["label"]), None)
        if inc:
            hits += 1
            correct += inc.root_commit == t["commit"]
    fps = sum(i.detection.event.label == "benign" for i in a.incidents)
    gaps = {f.control_id for i in a.incidents for f in i.failed_controls}
    return {"attacks": len(truth), "detected": hits,
            "detection_rate": hits / len(truth) if truth else 0.0,
            "trace_to_commit_accuracy": correct / hits if hits else 0.0,
            "false_positives": fps, "controls_named": sorted(gaps),
            "controls_catalog": len(CONTROLS)}
