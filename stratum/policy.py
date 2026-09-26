"""Zero-Trust policy engine evaluated over the lifecycle graph + dataset.

Rules are plain Python (OPA/Rego export is a TODO); each maps to a named control
so every finding says *which* control is missing.
"""
from __future__ import annotations

import ipaddress

from .dataset import Dataset
from .graph import LifecycleGraph
from .models import Control, Finding, NetworkPolicy

CONTROLS: dict[str, Control] = {c.id: c for c in [
    Control("ZT-NET-01", "Default-deny egress NetworkPolicy per namespace", "Network", "NIST 800-207 tenet 5; CIS K8s 5.3.2"),
    Control("ZT-WL-01", "No privileged / root containers", "Workload", "CIS K8s 5.2.2, 5.2.7"),
    Control("ZT-ID-01", "Dedicated workload identity (no default SA)", "Identity", "CIS K8s 5.1.5"),
    Control("ZT-ID-02", "Disable SA token automount unless needed", "Identity", "CIS K8s 5.1.6"),
    Control("ZT-ID-03", "Least-privilege RBAC (no cluster-admin workloads)", "Identity", "CIS K8s 5.1.1"),
    Control("ZT-PROV-01", "Only images built by the trusted pipeline may run", "Supply chain", "SLSA L2 provenance"),
    Control("ZT-PROV-02", "Builds carry verified signed provenance", "Supply chain", "SLSA L2; Sigstore"),
    Control("ZT-IMG-01", "No deny-listed (vulnerable) base images", "Supply chain", "CIS Docker 4.4"),
    Control("ZT-IMG-02", "Minimal/distroless images, no interactive shell", "Workload", "CIS Docker 4.3"),
]}

SEV = {"ZT-NET-01": "high", "ZT-WL-01": "high", "ZT-ID-01": "medium", "ZT-ID-02": "medium",
       "ZT-ID-03": "critical", "ZT-PROV-01": "critical", "ZT-PROV-02": "high",
       "ZT-IMG-01": "high", "ZT-IMG-02": "medium"}


def _f(cid: str, subject: str, msg: str) -> Finding:
    return Finding(cid, subject, SEV[cid], msg)


def has_default_deny_egress(ds: Dataset, ns: str) -> bool:
    return any(np.namespace == ns and "Egress" in np.policy_types for np in ds.network_policies)


def egress_allowed(ds: Dataset, ns: str, ip: str) -> bool:
    """Simulated NetworkPolicy enforcement (egress only)."""
    pols = [np for np in ds.network_policies if np.namespace == ns and "Egress" in np.policy_types]
    if not pols:
        return True
    addr = ipaddress.ip_address(ip)
    return any(addr in ipaddress.ip_network(c) for np in pols for c in np.egress_allow_cidrs)


def evaluate(ds: Dataset, g: LifecycleGraph, deny_bases: tuple[str, ...] = ()) -> list[Finding]:
    out: list[Finding] = []
    for ns in ds.namespaces:
        if not has_default_deny_egress(ds, ns.name):
            out.append(_f("ZT-NET-01", f"ns:{ns.name}", f"namespace '{ns.name}' has no default-deny egress policy"))
    sas = {(s.namespace, s.name): s for s in ds.service_accounts}
    images = {i.digest: i for i in ds.images}
    builds = {b.id: b for b in ds.builds}
    for w in ds.workloads:
        wid = f"workload:{w.namespace}/{w.name}"
        if w.privileged or w.run_as_root or w.host_network:
            out.append(_f("ZT-WL-01", wid, f"{wid} runs privileged={w.privileged} root={w.run_as_root}"))
        if w.service_account == "default":
            out.append(_f("ZT-ID-01", wid, f"{wid} uses the default service account"))
        sa = sas.get((w.namespace, w.service_account))
        if sa and sa.cluster_admin:
            out.append(_f("ZT-ID-03", wid, f"{wid} identity {sa.name} is bound to cluster-admin"))
        img = images.get(w.image_digest)
        if img is None or img.build_id is None or img.build_id not in builds:
            ref = img.ref if img else w.image_digest
            out.append(_f("ZT-PROV-01", wid, f"{wid} runs {ref} with no trusted-pipeline provenance (drift)"))
        else:
            if not builds[img.build_id].signed:
                out.append(_f("ZT-PROV-02", wid, f"{wid} image build {img.build_id} is unsigned"))
            if img.base_image in deny_bases:
                out.append(_f("ZT-IMG-01", wid, f"{wid} built on deny-listed base {img.base_image}"))
    return out


def recommend_egress_policy(ns: str, allow: tuple[str, ...] = ("10.0.0.0/8",)) -> NetworkPolicy:
    return NetworkPolicy("stratum-default-deny-egress", ns, ["Egress"], list(allow))


def render_netpol_yaml(np: NetworkPolicy) -> str:
    lines = ["apiVersion: networking.k8s.io/v1", "kind: NetworkPolicy", "metadata:",
             f"  name: {np.name}", f"  namespace: {np.namespace}", "spec:", "  podSelector: {}",
             "  policyTypes:"] + [f"    - {t}" for t in np.policy_types] + ["  egress:"]
    lines += ["    - to:"] + [f"        - ipBlock:\n            cidr: {c}" for c in np.egress_allow_cidrs]
    lines += ["    - ports:", "        - protocol: UDP", "          port: 53"]
    return "\n".join(lines) + "\n"
