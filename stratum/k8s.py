"""Cluster-state collector for real Kubernetes manifests.

Input is what ``kubectl get -o yaml`` / ``helm template`` / a GitOps repo gives
you: one or more multi-document YAML streams. Output is a :class:`Dataset`
(namespaces, service accounts with RBAC risk, NetworkPolicies, workloads with
their Pod Security Standards level) that the lifecycle graph and the
Zero-Trust policy engine consume unchanged.

No cluster access is needed; a live-cluster variant is simply
``kubectl get deploy,ds,sts,job,cronjob,pod,sa,netpol,clusterrole,clusterrolebinding,role,rolebinding -A -o yaml | stratum collect -``.
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

import yaml

from .dataset import Dataset
from .models import Namespace, NetworkPolicy, ServiceAccount, Workload
from .pss import evaluate_pod, highest_level

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class _StratumLoader(_Loader):  # type: ignore[misc,valid-type]
    """SafeLoader that tolerates the YAML 1.1 ``=`` (value) tag some CRDs contain."""


_StratumLoader.add_constructor("tag:yaml.org,2002:value", lambda loader, node: loader.construct_scalar(node))

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "Pod",
                  "ReplicationController"}
_WILD = "*"


def load_docs(paths: Iterable[str | Path]) -> list[dict]:
    """Parse every YAML document in the given files (``List`` kinds are flattened)."""
    docs: list[dict] = []
    for p in paths:
        text = Path(p).read_text(encoding="utf-8", errors="replace")
        for d in yaml.load_all(text, Loader=_StratumLoader):  # noqa: S506 - safe loader subclass
            if not isinstance(d, dict):
                continue
            if d.get("kind") == "List" or (d.get("kind", "").endswith("List") and "items" in d):
                docs.extend(i for i in d.get("items") or [] if isinstance(i, dict))
            else:
                docs.append(d)
    return docs


def pod_template(obj: dict) -> dict | None:
    """Return a Pod-shaped {metadata, spec} for any workload kind."""
    kind, spec = obj.get("kind"), obj.get("spec") or {}
    if kind == "Pod":
        return {"metadata": obj.get("metadata") or {}, "spec": spec}
    if kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec")) or {}
    tpl = spec.get("template")
    if not isinstance(tpl, dict):
        return None
    return {"metadata": tpl.get("metadata") or {}, "spec": tpl.get("spec") or {}}


def _rule_risks(rules: list[dict]) -> list[str]:
    risks = []
    for r in rules or []:
        verbs, res = set(r.get("verbs") or []), set(r.get("resources") or [])
        groups = set(r.get("apiGroups") or [""])
        if _WILD in verbs and _WILD in res:
            risks.append("wildcard verbs on wildcard resources")
        if res & {"secrets", _WILD} and verbs & {"get", "list", "watch", _WILD} and groups & {"", _WILD}:
            risks.append("secrets read")
        if res & {"pods/exec", _WILD} and verbs & {"create", _WILD}:
            risks.append("pods/exec")
        if res & {"clusterrolebindings", "rolebindings", "roles", "clusterroles"} and verbs & {
                "escalate", "bind", _WILD}:
            risks.append("RBAC escalate/bind")
        if res & {"nodes/proxy"}:
            risks.append("nodes/proxy")
    return sorted(set(risks))


def collect(docs: list[dict], *, source: str = "", default_ns: str = "default") -> Dataset:
    ds = Dataset()
    ns_names: set[str] = set()
    sa_objs: dict[tuple[str, str], dict] = {}
    roles: dict[tuple[str, str], list[str]] = {}          # (ns|"", name) -> risks
    bindings: list[tuple[str, str, str, list[tuple[str, str]]]] = []  # (bind ns, roleKind, roleName, subjects)

    for d in docs:
        kind, meta = d.get("kind"), d.get("metadata") or {}
        ns = meta.get("namespace") or default_ns
        if kind == "Namespace":
            ns_names.add(meta.get("name"))
        elif kind == "ServiceAccount":
            sa_objs[(ns, meta.get("name"))] = d
        elif kind in ("ClusterRole", "Role"):
            roles[("" if kind == "ClusterRole" else ns, meta.get("name"))] = _rule_risks(d.get("rules"))
        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            ref = d.get("roleRef") or {}
            subs = [(s.get("namespace") or ns, s.get("name")) for s in d.get("subjects") or []
                    if s.get("kind") == "ServiceAccount"]
            bindings.append(("" if kind == "ClusterRoleBinding" else ns, ref.get("kind"), ref.get("name"), subs))
        elif kind == "NetworkPolicy":
            spec = d.get("spec") or {}
            types = spec.get("policyTypes") or (["Ingress", "Egress"] if "egress" in spec else ["Ingress"])
            cidrs = [(t.get("ipBlock") or {}).get("cidr") for e in spec.get("egress") or []
                     for t in e.get("to") or [] if t.get("ipBlock")]
            ds.network_policies.append(NetworkPolicy(meta.get("name"), ns, types, [c for c in cidrs if c]))
            ns_names.add(ns)

    # RBAC: which service accounts are cluster-admin / carry risky permissions
    sa_admin: dict[tuple[str, str], bool] = defaultdict(bool)
    sa_risks: dict[tuple[str, str], set[str]] = defaultdict(set)
    for bind_ns, rkind, rname, subs in bindings:
        risks = roles.get(("" if rkind == "ClusterRole" else bind_ns, rname), [])
        scope = "cluster-wide" if bind_ns == "" else f"in {bind_ns}"
        for s in subs:
            if rname == "cluster-admin" and rkind == "ClusterRole":
                sa_admin[s] = sa_admin[s] or bind_ns == ""
                sa_risks[s].add(f"cluster-admin {scope}")
            for r in risks:
                sa_risks[s].add(f"{r} {scope}")

    for d in docs:
        kind, meta = d.get("kind"), d.get("metadata") or {}
        if kind not in WORKLOAD_KINDS:
            continue
        pod = pod_template(d)
        if pod is None:
            continue
        ns = meta.get("namespace") or default_ns
        ns_names.add(ns)
        spec = pod["spec"]
        sa = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
        sa_obj = sa_objs.get((ns, sa)) or {}
        automount = spec.get("automountServiceAccountToken")
        if automount is None:
            automount = sa_obj.get("automountServiceAccountToken", True)
        containers = [c for k in ("initContainers", "containers") for c in spec.get(k) or []]
        images = [c.get("image", "") for c in containers if c.get("image")]
        main = (spec.get("containers") or [{}])[0].get("image", "") or (images[0] if images else "?")
        viol = evaluate_pod(pod, "restricted")
        ctx = [c.get("securityContext") or {} for c in containers]
        psc = spec.get("securityContext") or {}
        root = psc.get("runAsUser") == 0 or any(c.get("runAsUser") == 0 for c in ctx)
        ds.workloads.append(Workload(
            name=meta.get("name"), namespace=ns, kind=kind, image_digest=main, service_account=sa,
            privileged=any(c.get("privileged") for c in ctx), run_as_root=root,
            host_network=bool(spec.get("hostNetwork")), pods=[f"{meta.get('name')}-0"],
            images=images, automount_token=bool(automount), pss_level=highest_level(pod),
            pss_violations=viol, source=source))
        if (ns, sa) not in sa_objs and sa != "default":
            sa_objs[(ns, sa)] = {}

    for (ns, name) in sorted(set(sa_objs) | set(sa_risks)):
        ds.service_accounts.append(ServiceAccount(name, ns, cluster_admin=sa_admin[(ns, name)],
                                                  rbac_risks=sorted(sa_risks[(ns, name)])))
    ds.namespaces = [Namespace(n) for n in sorted(n for n in ns_names if n)]
    return ds


def collect_files(paths: Iterable[str | Path], *, source: str = "", default_ns: str = "default") -> Dataset:
    return collect(load_docs(paths), source=source, default_ns=default_ns)
