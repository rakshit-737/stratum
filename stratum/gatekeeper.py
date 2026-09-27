"""Export policies/pss/pss.rego as an OPA Gatekeeper ConstraintTemplate + Constraint, and evaluate it with opa.

``policies/pss/pss.rego`` re-implements 8 of the 19 Pod Security Standards checks (the ones that are
plain field tests); ``tests/test_gatekeeper.py`` diffs it against :mod:`stratum.pss` on the upstream
fixtures when an ``opa`` binary is available.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import yaml

from .opa import POLICY_DIR, find_opa

PSS_REGO = POLICY_DIR / "pss" / "pss.rego"
KIND = "StratumPodSecurity"
REGO_CHECKS = ("hostnamespaces", "privileged", "capabilities_baseline", "hostpathvolumes", "hostports",
               "allowprivilegeescalation", "runasuser", "runasnonroot")
POD_KINDS = [{"apiGroups": [""], "kinds": ["Pod"]},
             {"apiGroups": ["apps"], "kinds": ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"]},
             {"apiGroups": ["batch"], "kinds": ["Job", "CronJob"]}]


def template_rego() -> str:
    return PSS_REGO.read_text(encoding="utf-8").replace("package stratum.pss", f"package {KIND.lower()}", 1)


def constraint_template() -> dict:
    return {
        "apiVersion": "templates.gatekeeper.sh/v1",
        "kind": "ConstraintTemplate",
        "metadata": {"name": KIND.lower(), "annotations": {"description": "Pod Security Standards subset exported by STRATUM"}},
        "spec": {
            "crd": {"spec": {"names": {"kind": KIND}, "validation": {"openAPIV3Schema": {
                "type": "object", "properties": {"level": {"type": "string", "enum": ["baseline", "restricted"]}}}}}},
            "targets": [{"target": "admission.k8s.gatekeeper.sh", "rego": template_rego()}],
        },
    }


def constraint(level: str = "restricted", action: str = "dryrun", exclude_ns: tuple[str, ...] = ("kube-system",)) -> dict:
    return {
        "apiVersion": "constraints.gatekeeper.sh/v1beta1",
        "kind": KIND,
        "metadata": {"name": f"stratum-pss-{level}"},
        "spec": {"enforcementAction": action,
                 "match": {"kinds": POD_KINDS, "excludedNamespaces": list(exclude_ns)},
                 "parameters": {"level": level}},
    }


def export_yaml(level: str = "restricted", action: str = "dryrun",
                exclude_ns: tuple[str, ...] = ("kube-system",)) -> str:
    return yaml.safe_dump_all([constraint_template(), constraint(level, action, exclude_ns)], sort_keys=False)


def rego_violations(objs: list[dict], opa: str | None = None) -> list[set[str]]:
    """Failing check ids per object according to the Rego policy (needs opa)."""
    opa = opa or find_opa()
    if not opa:
        raise FileNotFoundError("opa binary not found (PATH or $STRATUM_DATA/tools)")
    with tempfile.TemporaryDirectory() as td:
        data = Path(td) / "objs.json"
        data.write_text(json.dumps({"stratum_objs": objs}), encoding="utf-8")
        query = ("[v | some o in data.stratum_objs; "
                 "v := data.stratum.pss.violations with input as {\"review\": {\"object\": o}}]")
        res = subprocess.run([opa, "eval", "--format", "json", "-d", str(PSS_REGO), "-d", str(data), query],
                             capture_output=True, text=True, timeout=600)
    if res.returncode != 0:
        raise RuntimeError(res.stderr[-800:])
    vals = json.loads(res.stdout)["result"][0]["expressions"][0]["value"]
    return [{v[0] for v in vs} for vs in vals]
