"""Evaluate policies/stratum.rego with a real ``opa`` binary and diff against the Python engine."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .dataset import Dataset
from .graph import build_graph
from .policy import evaluate

POLICY_DIR = Path(__file__).resolve().parents[1] / "policies"


def find_opa() -> str | None:
    cand = shutil.which("opa")
    if cand:
        return cand
    tools = Path(os.environ.get("STRATUM_DATA", Path(__file__).resolve().parents[1] / "data")) / "tools"
    for n in ("opa.exe", "opa"):
        if (tools / n).exists():
            return str(tools / n)
    return None


def rego_input(ds: Dataset, deny_bases: tuple[str, ...] = ()) -> dict:
    doc = json.loads(ds.to_json())
    doc.pop("events", None)
    doc["deny_bases"] = list(deny_bases)
    return doc


def opa_findings(ds: Dataset, deny_bases: tuple[str, ...] = (), opa: str | None = None) -> set[tuple[str, str]]:
    opa = opa or find_opa()
    if not opa:
        raise FileNotFoundError("opa binary not found (PATH or $STRATUM_DATA/tools)")
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "input.json"
        inp.write_text(json.dumps(rego_input(ds, deny_bases)), encoding="utf-8")
        res = subprocess.run([opa, "eval", "--format", "json", "-d", str(POLICY_DIR), "-i", str(inp),
                              "data.stratum.findings"], capture_output=True, text=True, timeout=300)
    if res.returncode != 0:
        raise RuntimeError(res.stderr[-800:])
    val = json.loads(res.stdout)["result"][0]["expressions"][0]["value"]
    return {(f["control_id"], f["subject"]) for f in val}


def diff(ds: Dataset, deny_bases: tuple[str, ...] = (), opa: str | None = None) -> dict:
    py = {(f.control_id, f.subject) for f in evaluate(ds, build_graph(ds), deny_bases)}
    rg = opa_findings(ds, deny_bases, opa)
    return {"python": len(py), "rego": len(rg), "only_python": sorted(py - rg), "only_rego": sorted(rg - py),
            "equivalent": py == rg}
