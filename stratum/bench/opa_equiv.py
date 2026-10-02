"""Rego/Python equivalence on the full real corpus: policies/stratum.rego evaluated by a real ``opa``."""
from __future__ import annotations

import subprocess
from pathlib import Path

from ..opa import diff, find_opa
from ..realdata import real_dataset


def available() -> bool:
    return find_opa() is not None


def run(root: Path) -> dict:
    opa = find_opa()
    ver = subprocess.run([opa, "version"], capture_output=True, text=True).stdout.splitlines()[0] if opa else ""
    d = diff(real_dataset(root), opa=opa)  # same input as `stratum opa-check --data real`
    return {"opa": ver.replace("Version: ", ""), **{k: (len(v) if isinstance(v, list) else v) for k, v in d.items()}}


def markdown(r: dict) -> str:
    return "\n".join(["### Rego mirror vs Python engine on the real corpus", "",
                      f"OPA {r['opa']}: Python findings {r['python']}, Rego findings {r['rego']}, "
                      f"only-Python {r['only_python']}, only-Rego {r['only_rego']}, equivalent: **{str(r['equivalent']).lower()}**."])
