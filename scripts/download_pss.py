"""Kubernetes Pod Security Standards conformance fixtures (labelled ground truth).

Source: github.com/kubernetes/pod-security-admission (Apache-2.0), test/testdata.
Each fixture is a Pod manifest that the upstream PSA implementation must
ACCEPT (pass/) or REJECT (fail/) at a given level (baseline / restricted); the
filename prefix names the violated check. We use them to measure STRATUM's
policy engine against the reference implementation's own conformance suite.
"""
from __future__ import annotations

import shutil
import tarfile
from pathlib import Path

from _common import data_dir, fetch

TAG = "v0.37.1"
URL = f"https://codeload.github.com/kubernetes/pod-security-admission/tar.gz/refs/tags/{TAG}"


def main() -> None:
    out = data_dir() / "pss"
    arc = fetch(URL, out / f"pod-security-admission-{TAG}.tar.gz", key=f"pss/{TAG}.tar.gz")
    dest = out / "testdata"
    if dest.exists():
        shutil.rmtree(dest)
    with tarfile.open(arc) as t:
        for m in t.getmembers():
            if "/test/testdata/" in m.name and m.isfile() and m.name.endswith(".yaml"):
                rel = m.name.split("/test/testdata/", 1)[1]
                p = (dest / rel).resolve()
                if Path(rel).is_absolute() or ".." in Path(rel).parts or not p.is_relative_to(dest.resolve()):
                    print(f"skipping suspicious archive member {m.name!r}")
                    continue
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(t.extractfile(m).read())
    n = sum(1 for _ in dest.rglob("*.yaml"))
    print(f"PSS fixtures: {n} yaml files under {dest}")


if __name__ == "__main__":
    main()
