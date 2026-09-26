"""Scan the images referenced by the manifest corpus with Trivy (remote pull, no Docker).

Images are scanned smallest-first until a download budget is exhausted
(``--budget-mb``, default 1500) so the corpus stays laptop-sized; the list of
scanned / skipped images is written to scans/index.json. Output: one
``<name>.trivy.json`` per image (``--list-all-pkgs`` so shells can be detected).

Only public images are pulled from their public registries and scanned as
files; nothing is executed.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import data_dir  # noqa: E402

from stratum.corpus import provenance_path  # noqa: E402
from stratum.provenance import load  # noqa: E402


def safe(ref: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", ref.split("@")[0])[-120:]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget-mb", type=int, default=1500)
    ap.add_argument("--timeout", default="20m")
    a = ap.parse_args()
    root = data_dir()
    trivy = next((p for p in (root / "tools" / "trivy.exe", root / "tools" / "trivy") if p.exists()), None)
    if trivy is None:
        raise SystemExit("trivy not found - run scripts/download_tools.py first")
    provs = [p for p in load(provenance_path(root)) if not p.resolved.get("error")]
    provs.sort(key=lambda p: p.resolved.get("size", 0))
    out = root / "scans"
    out.mkdir(exist_ok=True)
    index, used = {"scanned": [], "skipped": [], "failed": []}, 0
    for p in provs:
        size = p.resolved.get("size", 0)
        dest = out / f"{safe(p.ref)}.trivy.json"
        if dest.exists():
            index["scanned"].append(p.ref)
            used += size
            continue
        if used + size > a.budget_mb * 1e6:
            index["skipped"].append({"ref": p.ref, "size_mb": round(size / 1e6, 1)})
            continue
        # scan the exact linux/amd64 digest we resolved, report under the manifest's ref
        r = p.resolved
        target = p.ref.split("@")[0].rsplit(":", 1)[0] if ":" in p.ref.split("/")[-1] else p.ref.split("@")[0]
        target = f"{target}@{r['digest']}"
        print(f"  scan {p.ref[:80]} ({size / 1e6:.0f} MB)", flush=True)
        cmd = [str(trivy), "image", "--image-src", "remote", "--scanners", "vuln", "--list-all-pkgs",
               "--format", "json", "--cache-dir", str(root / "trivy-cache"), "--skip-db-update",
               "--no-progress", "--timeout", a.timeout, "-o", str(dest), target]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0 or not dest.exists():
            index["failed"].append({"ref": p.ref, "err": res.stderr[-300:]})
            dest.unlink(missing_ok=True)
            continue
        doc = json.loads(dest.read_text(encoding="utf-8"))
        doc["ArtifactName"] = p.ref
        dest.write_text(json.dumps(doc), encoding="utf-8")
        index["scanned"].append(p.ref)
        used += size
    (out / "index.json").write_text(json.dumps(index, indent=1))
    print(f"scanned {len(index['scanned'])}, skipped {len(index['skipped'])} (budget), "
          f"failed {len(index['failed'])}; ~{used / 1e6:.0f} MB pulled")


if __name__ == "__main__":
    main()
