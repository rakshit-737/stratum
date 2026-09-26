"""One-shot data pipeline (the `make data` target).

    python scripts/download_all.py            # everything (~1-2 GB incl. image layers)
    python scripts/download_all.py --no-scan  # skip Trivy image pulls (~60 MB)

Order: tools -> PSS fixtures -> Tetragon events -> ADFA-LD -> CISA KEV ->
manifests -> Helm renders -> image provenance -> Trivy scans.
Set STRATUM_DATA to choose where data goes (default ./data, git-ignored).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
STEPS = ["download_tools", "download_pss", "download_tetragon", "download_adfa", "download_kev",
         "download_manifests", "render_helm", "resolve_provenance", "scan_images"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-scan", action="store_true", help="skip pulling images for Trivy")
    ap.add_argument("--only", nargs="*", help="run only these steps")
    a = ap.parse_args()
    for step in a.only or STEPS:
        if a.no_scan and step == "scan_images":
            continue
        print(f"== {step}", flush=True)
        rc = subprocess.run([sys.executable, str(HERE / f"{step}.py")], cwd=HERE).returncode
        if rc != 0:
            print(f"   {step} failed (exit {rc}); continuing", flush=True)


if __name__ == "__main__":
    main()
