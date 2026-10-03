"""Where a result file came from: CI run, commit and dataset manifest hash (written into every results/*.json)."""
from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


def _git(*args: str) -> str:
    try:
        return subprocess.run(["git", *args], capture_output=True, text=True, timeout=10,
                              cwd=Path(__file__).resolve().parents[2]).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def provenance(data_root: Path | None = None) -> dict:
    """``source_run`` (GitHub Actions run URL, or None for a local run), ``commit`` (``GITHUB_SHA`` or git HEAD),
    ``code_modified`` (uncommitted changes under ``stratum/`` at run time) and the SHA-256 of
    ``$STRATUM_DATA/MANIFEST.json`` when the run read the downloaded corpus."""
    env = os.environ
    run = (f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{env['GITHUB_REPOSITORY']}/actions/runs/"
           f"{env['GITHUB_RUN_ID']}" if env.get("GITHUB_RUN_ID") and env.get("GITHUB_REPOSITORY") else None)
    out: dict = {"source_run": run, "commit": env.get("GITHUB_SHA") or _git("rev-parse", "HEAD") or None}
    if not env.get("GITHUB_SHA"):
        out["code_modified"] = bool(_git("status", "--porcelain", "--", "stratum"))
    if data_root is not None and (Path(data_root) / "MANIFEST.json").is_file():
        out["dataset_manifest_sha256"] = hashlib.sha256((Path(data_root) / "MANIFEST.json").read_bytes()).hexdigest()
    return out
