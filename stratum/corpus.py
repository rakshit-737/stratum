"""Locate and load the real-data corpus produced by ``scripts/download_*.py``.

Everything lives under ``$STRATUM_DATA`` (default ``./data``). Functions here
return ``None`` / empty results when a piece is missing so callers (CLI, API,
benchmarks, tests marked ``realdata``) can degrade gracefully.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .dataset import Dataset
from .ingest import load_kev, trivy_reports
from .k8s import collect_files
from .models import ImageReport


def data_dir() -> Path:
    return Path(os.environ.get("STRATUM_DATA", Path.cwd() / "data"))


def manifest_index(root: Path | None = None) -> dict:
    p = (root or data_dir()) / "manifests" / "index.json"
    return json.loads(p.read_text()) if p.exists() else {}


def manifests_dataset(root: Path | None = None, projects: list[str] | None = None) -> Dataset:
    """One Dataset for a notional cluster running every downloaded project."""
    base = (root or data_dir()) / "manifests"
    ds = Dataset()
    for name, meta in manifest_index(root).items():
        if projects and name not in projects:
            continue
        part = collect_files([base / f for f in meta["files"]], source=name, default_ns=name)
        ds.merge(part)
    # namespaces / SAs may repeat across projects sharing kube-system
    seen, nss = set(), []
    for n in ds.namespaces:
        if n.name not in seen:
            seen.add(n.name)
            nss.append(n)
    ds.namespaces = nss
    return ds


def kev_ids(root: Path | None = None) -> set[str]:
    p = (root or data_dir()) / "kev" / "known_exploited_vulnerabilities.json"
    return load_kev(p) if p.exists() else set()


def scan_reports(root: Path | None = None) -> list[ImageReport]:
    d = (root or data_dir()) / "scans"
    files = sorted(d.glob("*.trivy.json")) if d.exists() else []
    return trivy_reports(files, kev_ids(root)) if files else []


def provenance_path(root: Path | None = None) -> Path:
    return (root or data_dir()) / "provenance" / "provenance.json"
