"""Assemble the real-data lifecycle bundle: manifests + image provenance + scans + runtime events."""
from __future__ import annotations

from pathlib import Path

from .corpus import data_dir, manifests_dataset, provenance_path, scan_reports
from .dataset import Dataset
from .ingest import runtime_inventory, tetragon_events
from .provenance import load, to_dataset


def real_dataset(root: Path | None = None, *, with_events: bool = True) -> Dataset:
    root = root or data_dir()
    ds = manifests_dataset(root)
    if not ds.workloads:
        raise FileNotFoundError(f"no manifests under {root}/manifests - run scripts/download_manifests.py")
    reports = scan_reports(root)
    pp = provenance_path(root)
    if pp.exists():
        ds.merge(to_dataset(load(pp), reports))
    else:
        ds.image_reports = reports
    if with_events and (root / "tetragon").exists():
        ds.events = tetragon_events(sorted((root / "tetragon").rglob("*.json")))
        known = {(w.namespace, p) for w in ds.workloads for p in w.pods}
        wl, imgs = runtime_inventory(ds.events, known)
        ds.workloads += wl
        ds.images += [i for i in imgs if i.digest not in {x.digest for x in ds.images}]
    return ds


def available(root: Path | None = None) -> bool:
    return ((root or data_dir()) / "manifests" / "index.json").exists()
