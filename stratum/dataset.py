"""Dataset bundle: what the collectors emit (CI provenance, K8s state, runtime events)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .models import (
    Build,
    Commit,
    Image,
    ImageReport,
    Namespace,
    NetworkPolicy,
    RuntimeEvent,
    ServiceAccount,
    Workload,
    from_dict,
    to_dict,
)

_KINDS = {
    "commits": Commit, "builds": Build, "images": Image, "namespaces": Namespace,
    "service_accounts": ServiceAccount, "network_policies": NetworkPolicy,
    "workloads": Workload, "events": RuntimeEvent, "image_reports": ImageReport,
}


@dataclass
class Dataset:
    commits: list[Commit] = field(default_factory=list)
    builds: list[Build] = field(default_factory=list)
    images: list[Image] = field(default_factory=list)
    namespaces: list[Namespace] = field(default_factory=list)
    service_accounts: list[ServiceAccount] = field(default_factory=list)
    network_policies: list[NetworkPolicy] = field(default_factory=list)
    workloads: list[Workload] = field(default_factory=list)
    events: list[RuntimeEvent] = field(default_factory=list)
    image_reports: list[ImageReport] = field(default_factory=list)
    ground_truth: dict = field(default_factory=dict)

    def to_json(self) -> str:
        out = {k: [to_dict(o) for o in getattr(self, k)] for k in _KINDS}
        out["ground_truth"] = self.ground_truth
        return json.dumps(out, indent=2)

    @classmethod
    def from_json(cls, text: str) -> Dataset:
        raw = json.loads(text)
        ds = cls(ground_truth=raw.get("ground_truth", {}))
        for k, typ in _KINDS.items():
            setattr(ds, k, [from_dict(typ, d) for d in raw.get(k, [])])
        return ds

    def merge(self, other: Dataset) -> Dataset:
        """Union of two bundles (e.g. manifests + scans + provenance)."""
        for k in _KINDS:
            getattr(self, k).extend(getattr(other, k))
        self.ground_truth.update(other.ground_truth)
        return self

    def save(self, path) -> None:
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path) -> Dataset:
        return cls.from_json(Path(path).read_text(encoding="utf-8"))
