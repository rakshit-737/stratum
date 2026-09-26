"""Typed domain models. Plain dataclasses so they serialize to JSON trivially."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Optional


@dataclass
class Commit:
    sha: str
    repo: str
    author: str
    message: str
    pr: Optional[int] = None


@dataclass
class Build:
    id: str
    commit_sha: str
    pipeline: str
    signed: bool = True          # provenance attestation present/verified


@dataclass
class Image:
    digest: str
    ref: str
    build_id: Optional[str]      # None => not produced by the trusted pipeline
    base_image: Optional[str] = None
    layers: list[str] = field(default_factory=list)


@dataclass
class Namespace:
    name: str


@dataclass
class ServiceAccount:
    name: str
    namespace: str
    cluster_admin: bool = False


@dataclass
class NetworkPolicy:
    name: str
    namespace: str
    policy_types: list[str] = field(default_factory=lambda: ["Egress"])
    egress_allow_cidrs: list[str] = field(default_factory=list)  # empty + Egress => default deny


@dataclass
class Workload:
    name: str
    namespace: str
    kind: str
    image_digest: str
    service_account: str = "default"
    privileged: bool = False
    run_as_root: bool = False
    host_network: bool = False
    pods: list[str] = field(default_factory=list)


@dataclass
class RuntimeEvent:
    ts: float
    pod: str
    namespace: str
    kind: str                    # exec | connect | open
    process: str = ""
    args: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    path: str = ""
    label: str = "benign"        # synthetic ground truth; never read by detectors


@dataclass
class Control:
    id: str
    title: str
    pillar: str                  # Zero-Trust pillar
    reference: str               # NIST SP 800-207 / CIS K8s / SLSA reference


@dataclass
class Finding:
    control_id: str
    subject: str                 # graph node id
    severity: str
    message: str


@dataclass
class Detection:
    rule: str
    event: RuntimeEvent
    severity: str
    score: float
    reason: str
    control_id: str              # control that should have prevented it


@dataclass
class Incident:
    id: str
    detection: Detection
    workload: Optional[str]
    chain: list[str]             # pod -> workload -> image -> build -> commit
    root_commit: Optional[str]
    author: Optional[str]
    pr: Optional[int]
    failed_controls: list[Finding]
    blast_radius: list[str]
    recommendations: list[str]


def from_dict(cls, d: dict):
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in d.items() if k in names})


def to_dict(obj) -> dict:
    return asdict(obj)
