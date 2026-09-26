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
    rbac_risks: list[str] = field(default_factory=list)      # e.g. "cluster-wide secrets read"


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
    # --- populated by the real-manifest collector (stratum.k8s); empty for synthetic data
    images: list[str] = field(default_factory=list)          # every container image ref
    automount_token: Optional[bool] = None                   # effective automountServiceAccountToken
    pss_level: str = ""                                      # restricted | baseline | privileged
    pss_violations: dict = field(default_factory=dict)       # check id -> [violations] (restricted level)
    source: str = ""                                         # e.g. helm chart that rendered it


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
    label: str = "benign"        # ground truth annotation; never read by detectors
    # --- populated by real sensors (Tetragon); empty for synthetic data
    image: str = ""              # container image ref as reported by the runtime
    image_digest: str = ""       # sha256:... of the running image
    container_id: str = ""
    parent: str = ""             # parent process binary
    uid: int = -1
    privileged: bool = False     # CAP_SYS_ADMIN in the effective set
    node: str = ""
    source: str = ""             # file / stream the event came from


@dataclass
class ImageReport:
    """What an SBOM / vulnerability scan (Trivy) + OCI labels say about one image."""
    ref: str
    digest: str = ""
    os: str = ""                                             # e.g. "debian 12.11" -> base-image node
    packages: int = 0
    vulns: dict = field(default_factory=dict)                # severity -> count
    kev: list[str] = field(default_factory=list)             # CVEs in the CISA KEV catalog
    critical: list[str] = field(default_factory=list)        # CVE ids with severity CRITICAL
    shells: list[str] = field(default_factory=list)          # shell-providing packages (bash, busybox...)
    source_repo: str = ""                                    # org.opencontainers.image.source
    revision: str = ""                                       # org.opencontainers.image.revision


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
