"""Runtime detection: deterministic rules + a small unsupervised novelty model.

"AI flags, the graph explains": the anomaly model only scores novelty of
(process, event-kind, destination-port) per workload vs. a baseline window.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter, defaultdict

from .graph import LifecycleGraph
from .models import Detection, RuntimeEvent

SHELLS = {"sh", "bash", "dash", "ash", "zsh", "ksh", "busybox"}
NET_TOOLS = {"nc", "ncat", "netcat", "socat", "nmap", "ssh", "scp", "sftp", "telnet", "sshpass", "masscan"}
ESCAPE_TOOLS = {"nsenter", "unshare", "chroot"}
CRED_PATHS = ("serviceaccount/token", "/.ssh/id_", "/etc/shadow", ".keystore", "/.aws/credentials",
              "/.kube/config", "/.docker/config.json")
SYSTEM_WRITE = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/crontab", "/root/.ssh/authorized_keys",
                "/etc/ld.so.preload")
TMP_DIRS = ("/tmp/", "/dev/shm/", "/var/tmp/")
# projected SA token as the kernel sees it: .../serviceaccount/..2026_09_27_10_00_00.123/token
_SA_TOKEN = re.compile(r"serviceaccount/(\.\.[^/]+/)?token$|/\.\.\d{4}_\d\d_\d\d_[^/]+/token$")
_INTERNAL = [ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                "100.64.0.0/10", "fd00::/8")]


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # NOTE: Python treats TEST-NET ranges as "private"; cluster-internal == RFC1918/CGNAT/ULA + loopback here.
    return not (addr.is_loopback or addr.is_link_local or any(addr in n for n in _INTERNAL if
                                                              n.version == addr.version))


def rule_detect(e: RuntimeEvent) -> Detection | None:
    """Deterministic rules, most specific first. Each names the control that should have prevented it."""
    base = e.process.rsplit("/", 1)[-1]
    if e.kind == "exec" and base in ESCAPE_TOOLS and ("-t 1" in e.args or "--target 1" in e.args or not e.args):
        return Detection("R-ESCAPE", e, "critical", 1.0,
                         f"'{base} {e.args}' entered the host namespaces (container escape)", "ZT-WL-01")
    if e.kind in ("open", "write") and ("serviceaccount/token" in e.path or _SA_TOKEN.search(e.path)):
        return Detection("R-SA-TOKEN", e, "high", 1.0, f"'{e.process}' read the service-account token", "ZT-ID-02")
    if e.kind in ("open", "write") and any(c in e.path for c in CRED_PATHS):
        return Detection("R-CRED-READ", e, "high", 1.0, f"'{base}' accessed credential material {e.path}",
                         "ZT-ID-04")
    if e.kind == "write" and e.path.startswith(SYSTEM_WRITE):
        return Detection("R-SYS-WRITE", e, "high", 1.0, f"'{base}' modified {e.path}", "ZT-WL-02")
    if e.kind == "exec" and e.pod.startswith("ctr:") and e.container_id:
        return Detection("R-UNMANAGED", e, "high", 1.0,
                         f"process '{base}' in container {e.container_id[:12]} not managed by Kubernetes "
                         "(no pod / pipeline provenance)", "ZT-PROV-01")
    if e.kind == "exec" and e.process.startswith(TMP_DIRS):
        return Detection("R-TMP-EXEC", e, "high", 1.0, f"binary executed from a temp dir: {e.process}", "ZT-WL-02")
    if e.kind == "exec" and base in NET_TOOLS:
        return Detection("R-NETTOOL", e, "high", 1.0, f"network/lateral-movement tool '{base} {e.args[:60]}'",
                         "ZT-IMG-02")
    if e.kind == "exec" and base in SHELLS:
        return Detection("R-SHELL", e, "high", 1.0, f"shell '{e.process}' spawned in container", "ZT-IMG-02")
    if e.kind == "connect" and _is_external(e.dest_ip):
        return Detection("R-EGRESS", e, "high", 1.0,
                         f"egress to external {e.dest_ip}:{e.dest_port} from '{e.process}'", "ZT-NET-01")
    return None


class NoveltyModel:
    """Per-workload frequency baseline; score = 1 - P(feature | workload)."""

    def __init__(self, threshold: float = 0.99) -> None:
        self.threshold = threshold
        self.counts: dict[str, Counter] = defaultdict(Counter)
        self.totals: Counter = Counter()

    @staticmethod
    def feature(e: RuntimeEvent) -> tuple:
        return (e.kind, e.process.rsplit("/", 1)[-1], e.dest_port if e.kind == "connect" else e.path)

    def fit(self, events: list[tuple[str, RuntimeEvent]]) -> NoveltyModel:
        for wid, e in events:
            self.counts[wid][self.feature(e)] += 1
            self.totals[wid] += 1
        return self

    def score(self, wid: str, e: RuntimeEvent) -> float:
        tot = self.totals.get(wid, 0)
        if tot == 0:
            return 1.0
        return 1.0 - self.counts[wid][self.feature(e)] / tot


def detect(events: list[RuntimeEvent], g: LifecycleGraph, train_end: float) -> list[Detection]:
    """Rules on every post-baseline event; the novelty model only when a baseline window exists."""
    def wid(e):
        return g.pod_workload(e.namespace, e.pod) or f"pod:{e.namespace}/{e.pod}"

    train = [(wid(e), e) for e in events if e.ts < train_end]
    model = NoveltyModel().fit(train) if train else None
    out: list[Detection] = []
    for e in events:
        if e.ts < train_end:
            continue
        d = rule_detect(e)
        s = model.score(wid(e), e) if model else 0.0
        if d:
            d.score = max(d.score, s)
            out.append(d)
        elif model and s >= model.threshold:
            out.append(Detection("A-NOVEL", e, "medium", s, f"behaviour never seen for {wid(e)}", "ZT-IMG-02"))
    return out


def legacy_rule_detect(e: RuntimeEvent) -> Detection | None:
    """The v0.1 rule set (shell / SA token / external egress), kept as a benchmark baseline."""
    base = e.process.rsplit("/", 1)[-1]
    if e.kind == "exec" and base in {"sh", "bash", "dash", "ash", "zsh"}:
        return Detection("R-SHELL", e, "high", 1.0, "shell", "ZT-IMG-02")
    if e.kind == "open" and "serviceaccount/token" in e.path:
        return Detection("R-SA-TOKEN", e, "high", 1.0, "sa token", "ZT-ID-02")
    if e.kind == "connect" and _is_external(e.dest_ip):
        return Detection("R-EGRESS", e, "high", 1.0, "egress", "ZT-NET-01")
    return None
