"""Runtime detection: deterministic rules + a small unsupervised novelty model.

"AI flags, the graph explains": the anomaly model only scores novelty of
(process, event-kind, destination-port) per workload vs. a baseline window.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict

from .graph import LifecycleGraph
from .models import Detection, RuntimeEvent

SHELLS = {"sh", "bash", "dash", "ash", "zsh"}
_INTERNAL = [ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # NOTE: Python treats TEST-NET ranges as "private"; cluster-internal == RFC1918 + loopback here.
    return not (addr.is_loopback or any(addr in n for n in _INTERNAL))



def rule_detect(e: RuntimeEvent) -> Detection | None:
    base = e.process.rsplit("/", 1)[-1]
    if e.kind == "exec" and base in SHELLS:
        return Detection("R-SHELL", e, "high", 1.0, f"interactive shell '{e.process}' spawned in container", "ZT-IMG-02")
    if e.kind == "open" and "serviceaccount/token" in e.path:
        return Detection("R-SA-TOKEN", e, "high", 1.0, f"'{e.process}' read the service-account token", "ZT-ID-02")
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

    def fit(self, events: list[tuple[str, RuntimeEvent]]) -> "NoveltyModel":
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
    def wid(e):
        return g.pod_workload(e.namespace, e.pod) or f"pod:{e.namespace}/{e.pod}"

    train = [(wid(e), e) for e in events if e.ts < train_end]
    model = NoveltyModel().fit(train)
    out: list[Detection] = []
    for e in events:
        if e.ts < train_end:
            continue
        d = rule_detect(e)
        s = model.score(wid(e), e)
        if d:
            d.score = max(d.score, s)
            out.append(d)
        elif s >= model.threshold:
            out.append(Detection("A-NOVEL", e, "medium", s, f"behaviour never seen for {wid(e)}", "ZT-IMG-02"))
    return out
