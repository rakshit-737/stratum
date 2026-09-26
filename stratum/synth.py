"""Deterministic synthetic cluster + CI provenance + runtime event generator.

No live Kubernetes needed. The scenario embeds the five demo stories from the spec:
shell-in-pod, C2 egress with no egress policy, a vulnerable shared base image,
an untrusted (drift) image, and a service-account token grab. Ground truth is
recorded so trace-to-commit accuracy can be measured.
"""
from __future__ import annotations

import random

from .dataset import Dataset
from .models import (Build, Commit, Image, Namespace, NetworkPolicy, RuntimeEvent,
                     ServiceAccount, Workload)

BAD_BASE = "alpine:3.14.0"          # stands in for a base image with a known-critical CVE
GOOD_BASE = "python:3.12-slim"
TRAIN_END = 1000.0                  # events before this ts form the anomaly baseline

# name, ns, repo, base, sa, privileged, root, author, pr, main process, internal ports
_SERVICES = [
    ("frontend", "shop", "acme/frontend", BAD_BASE, "default", False, False, "alice", 101, "node", [8080]),
    ("cart", "shop", "acme/cart", BAD_BASE, "cart-sa", False, False, "bob", 214, "python", [6379, 8080]),
    ("payments-api", "payments", "acme/payments", GOOD_BASE, "payments-sa", False, False, "carol", 57, "gunicorn", [5432]),
    ("worker", "legacy", "acme/worker", BAD_BASE, "worker-sa", True, True, "dave", 9, "celery", [5672]),
]


def _sha(rng: random.Random) -> str:
    return "%040x" % rng.getrandbits(160)


def generate(seed: int = 7, benign_per_pod: int = 40) -> Dataset:
    rng = random.Random(seed)
    ds = Dataset()
    for ns in ("shop", "payments", "legacy"):
        ds.namespaces.append(Namespace(ns))
    ds.service_accounts += [
        ServiceAccount("default", "shop"), ServiceAccount("cart-sa", "shop"),
        ServiceAccount("payments-sa", "payments"),
        ServiceAccount("worker-sa", "legacy", cluster_admin=True),
    ]
    # payments is the only namespace with a default-deny egress policy
    ds.network_policies.append(NetworkPolicy("default-deny-egress", "payments", ["Egress"], ["10.0.0.0/8"]))

    commit_of: dict[str, str] = {}
    procs: dict[str, tuple[str, list[int]]] = {}
    for i, (name, ns, repo, base, sa, priv, root, author, pr, proc, ports) in enumerate(_SERVICES):
        sha = _sha(rng)
        commit_of[f"{ns}/{name}"] = sha
        ds.commits.append(Commit(sha, repo, author, f"feat({name}): release", pr))
        bid = f"gha-{1000 + i}"
        ds.builds.append(Build(bid, sha, "github-actions/release.yml", signed=True))
        digest = "sha256:" + "%064x" % rng.getrandbits(256)
        ds.images.append(Image(digest, f"ghcr.io/{repo}:1.{i}.0", bid, base,
                               layers=[f"base:{base}", f"app:{sha[:8]}"]))
        pods = [f"{name}-{rng.randrange(16**5):05x}-{k}" for k in range(2)]
        ds.workloads.append(Workload(name, ns, "Deployment", digest, sa, priv, root, pods=pods))
        for p in pods:
            procs[p] = (proc, ports)

    # drift: image pulled from a random registry, not built by the trusted pipeline
    rogue = "sha256:" + "%064x" % rng.getrandbits(256)
    ds.images.append(Image(rogue, "docker.io/randomuser/debug-tools:latest", None, None))
    ds.workloads.append(Workload("debug-tools", "shop", "Pod", rogue, "default", pods=["debug-tools"]))
    procs["debug-tools"] = ("sleep", [])

    # benign baseline + post-baseline benign traffic
    for w in ds.workloads:
        for p in w.pods:
            proc, ports = procs[p]
            for _ in range(benign_per_pod):
                ts = rng.uniform(0, 2000)
                r = rng.random()
                if r < 0.2 or not ports:
                    ds.events.append(RuntimeEvent(ts, p, w.namespace, "exec", proc, "--serve"))
                elif r < 0.8:
                    ds.events.append(RuntimeEvent(ts, p, w.namespace, "connect", proc,
                                                  dest_ip=f"10.0.{rng.randrange(4)}.{rng.randrange(2, 250)}",
                                                  dest_port=rng.choice(ports)))
                else:
                    ds.events.append(RuntimeEvent(ts, p, w.namespace, "open", proc, path="/app/config.yaml"))

    cart_pod = ds.workloads[1].pods[0]
    worker_pod = ds.workloads[3].pods[0]
    attacks = [
        RuntimeEvent(1500.0, cart_pod, "shop", "exec", "/bin/sh", "-c id", label="shell"),
        RuntimeEvent(1501.0, cart_pod, "shop", "connect", "/bin/sh", dest_ip="203.0.113.50", dest_port=4444, label="c2"),
        RuntimeEvent(1600.0, worker_pod, "legacy", "open", "cat",
                     path="/var/run/secrets/kubernetes.io/serviceaccount/token", label="token"),
        RuntimeEvent(1601.0, worker_pod, "legacy", "connect", "curl", dest_ip="198.51.100.9", dest_port=443, label="exfil"),
        RuntimeEvent(1700.0, "debug-tools", "shop", "connect", "xmrig", dest_ip="198.51.100.77", dest_port=3333, label="miner"),
    ]
    ds.events += attacks
    ds.events.sort(key=lambda e: e.ts)
    ds.ground_truth = {
        "train_end": TRAIN_END,
        "bad_base": BAD_BASE,
        "attacks": [
            {"pod": cart_pod, "namespace": "shop", "commit": commit_of["shop/cart"], "label": "shell"},
            {"pod": cart_pod, "namespace": "shop", "commit": commit_of["shop/cart"], "label": "c2"},
            {"pod": worker_pod, "namespace": "legacy", "commit": commit_of["legacy/worker"], "label": "token"},
            {"pod": worker_pod, "namespace": "legacy", "commit": commit_of["legacy/worker"], "label": "exfil"},
            {"pod": "debug-tools", "namespace": "shop", "commit": None, "label": "miner"},
        ],
    }
    return ds
