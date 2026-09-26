"""Parsers for real sensor / scanner output.

* :func:`tetragon_events` - Cilium Tetragon JSON export (``tetra getevents -o json``
  or the ``export-filename`` log) -> :class:`RuntimeEvent`.
* :func:`trivy_report` - ``trivy image --format json --list-all-pkgs`` ->
  :class:`ImageReport` (vulnerability counts, KEV hits, shells, OCI labels).
* :func:`load_kev` - CISA Known Exploited Vulnerabilities catalog -> set of CVE ids.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Iterator
from datetime import datetime
from pathlib import Path

from .models import Image, ImageReport, RuntimeEvent, Workload
from .registry import github_repo, revision

SHELL_PACKAGES = {"bash", "dash", "busybox", "busybox-binsh", "zsh", "mksh", "ash", "tcsh", "ksh", "yash",
                  "loksh", "oksh", "fish"}


# ------------------------------------------------------------------ Tetragon
def _iter_json(path: Path) -> Iterator[dict]:
    text = path.read_text(encoding="utf-8")
    try:
        doc = json.loads(text)
        yield from (doc if isinstance(doc, list) else [doc])
    except json.JSONDecodeError:
        for line in text.splitlines():
            if line.strip():
                yield json.loads(line)


def _ts(s: str) -> float:
    if not s:
        return 0.0
    s = s.rstrip("Z")
    if "." in s:  # Tetragon emits nanoseconds; datetime takes microseconds
        head, frac = s.split(".", 1)
        s = f"{head}.{frac[:6]}"
    return datetime.fromisoformat(s + "+00:00").timestamp()


def _strip_runtime(image_id: str) -> str:
    for p in ("docker-pullable://", "docker://", "containerd://"):
        image_id = image_id.removeprefix(p)
    return image_id


def tetragon_event(raw: dict, source: str = "") -> RuntimeEvent | None:
    kind = next((k for k in raw if k.startswith("process_")), None)
    if kind is None:
        return None
    body = raw[kind]
    proc, parent = body.get("process") or {}, body.get("parent") or {}
    pod = proc.get("pod") or {}
    ctr = pod.get("container") or {}
    img = ctr.get("image") or {}
    image_id = _strip_runtime(img.get("id", ""))
    caps = ((proc.get("cap") or {}).get("effective")) or []
    ev = RuntimeEvent(
        ts=_ts(raw.get("time", "")), pod=pod.get("name") or f"ctr:{proc.get('docker', '')[:12] or 'host'}",
        namespace=pod.get("namespace", ""), kind="", process=proc.get("binary", ""),
        args=proc.get("arguments", ""), image=img.get("name", ""),
        image_digest=image_id.split("@", 1)[1] if "@" in image_id else "",
        container_id=_strip_runtime(ctr.get("id", "")) or proc.get("docker", ""),
        parent=parent.get("binary", ""), uid=int(proc.get("uid", -1)),
        privileged="CAP_SYS_ADMIN" in caps, node=raw.get("node_name", ""), source=source)
    if kind == "process_exec":
        ev.kind = "exec"
    elif kind == "process_connect":
        ev.kind, ev.dest_ip, ev.dest_port = "connect", body.get("destination_ip", ""), int(
            body.get("destination_port") or 0)
    elif kind == "process_listen":
        ev.kind = "listen"
    elif kind == "process_kprobe":
        fn = body.get("function_name", "")
        args = body.get("args") or []
        path = next(("/" + a["file_arg"]["path"].lstrip("/") for a in args if "file_arg" in a), "")
        sock = next((a["sock_arg"] for a in args if "sock_arg" in a), None)
        if sock:
            ev.kind, ev.dest_ip, ev.dest_port = "connect", sock.get("daddr", ""), int(sock.get("dport") or 0)
        elif path:
            ev.kind, ev.path = ("write" if "write" in fn else "open"), path
        else:
            ev.kind = "kprobe:" + fn
    else:  # exit / close: lifecycle bookkeeping, not security signal
        return None
    return ev


def tetragon_events(paths: Iterable[str | Path]) -> list[RuntimeEvent]:
    out = []
    for p in paths:
        p = Path(p)
        for raw in _iter_json(p):
            e = tetragon_event(raw, source=p.name)
            if e is not None:
                out.append(e)
    return sorted(out, key=lambda e: e.ts)


# --------------------------------------------------------------------- Trivy
def load_kev(path: str | Path) -> set[str]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    return {v["cveID"] for v in doc.get("vulnerabilities", [])}


def trivy_report(doc: dict, kev: set[str] | None = None) -> ImageReport:
    kev = kev or set()
    meta = doc.get("Metadata") or {}
    osinfo = meta.get("OS") or {}
    labels = (((meta.get("ImageConfig") or {}).get("config")) or {}).get("Labels") or {}
    sev: Counter = Counter()
    seen: set[tuple[str, str]] = set()
    crit, kev_hits, shells, pkgs = set(), set(), set(), 0
    for res in doc.get("Results") or []:
        for p in res.get("Packages") or []:
            pkgs += 1
            if res.get("Class") == "os-pkgs" and p.get("Name") in SHELL_PACKAGES:
                shells.add(p["Name"])
        for v in res.get("Vulnerabilities") or []:
            key = (v.get("VulnerabilityID", ""), v.get("PkgName", ""))
            if key in seen:
                continue
            seen.add(key)
            s = v.get("Severity", "UNKNOWN")
            sev[s] += 1
            if s == "CRITICAL":
                crit.add(key[0])
            if key[0] in kev:
                kev_hits.add(key[0])
    digests = meta.get("RepoDigests") or []
    return ImageReport(
        ref=doc.get("ArtifactName", ""),
        digest=digests[0].split("@", 1)[1] if digests and "@" in digests[0] else "",
        os=f"{osinfo.get('Family', '')} {osinfo.get('Name', '')}".strip(),
        packages=pkgs, vulns=dict(sev), kev=sorted(kev_hits), critical=sorted(crit),
        shells=sorted(shells), source_repo=github_repo(labels), revision=revision(labels))


def trivy_reports(paths: Iterable[str | Path], kev: set[str] | None = None) -> list[ImageReport]:
    return [trivy_report(json.loads(Path(p).read_text(encoding="utf-8")), kev) for p in paths]


def runtime_inventory(events: Iterable[RuntimeEvent], known: set[tuple[str, str]] | None = None
                      ) -> tuple[list[Workload], list[Image]]:
    """Workloads/images observed only at runtime (pods not present in any manifest).

    A pod seen by the sensor but absent from the declared cluster state is
    itself a drift signal; its image is keyed by the runtime digest so the
    lifecycle trace still reaches the exact image that ran.
    """
    known = known or set()
    wl: dict[tuple[str, str], Workload] = {}
    imgs: dict[str, Image] = {}
    for e in events:
        if not e.namespace or (e.namespace, e.pod) in known:
            continue
        ref = f"{e.image.split('@')[0]}@{e.image_digest}" if e.image_digest else (e.image or "?")
        key = (e.namespace, e.pod)
        if key not in wl:
            wl[key] = Workload(e.pod, e.namespace, "Pod(runtime)", ref, pods=[e.pod], images=[ref],
                               privileged=e.privileged, source=f"runtime:{e.source}")
        else:
            wl[key].privileged = wl[key].privileged or e.privileged
        if ref not in imgs:
            imgs[ref] = Image(ref, e.image, None)
    return list(wl.values()), list(imgs.values())
