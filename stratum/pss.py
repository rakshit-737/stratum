"""Kubernetes Pod Security Standards (baseline + restricted), latest (v1.37) semantics.

A pure-Python re-implementation of the checks in k8s.io/pod-security-admission,
used in two places:

* the Zero-Trust policy engine (workload-hardening controls ZT-WL-*), and
* the conformance benchmark (``stratum bench pss``), which replays the upstream
  project's own pass/fail fixtures against this module.

Every check returns a list of human-readable violations; an empty list = pass.
Check ids match the upstream fixture filename prefixes so results can be scored
per check.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable

Pod = dict  # {"metadata": {...}, "spec": {...}}

BASELINE_CAPS = {"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "MKNOD",
                 "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}
SAFE_SYSCTLS = {
    "kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.tcp_syncookies",
    "net.ipv4.ping_group_range", "net.ipv4.ip_unprivileged_port_start",
    "net.ipv4.ip_local_reserved_ports", "net.ipv4.tcp_keepalive_time", "net.ipv4.tcp_fin_timeout",
    "net.ipv4.tcp_keepalive_intvl", "net.ipv4.tcp_keepalive_probes", "net.ipv4.tcp_rmem",
    "net.ipv4.tcp_wmem", "net.ipv4.tcp_slow_start_after_idle", "net.ipv4.tcp_notsent_lowat",
}
SELINUX_TYPES = {"", "container_t", "container_init_t", "container_kvm_t", "container_engine_t"}
RESTRICTED_VOLUMES = {"configMap", "csi", "downwardAPI", "emptyDir", "ephemeral",
                      "persistentVolumeClaim", "projected", "secret", "image"}
_VOLUME_META = {"name"}


def _containers(spec: dict) -> Iterable[dict]:
    for key in ("initContainers", "containers", "ephemeralContainers"):
        yield from spec.get(key) or []


def _sc(obj: dict) -> dict:
    return obj.get("securityContext") or {}


def _is_windows(spec: dict) -> bool:
    return ((spec.get("os") or {}).get("name") or "").lower() == "windows"


def _userns(spec: dict) -> bool:
    return spec.get("hostUsers") is False


# ---------------------------------------------------------------- baseline
def host_namespaces(meta: dict, spec: dict) -> list[str]:
    return [f"{k}=true" for k in ("hostNetwork", "hostPID", "hostIPC") if spec.get(k)]


def privileged(meta: dict, spec: dict) -> list[str]:
    return [f"container {c.get('name')} privileged" for c in _containers(spec) if _sc(c).get("privileged")]


def capabilities_baseline(meta: dict, spec: dict) -> list[str]:
    out = []
    for c in _containers(spec):
        add = ((_sc(c).get("capabilities") or {}).get("add")) or []
        bad = [x for x in add if x not in BASELINE_CAPS]
        if bad:
            out.append(f"container {c.get('name')} adds {','.join(bad)}")
    return out


def host_path_volumes(meta: dict, spec: dict) -> list[str]:
    return [f"volume {v.get('name')} is hostPath" for v in spec.get("volumes") or [] if "hostPath" in v]


def host_ports(meta: dict, spec: dict) -> list[str]:
    return [f"container {c.get('name')} hostPort {p['hostPort']}" for c in _containers(spec)
            for p in c.get("ports") or [] if p.get("hostPort")]


def _apparmor_ok_field(prof: dict | None) -> bool:
    return prof is None or prof.get("type") in (None, "RuntimeDefault", "Localhost")


def apparmor_profile(meta: dict, spec: dict) -> list[str]:
    out = []
    for k, v in (meta.get("annotations") or {}).items():
        if k.startswith("container.apparmor.security.beta.kubernetes.io/"):
            if not (v in ("", "runtime/default") or v.startswith("localhost/")):
                out.append(f"annotation {k}={v}")
    if not _apparmor_ok_field(_sc(spec).get("appArmorProfile")):
        out.append("pod appArmorProfile")
    out += [f"container {c.get('name')} appArmorProfile" for c in _containers(spec)
            if not _apparmor_ok_field(_sc(c).get("appArmorProfile"))]
    return out


def _selinux_bad(opts: dict | None) -> bool:
    if not opts:
        return False
    return (opts.get("type") or "") not in SELINUX_TYPES or bool(opts.get("user")) or bool(opts.get("role"))


def selinux_options(meta: dict, spec: dict) -> list[str]:
    out = ["pod seLinuxOptions"] if _selinux_bad(_sc(spec).get("seLinuxOptions")) else []
    out += [f"container {c.get('name')} seLinuxOptions" for c in _containers(spec)
            if _selinux_bad(_sc(c).get("seLinuxOptions"))]
    return out


def _unmasked(spec: dict) -> list[str]:
    return [f"container {c.get('name')} procMount={_sc(c)['procMount']}" for c in _containers(spec)
            if _sc(c).get("procMount") not in (None, "Default")]


def proc_mount(meta: dict, spec: dict) -> list[str]:
    return [] if _userns(spec) else _unmasked(spec)


def seccomp_profile_baseline(meta: dict, spec: dict) -> list[str]:
    out = []
    for k, v in (meta.get("annotations") or {}).items():
        if k == "seccomp.security.alpha.kubernetes.io/pod" or k.startswith(
                "container.seccomp.security.alpha.kubernetes.io/"):
            if not (v in ("runtime/default", "docker/default") or v.startswith("localhost/")):
                out.append(f"annotation {k}={v}")
    if (_sc(spec).get("seccompProfile") or {}).get("type") == "Unconfined":
        out.append("pod seccompProfile Unconfined")
    out += [f"container {c.get('name')} seccompProfile Unconfined" for c in _containers(spec)
            if (_sc(c).get("seccompProfile") or {}).get("type") == "Unconfined"]
    return out


def sysctls(meta: dict, spec: dict) -> list[str]:
    return [f"sysctl {s.get('name')}" for s in _sc(spec).get("sysctls") or [] if s.get("name") not in SAFE_SYSCTLS]


def windows_host_process(meta: dict, spec: dict) -> list[str]:
    out = ["pod hostProcess"] if (_sc(spec).get("windowsOptions") or {}).get("hostProcess") else []
    out += [f"container {c.get('name')} hostProcess" for c in _containers(spec)
            if (_sc(c).get("windowsOptions") or {}).get("hostProcess")]
    return out


def host_probes_and_host_lifecycle(meta: dict, spec: dict) -> list[str]:
    out = []
    for c in _containers(spec):
        handlers = [c.get(p) for p in ("livenessProbe", "readinessProbe", "startupProbe")]
        handlers += [(c.get("lifecycle") or {}).get(h) for h in ("postStart", "preStop")]
        for h in handlers:
            for kind in ("httpGet", "tcpSocket"):
                host = ((h or {}).get(kind) or {}).get("host")
                if host:
                    out.append(f"container {c.get('name')} {kind}.host={host}")
    return out


# -------------------------------------------------------------- restricted
def restricted_volumes(meta: dict, spec: dict) -> list[str]:
    out = []
    for v in spec.get("volumes") or []:
        kinds = set(v) - _VOLUME_META
        bad = kinds - RESTRICTED_VOLUMES
        if bad:
            out.append(f"volume {v.get('name')} type {','.join(sorted(bad))}")
    return out


def allow_privilege_escalation(meta: dict, spec: dict) -> list[str]:
    if _is_windows(spec):
        return []
    return [f"container {c.get('name')} allowPrivilegeEscalation!=false" for c in _containers(spec)
            if _sc(c).get("allowPrivilegeEscalation") is not False]


def run_as_non_root(meta: dict, spec: dict) -> list[str]:
    if _userns(spec):
        return []
    pod_val = _sc(spec).get("runAsNonRoot")
    out = ["pod runAsNonRoot=false"] if pod_val is False else []
    for c in _containers(spec):
        v = _sc(c).get("runAsNonRoot")
        if v is False:
            out.append(f"container {c.get('name')} runAsNonRoot=false")
        elif v is None and pod_val is not True:
            out.append(f"container {c.get('name')} runAsNonRoot unset")
    return out


def run_as_user(meta: dict, spec: dict) -> list[str]:
    if _userns(spec):
        return []
    out = ["pod runAsUser=0"] if _sc(spec).get("runAsUser") == 0 else []
    out += [f"container {c.get('name')} runAsUser=0" for c in _containers(spec) if _sc(c).get("runAsUser") == 0]
    return out


def seccomp_profile_restricted(meta: dict, spec: dict) -> list[str]:
    if _is_windows(spec):
        return []
    ok = ("RuntimeDefault", "Localhost")
    pod_t = (_sc(spec).get("seccompProfile") or {}).get("type")
    out = [f"pod seccompProfile {pod_t}"] if pod_t is not None and pod_t not in ok else []
    for c in _containers(spec):
        t = (_sc(c).get("seccompProfile") or {}).get("type")
        if t is not None and t not in ok:
            out.append(f"container {c.get('name')} seccompProfile {t}")
        elif t is None and pod_t not in ok:
            out.append(f"container {c.get('name')} seccompProfile unset")
    return out


def capabilities_restricted(meta: dict, spec: dict) -> list[str]:
    if _is_windows(spec):
        return []
    out = []
    for c in _containers(spec):
        caps = _sc(c).get("capabilities") or {}
        if "ALL" not in (caps.get("drop") or []):
            out.append(f"container {c.get('name')} does not drop ALL")
        bad = [x for x in caps.get("add") or [] if x != "NET_BIND_SERVICE"]
        if bad:
            out.append(f"container {c.get('name')} adds {','.join(bad)}")
    return out


def proc_mount_restricted(meta: dict, spec: dict) -> list[str]:
    return _unmasked(spec)


Check = Callable[[dict, dict], list[str]]
BASELINE: dict[str, Check] = {
    "hostnamespaces": host_namespaces, "privileged": privileged,
    "capabilities_baseline": capabilities_baseline, "hostpathvolumes": host_path_volumes,
    "hostports": host_ports, "apparmorprofile": apparmor_profile, "selinuxoptions": selinux_options,
    "procmount": proc_mount, "seccompprofile_baseline": seccomp_profile_baseline, "sysctls": sysctls,
    "windowshostprocess": windows_host_process, "hostprobesandhostlifecycle": host_probes_and_host_lifecycle,
}
RESTRICTED: dict[str, Check] = {
    **BASELINE, "restrictedvolumes": restricted_volumes,
    "allowprivilegeescalation": allow_privilege_escalation, "runasnonroot": run_as_non_root,
    "runasuser": run_as_user, "seccompprofile_restricted": seccomp_profile_restricted,
    "capabilities_restricted": capabilities_restricted, "procmount_restricted": proc_mount_restricted,
}
LEVELS = {"baseline": BASELINE, "restricted": RESTRICTED}


def evaluate_pod(pod: Pod, level: str = "restricted") -> dict[str, list[str]]:
    """Return {check_id: [violations]} for every failing check at ``level``."""
    meta, spec = pod.get("metadata") or {}, pod.get("spec") or {}
    out = {}
    for cid, fn in LEVELS[level].items():
        v = fn(meta, spec)
        if v:
            out[cid] = v
    return out


def highest_level(pod: Pod) -> str:
    """The strictest PSS level the pod satisfies: restricted | baseline | privileged."""
    if not evaluate_pod(pod, "restricted"):
        return "restricted"
    if not evaluate_pod(pod, "baseline"):
        return "baseline"
    return "privileged"


def legacy_check(pod: Pod) -> bool:
    """The v0.1 MVP heuristic (privileged / root / hostNetwork), kept as a benchmark baseline.

    Returns True when the pod would have been flagged.
    """
    spec = pod.get("spec") or {}
    if spec.get("hostNetwork"):
        return True
    if _sc(spec).get("runAsUser") == 0:
        return True
    return any(_sc(c).get("privileged") or _sc(c).get("runAsUser") == 0 for c in _containers(spec))
