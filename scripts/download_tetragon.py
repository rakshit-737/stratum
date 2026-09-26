"""Real Cilium Tetragon JSON events, pinned to a commit of cilium/tetragon (Apache-2.0).

These are the events captured for the book "Security Observability with eBPF"
(Isovalent/O'Reilly, 2022): a privileged-pod container escape (nsenter into the
host namespaces), a Merlin C2 agent started via a static pod, and
post-exploitation (7z, scp, ssh tunnel), plus the process-lifecycle examples
and the repository's testdata stream. Event logs only - no binaries.
"""
from __future__ import annotations

from _common import data_dir, fetch

COMMIT = "1911464de685034ca2ce49274a0fd983ac569b38"
BASE = f"https://raw.githubusercontent.com/cilium/tetragon/{COMMIT}/"
DOC = "docs/security-observability-with-ebpf/03_chapter/"
FILES = [
    "testdata/events.json",
    *[DOC + "00_four_golden_signals/" + f for f in (
        "process_exec.json", "process_connect.json", "process_listen.json",
        "process_close.json", "process_kprobe.json", "process_exit.json")],
    *[DOC + "00_process_lifecycle/" + f for f in (
        "lifecycle_sh_process_exec.json", "cat_process_exec.json", "cat_process_kprobe.json",
        "nc_process_exec.json", "nc_process_connect.json", "nc_process_close.json")],
    *[DOC + "03_security_observability_events/01_reaching_the_host_namespace/" + f for f in (
        "nginx-execution.json", "nginx-listen.json", "privileged-pod-init.json",
        "privileged-pod-bash.json", "privileged-pod-nsenter.json", "host-namespace-bash.json")],
    *[DOC + "03_security_observability_events/02_persistance/" + f for f in (
        "merlin-agent-insert-pod-spec.json", "merlin-agent-container-start-containerd-shim.json",
        "merlin-agent-container-start-runc.json", "merlin-agent-go-start.json",
        "merlin-agent-go-connect.json", "merlin-agent-job-connect.json", "merlin-agent-job-close.json")],
    *[DOC + "03_security_observability_events/03_post_exploitation_techniques/" + f for f in (
        "merlin-agent-sh.json", "merlin-agent-7z.json", "merlin-agent-scp.json",
        "merlin-agent-scp-sh.json", "merlin-agent-scp-ssh.json", "merlin-agent-ssh-tunnel-connect.json",
        "merlin-agent-ssh-tunnel-close.json")],
]


def main() -> None:
    out = data_dir() / "tetragon"
    for f in FILES:
        fetch(BASE + f, out / f, key=f"tetragon/{f}")
    print(f"Tetragon events: {len(FILES)} files under {out}")


if __name__ == "__main__":
    main()
