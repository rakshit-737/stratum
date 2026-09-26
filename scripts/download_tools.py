"""Fetch the pinned third-party CLIs STRATUM drives: Trivy, Syft, Helm, OPA.

Binaries are verified against the checksum files each project publishes and
placed in $STRATUM_DATA/tools/. Nothing is installed system-wide.
"""
from __future__ import annotations

import platform
import stat
import sys
import tarfile
import urllib.request
import zipfile

from _common import UA, data_dir, fetch

TRIVY, SYFT, HELM, OPA = "0.74.0", "1.52.0", "4.3.0", "1.21.0"


def _plat() -> tuple[str, str]:
    osn = {"win32": "windows", "darwin": "darwin"}.get(sys.platform, "linux")
    arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "amd64"
    return osn, arch


def _sum_from(url: str, name: str) -> str:
    txt = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60).read().decode()
    for line in txt.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == name:
            return parts[0]
        if len(parts) == 1 and len(parts[0]) == 64:
            return parts[0]
    raise SystemExit(f"no checksum for {name} in {url}")


def _extract(archive, member_suffix: str, out) -> None:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            m = next(n for n in z.namelist() if n.endswith(member_suffix))
            out.write_bytes(z.read(m))
    else:
        with tarfile.open(archive) as t:
            m = next(n for n in t.getmembers() if n.name.endswith(member_suffix))
            out.write_bytes(t.extractfile(m).read())
    out.chmod(out.stat().st_mode | stat.S_IEXEC)


def main() -> None:
    osn, arch = _plat()
    exe = ".exe" if osn == "windows" else ""
    tools = data_dir() / "tools"
    tools.mkdir(exist_ok=True)

    tarch = {"amd64": "64bit", "arm64": "ARM64"}[arch]
    tos = {"windows": "windows", "linux": "Linux", "darwin": "macOS"}[osn]
    ext = "zip" if osn == "windows" else "tar.gz"
    n = f"trivy_{TRIVY}_{tos}-{tarch}.{ext}"
    base = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY}/"
    a = fetch(base + n, tools / n, sha=_sum_from(base + f"trivy_{TRIVY}_checksums.txt", n))
    _extract(a, "trivy" + exe, tools / ("trivy" + exe))

    n = f"syft_{SYFT}_{osn}_{arch}.{ext}"
    base = f"https://github.com/anchore/syft/releases/download/v{SYFT}/"
    a = fetch(base + n, tools / n, sha=_sum_from(base + f"syft_{SYFT}_checksums.txt", n))
    _extract(a, "syft" + exe, tools / ("syft" + exe))

    n = f"helm-v{HELM}-{osn}-{arch}.{ext}"
    base = "https://get.helm.sh/"
    a = fetch(base + n, tools / n, sha=_sum_from(base + n + ".sha256sum", n))
    _extract(a, "helm" + exe, tools / ("helm" + exe))

    n = f"opa_{osn}_{arch}{exe}" + ("_static" if osn == "linux" else "")
    base = f"https://github.com/open-policy-agent/opa/releases/download/v{OPA}/"
    fetch(base + n, tools / ("opa" + exe), sha=_sum_from(base + n + ".sha256", n))
    (tools / ("opa" + exe)).chmod(0o755)
    print(f"tools ready in {tools}")


if __name__ == "__main__":
    main()
