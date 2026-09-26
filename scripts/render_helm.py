"""Render popular Helm charts with their DEFAULT values into plain manifests.

Adds Helm-only projects to the manifest corpus ($STRATUM_DATA/manifests/<name>/)
and registers them in manifests/index.json with category "helm". Requires the
helm binary from scripts/download_tools.py. Chart versions are pinned below;
``helm template`` is offline rendering - nothing is installed anywhere.
"""
from __future__ import annotations

import json
import subprocess

from _common import data_dir, record, sha256

# name -> (repo URL or oci:// ref, chart, version, extra args)
CHARTS: dict[str, tuple[str, str, str, list[str]]] = {
    "vault": ("https://helm.releases.hashicorp.com", "vault", "0.34.1", []),
    "falco": ("https://falcosecurity.github.io/charts", "falco", "9.2.0", []),
    "tetragon": ("https://helm.cilium.io", "tetragon", "1.7.1", []),
    "traefik": ("https://traefik.github.io/charts", "traefik", "41.6.0", []),
    "external-secrets": ("https://charts.external-secrets.io", "external-secrets", "2.11.0", []),
    "trivy-operator": ("https://aquasecurity.github.io/helm-charts", "trivy-operator", "0.36.0", []),
    "redis-bitnami": ("oci://registry-1.docker.io/bitnamicharts", "redis", "28.2.4", []),
    "postgresql-bitnami": ("oci://registry-1.docker.io/bitnamicharts", "postgresql", "18.12.2", []),
    "jenkins": ("https://charts.jenkins.io", "jenkins", "5.9.64", []),
    "harbor": ("https://helm.goharbor.io", "harbor", "1.19.2", []),
    # Large repo indexes (tens of MB); enable when bandwidth allows:
    # "grafana": ("https://grafana.github.io/helm-charts", "grafana", "", []),
    # "prometheus": ("https://prometheus-community.github.io/helm-charts", "prometheus", "", []),
}


def main() -> None:
    root = data_dir()
    helm = next((p for p in (root / "tools" / "helm.exe", root / "tools" / "helm") if p.exists()), None)
    if helm is None:
        raise SystemExit("helm not found - run scripts/download_tools.py first")
    out = root / "manifests"
    idx_path = out / "index.json"
    index = json.loads(idx_path.read_text()) if idx_path.exists() else {}
    for name, (repo, chart, ver, extra) in CHARTS.items():
        dest = out / name / f"{name}.yaml"
        dest.parent.mkdir(parents=True, exist_ok=True)
        if repo.startswith("oci://"):
            cmd = [str(helm), "template", name, f"{repo}/{chart}"]
        else:
            cmd = [str(helm), "template", name, chart, "--repo", repo]
        cmd += ["--namespace", name, *extra] + (["--version", ver] if ver else [])
        print(f"  helm template {name} ...", flush=True)
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if res.returncode != 0:
            print(f"    FAILED: {res.stderr.strip()[-300:]}")
            continue
        dest.write_text(res.stdout, encoding="utf-8")
        chart_ver = f"{chart}-{ver}" if ver else next(
            (ln.split(":", 1)[1].strip().strip('"') for ln in res.stdout.splitlines() if "helm.sh/chart" in ln), "?")
        record(f"helm/{name}", f"{chart_ver} {sha256(dest)}", pin=False)
        index[name] = {"version": chart_ver, "category": "helm", "files": [f"{name}/{name}.yaml"],
                       "urls": [f"{repo} {chart}"]}
        print(f"    ok  {chart_ver}")
    idx_path.write_text(json.dumps(index, indent=2))


if __name__ == "__main__":
    main()
