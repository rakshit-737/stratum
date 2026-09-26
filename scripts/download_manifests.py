"""Real Kubernetes install manifests of popular open-source projects.

Each entry is the upstream project's own pinned release manifest (most are
rendered by the project from its official Helm chart, e.g. ingress-nginx,
cert-manager, kyverno, gatekeeper, longhorn). Licences are the projects' own
(Apache-2.0 for all entries below). The first download records a SHA-256 in
scripts/checksums.json; later runs are verified against it.

Helm-only charts can be added with ``scripts/render_helm.py`` if a ``helm``
binary is available (see scripts/download_tools.py).
"""
from __future__ import annotations

import json

from _common import data_dir, fetch

GH = "https://github.com"
RAW = "https://raw.githubusercontent.com"
KSM = f"{RAW}/kubernetes/kube-state-metrics/v2.20.0/examples/standard/"

# name -> (version, [urls], category)
MANIFESTS: dict[str, tuple[str, list[str], str]] = {
    "argo-cd": ("v3.5.3", [f"{RAW}/argoproj/argo-cd/v3.5.3/manifests/install.yaml"], "gitops"),
    "flux2": ("v2.9.5", [f"{GH}/fluxcd/flux2/releases/download/v2.9.5/install.yaml"], "gitops"),
    "cert-manager": ("v1.21.2", [f"{GH}/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml"],
                     "security"),
    "sealed-secrets": ("v0.40.0", [f"{GH}/bitnami-labs/sealed-secrets/releases/download/v0.40.0/controller.yaml"],
                       "security"),
    "kyverno": ("v1.19.1", [f"{GH}/kyverno/kyverno/releases/download/v1.19.1/install.yaml"], "policy"),
    "gatekeeper": ("v3.23.1", [f"{RAW}/open-policy-agent/gatekeeper/v3.23.1/deploy/gatekeeper.yaml"], "policy"),
    "ingress-nginx": ("controller-v1.15.1", [
        f"{RAW}/kubernetes/ingress-nginx/controller-v1.15.1/deploy/static/provider/cloud/deploy.yaml"], "networking"),
    "metallb": ("v0.16.0", [f"{RAW}/metallb/metallb/v0.16.0/config/manifests/metallb-native.yaml"], "networking"),
    "calico": ("v3.32.2", [f"{RAW}/projectcalico/calico/v3.32.2/manifests/calico.yaml"], "networking"),
    "flannel": ("v0.28.9", [f"{GH}/flannel-io/flannel/releases/download/v0.28.9/kube-flannel.yml"], "networking"),
    "metrics-server": ("v0.9.0", [f"{GH}/kubernetes-sigs/metrics-server/releases/download/v0.9.0/components.yaml"],
                       "observability"),
    "kube-state-metrics": ("v2.20.0", [KSM + f for f in (
        "cluster-role-binding.yaml", "cluster-role.yaml", "deployment.yaml", "service-account.yaml",
        "service.yaml")], "observability"),
    "prometheus-operator": ("v0.94.1", [
        f"{GH}/prometheus-operator/prometheus-operator/releases/download/v0.94.1/bundle.yaml"], "observability"),
    "kubernetes-dashboard": ("v2.7.0", [
        f"{RAW}/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml"], "observability"),
    "longhorn": ("v1.12.1", [f"{GH}/longhorn/longhorn/releases/download/v1.12.1/longhorn.yaml"], "storage"),
    "local-path-provisioner": ("v0.0.37", [
        f"{RAW}/rancher/local-path-provisioner/v0.0.37/deploy/local-path-storage.yaml"], "storage"),
    "cloudnative-pg": ("v1.30.1", [f"{GH}/cloudnative-pg/cloudnative-pg/releases/download/v1.30.1/cnpg-1.30.1.yaml"],
                       "database"),
    "keda": ("v2.21.0", [f"{GH}/kedacore/keda/releases/download/v2.21.0/keda-2.21.0-core.yaml"], "autoscaling"),
    "knative-serving": ("v1.23.0", [
        f"{GH}/knative/serving/releases/download/knative-v1.23.0/serving-core.yaml"], "serverless"),
    "tekton-pipelines": ("v1.16.0", [f"{GH}/tektoncd/pipeline/releases/download/v1.16.0/release.yaml"], "ci-cd"),
    "online-boutique": ("v0.10.7", [
        f"{RAW}/GoogleCloudPlatform/microservices-demo/v0.10.7/release/kubernetes-manifests.yaml"], "demo-app"),
}


def main() -> None:
    out = data_dir() / "manifests"
    index = {}
    for name, (ver, urls, cat) in MANIFESTS.items():
        files = []
        for _i, u in enumerate(urls):
            fn = u.rsplit("/", 1)[-1] if len(urls) > 1 else f"{name}-{ver}.yaml"
            p = fetch(u, out / name / fn, key=f"manifests/{name}/{fn}")
            files.append(str(p.relative_to(out)))
        index[name] = {"version": ver, "category": cat, "files": files, "urls": urls}
    (out / "index.json").write_text(json.dumps(index, indent=2))
    print(f"{len(index)} projects under {out}")


if __name__ == "__main__":
    main()
