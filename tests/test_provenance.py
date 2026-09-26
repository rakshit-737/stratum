from stratum.graph import build_graph
from stratum.k8s import collect
from stratum.models import ImageReport
from stratum.policy import evaluate
from stratum.provenance import Provenance, to_dataset
from stratum.registry import github_repo, parse_ref, revision


def test_parse_ref():
    assert parse_ref("nginx").display == "docker.io/library/nginx:latest"
    r = parse_ref("ghcr.io/o/r/sub:v1@sha256:abc")
    assert (r.registry, r.repo, r.tag, r.digest) == ("ghcr.io", "o/r/sub", "v1", "sha256:abc")
    assert parse_ref("localhost:5000/x:1").registry == "localhost:5000"
    assert parse_ref("bitnami/redis:7").repo == "bitnami/redis"


def test_label_helpers():
    assert github_repo({"org.opencontainers.image.source": "https://github.com/fluxcd/flux2.git"}) == "fluxcd/flux2"
    assert github_repo({"org.opencontainers.image.url": "https://example.com"}) == ""
    assert revision({"org.opencontainers.image.revision": "0123abc"}) == "0123abc"
    assert revision({"org.opencontainers.image.revision": "main"}) == ""


def test_trace_real_shape_to_commit():
    ref = "ghcr.io/acme/app:v1"
    docs = [{"kind": "Deployment", "metadata": {"name": "app", "namespace": "prod"},
             "spec": {"template": {"spec": {"serviceAccountName": "app",
                                            "containers": [{"name": "c", "image": ref}]}}}}]
    ds = collect(docs)
    prov = Provenance(ref, {"digest": "sha256:" + "1" * 64, "signed": False}, "acme/app", "f" * 40,
                      {"verified": True, "sha": "f" * 40, "author": "alice", "message": "fix", "pr": 7})
    rep = ImageReport(ref, os="alpine 3.20.1", critical=["CVE-X"], kev=["CVE-X"], shells=["busybox"])
    ds.merge(to_dataset([prov], [rep]))
    g = build_graph(ds)
    chain = g.trace_upstream("pod:prod/app-0")
    assert [c.split(":")[0] for c in chain] == ["pod", "workload", "image", "build", "commit"]
    assert g.nodes[chain[-1]]["author"] == "alice"
    assert g.blast_radius("base:alpine 3.20.1") == ["workload:prod/app"]
    ids = {f.control_id for f in evaluate(ds, g)}
    assert {"ZT-PROV-02", "ZT-IMG-01", "ZT-IMG-03", "ZT-IMG-02", "ZT-PROV-03"} <= ids
    assert "ZT-PROV-01" not in ids
