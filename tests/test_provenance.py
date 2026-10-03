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


GHCR_FALLBACK_INDEX = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
    {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "5d" * 32,
     "artifactType": "application/vnd.oci.empty.v1+json"}]}
# the referrer manifest cosign v3 `sign` pushed for ghcr.io/rakshit-737/stratum:1.1.0 (trimmed)
COSIGN_V3_SIGNATURE = {"artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                       "annotations": {"dev.sigstore.bundle.content": "dsse-envelope",
                                       "dev.sigstore.bundle.predicateType": "https://sigstore.dev/cosign/sign/v1"}}


def test_classify_referrers():
    from stratum.registry import classify_referrers
    # the fallback-tag index leaves artifactType empty: the referrer manifest itself is read
    assert classify_referrers(GHCR_FALLBACK_INDEX, lambda d: COSIGN_V3_SIGNATURE) == ("sigstore-bundle", "")
    assert classify_referrers(GHCR_FALLBACK_INDEX) == ("", "")
    slsa = {"manifests": [{"artifactType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                           "annotations": {"dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v1"}}]}
    assert classify_referrers(slsa) == ("", "sigstore-bundle")
    assert classify_referrers({"manifests": [{"artifactType": "application/vnd.in-toto+json"},
                                             {"artifactType": "application/vnd.dev.cosign.artifact.sig.v1+json"}]}) \
        == ("cosign-oci11", "in-toto")


def test_signature_artifacts_sees_bundle_without_sig_tag():
    from stratum.registry import Registry, Resolved, parse_ref

    class Fake(Registry):
        def exists(self, ref, tag):
            return tag == "sha256-" + "d8" * 32          # no .sig / .att tag, only the referrers fallback tag

        def _json(self, ref, path, accept=""):
            if path == "manifests/sha256-" + "d8" * 32:
                return GHCR_FALLBACK_INDEX, ""
            if path.startswith("manifests/sha256:5d"):
                return COSIGN_V3_SIGNATURE, ""
            raise ValueError(path)
    idx = {"manifests": [{"annotations": {"vnd.docker.reference.type": "attestation-manifest"}}]}
    r = Fake().signature_artifacts(parse_ref("ghcr.io/o/r:1"), Resolved("x", index_digest="sha256:" + "d8" * 32), idx)
    assert (r.signed, r.signature_format, r.attested, r.buildkit_attestation) == (True, "sigstore-bundle", False, True)
