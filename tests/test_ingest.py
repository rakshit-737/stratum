import json

from stratum.detect import legacy_rule_detect, rule_detect
from stratum.ingest import runtime_inventory, tetragon_events, trivy_report

NGINX = "sha256:0d17b565c37bcbd895e9d92315a05c1c3c9a29f762b011a10c54a66cd53c9b31"


def _events(fix):
    return tetragon_events(sorted((fix / "tetragon").glob("*.json")))


def test_tetragon_parse(fix):
    evs = _events(fix)
    assert all(e.kind for e in evs)                      # exit events dropped
    ns = next(e for e in evs if e.process.endswith("nsenter"))
    assert ns.pod == "privileged-pod" and ns.privileged and ns.image_digest == NGINX
    conn = next(e for e in evs if e.source == "merlin-agent-go-connect.json")
    assert (conn.kind, conn.dest_ip, conn.dest_port) == ("connect", "34.116.205.187", 443)
    assert conn.pod.startswith("ctr:")
    kp = next(e for e in evs if e.source == "cat_process_kprobe.json")
    assert kp.kind == "open" and kp.path.endswith("elasticsearch.keystore")


def test_rules_on_real_events(fix):
    evs = {e.source: e for e in _events(fix)}
    assert rule_detect(evs["privileged-pod-nsenter.json"]).rule == "R-ESCAPE"
    assert rule_detect(evs["merlin-agent-go-start.json"]).control_id == "ZT-PROV-01"
    assert rule_detect(evs["nc_process_connect.json"]).rule == "R-EGRESS"
    assert rule_detect(evs["cat_process_kprobe.json"]).rule == "R-CRED-READ"
    assert legacy_rule_detect(evs["privileged-pod-nsenter.json"]) is None   # v0.1 misses the escape


def test_runtime_inventory(fix):
    wl, imgs = runtime_inventory(_events(fix))
    pp = next(w for w in wl if w.name == "privileged-pod")
    assert pp.privileged and pp.image_digest.endswith("@" + NGINX)
    assert not any(w.namespace == "" for w in wl)
    assert any(i.digest == pp.image_digest for i in imgs)


def test_trivy_report_parse():
    doc = {"ArtifactName": "ghcr.io/o/r:1", "Metadata": {
        "OS": {"Family": "debian", "Name": "12.11"}, "RepoDigests": ["ghcr.io/o/r@sha256:ab"],
        "ImageConfig": {"config": {"Labels": {"org.opencontainers.image.source": "https://github.com/o/r",
                                              "org.opencontainers.image.revision": "a" * 40}}}},
        "Results": [{"Class": "os-pkgs", "Packages": [{"Name": "bash"}, {"Name": "libc6"}],
                     "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "libc6", "Severity": "CRITICAL"},
                                         {"VulnerabilityID": "CVE-1", "PkgName": "libc6", "Severity": "CRITICAL"},
                                         {"VulnerabilityID": "CVE-2", "PkgName": "bash", "Severity": "LOW"}]}]}
    r = trivy_report(json.loads(json.dumps(doc)), kev={"CVE-1"})
    assert r.os == "debian 12.11" and r.digest == "sha256:ab" and r.packages == 2
    assert r.vulns == {"CRITICAL": 1, "LOW": 1} and r.kev == ["CVE-1"] and r.shells == ["bash"]
    assert r.source_repo == "o/r" and r.revision == "a" * 40
