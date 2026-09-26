from stratum.graph import build_graph
from stratum.k8s import collect, collect_files, load_docs, pod_template
from stratum.policy import evaluate


def test_collect_real_manifests(fix):
    ds = collect_files([fix / "manifests" / "metrics-server.yaml"], source="metrics-server", default_ns="x")
    [w] = ds.workloads
    assert (w.namespace, w.name, w.kind) == ("kube-system", "metrics-server", "Deployment")
    assert w.image_digest.startswith("registry.k8s.io/metrics-server/metrics-server:")
    assert w.pss_level == "restricted" and w.service_account == "metrics-server"
    assert any(n.name == "kube-system" for n in ds.namespaces)


def test_local_path_provisioner_findings(fix):
    ds = collect_files([fix / "manifests" / "local-path-provisioner.yaml"], default_ns="lpp")
    fs = {(f.control_id, f.subject) for f in evaluate(ds, build_graph(ds))}
    wid = "workload:local-path-storage/local-path-provisioner"
    assert ("ZT-NET-01", "ns:local-path-storage") in fs
    assert ("ZT-PROV-03", wid) in fs          # image referenced by tag
    assert ("ZT-WL-02", wid) in fs            # not PSS restricted


def test_rbac_cluster_admin_and_secret_read():
    docs = [
        {"kind": "ServiceAccount", "metadata": {"name": "op", "namespace": "a"}},
        {"kind": "ClusterRoleBinding", "metadata": {"name": "b"},
         "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
         "subjects": [{"kind": "ServiceAccount", "name": "op", "namespace": "a"}]},
        {"kind": "ClusterRole", "metadata": {"name": "reader"},
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}]},
        {"kind": "ClusterRoleBinding", "metadata": {"name": "c"}, "roleRef": {"kind": "ClusterRole", "name": "reader"},
         "subjects": [{"kind": "ServiceAccount", "name": "rd", "namespace": "a"}]},
        {"kind": "Deployment", "metadata": {"name": "d", "namespace": "a"},
         "spec": {"template": {"spec": {"serviceAccountName": "rd",
                                        "containers": [{"name": "c", "image": "i@sha256:1"}]}}}},
    ]
    ds = collect(docs)
    sas = {s.name: s for s in ds.service_accounts}
    assert sas["op"].cluster_admin and "secrets read cluster-wide" in sas["rd"].rbac_risks
    ids = {f.control_id for f in evaluate(ds, build_graph(ds))}
    assert {"ZT-ID-04", "ZT-ID-02"} <= ids and "ZT-PROV-03" not in ids


def test_pod_template_kinds():
    cj = {"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": {"spec": {"containers": []}}}}}}
    assert pod_template(cj) == {"metadata": {}, "spec": {"containers": []}}
    assert pod_template({"kind": "Service", "spec": {}}) is None


def test_list_kind_and_value_tag(tmp_path):
    p = tmp_path / "l.yaml"
    p.write_text("kind: List\nitems:\n- kind: Namespace\n  metadata: {name: n1}\n---\nx: !!value =\n")
    docs = load_docs([p])
    assert docs[0]["kind"] == "Namespace" and docs[1] == {"x": "="}
