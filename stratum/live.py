"""Live-cluster check: real Tetragon events from a kind cluster -> STRATUM detection + trace-to-commit.

Used by ``.github/workflows/live.yml``. The workflow builds a demo image, pushes it to GHCR, signs it with
cosign (keyless, GitHub OIDC), deploys it to kind with Tetragon and Gatekeeper, runs scripted
attack-shaped actions inside the pod and exports Tetragon's JSON. This module joins that evidence into
one :class:`Dataset` (manifests + the CI build that produced the image + the live events), runs the
normal analysis, and asserts on the result.
"""
from __future__ import annotations

import json
from pathlib import Path

from .dataset import Dataset
from .incident import analyze
from .ingest import tetragon_events
from .k8s import collect_files
from .models import Build, Commit, Image
from .sigstore import SignedImage

# rule -> what the scripted action inside the pod was
EXPECTED = {"R-SHELL": "kubectl exec ... sh", "R-SA-TOKEN": "cat the projected SA token",
            "R-NETTOOL": "nc to the in-cluster sink"}


def _owner_workload(pod: dict) -> str | None:
    refs = (pod.get("metadata") or {}).get("ownerReferences") or []
    if not refs:
        return None
    name = refs[0].get("name", "")
    return name.rsplit("-", 1)[0] if refs[0].get("kind") == "ReplicaSet" else name


def _repo(ref: str) -> str:
    """Repository part of an image reference (drops ``@digest`` and a ``:tag`` on the last segment)."""
    ref = ref.split("@")[0]
    head, _, last = ref.rpartition("/")
    return (head + "/" if head else "") + last.split(":")[0]


def label_signatures(labels: dict[str, str], repository_of: dict[str, str] | None = None) -> list[SignedImage]:
    """Unverified provenance from the OCI ``org.opencontainers.image.revision`` label ({digest: revision}).

    Anyone who can build an image can set this label, so it is the ablation's "label provenance" arm.
    """
    repository_of = repository_of or {}
    return [SignedImage(d, repository_of.get(d, ""), rev, "", "", "", None, None)
            for d, rev in sorted(labels.items()) if rev]


def build_dataset(manifests: list[str | Path], pods_json: str | Path, events: list[str | Path], *,
                  signatures: list[SignedImage], author: str = "", signed: bool = True,
                  match: str = "digest") -> Dataset:
    """Join manifests, pod state, Tetragon events and verified signatures into one :class:`Dataset`.

    The ``image -> build -> commit`` edges come only from ``signatures`` (parsed from ``cosign verify``):
    a workload whose image digest has no verified signature gets no build, so its incidents cannot
    reach a commit. Nothing about the expected commit is passed in here.

    ``signed`` and ``match`` exist for the ablation only: ``signed=False`` marks the builds as unverified
    (label provenance), and ``match="repository"`` joins a signature to every workload whose image is in
    the same repository instead of requiring the exact digest.
    """
    ds = collect_files(manifests, source="live")
    pods = json.loads(Path(pods_json).read_text(encoding="utf-8")).get("items", [])
    by_wl: dict[tuple[str, str], list[str]] = {}
    for p in pods:
        meta = p.get("metadata") or {}
        wl = _owner_workload(p)
        if wl:
            by_wl.setdefault((meta.get("namespace", ""), wl), []).append(meta.get("name", ""))
    for w in ds.workloads:
        w.pods = sorted(by_wl.get((w.namespace, w.name), w.pods))
    seen: set[str] = set()
    for sig in signatures:
        build = sig.run_id or f"sig-{sig.digest[7:19]}"
        if sig.commit not in {c.sha for c in ds.commits}:
            ds.commits.append(Commit(sig.commit, sig.source_repo, author, f"signed by {sig.ref}"))
        if build not in {b.id for b in ds.builds}:
            ds.builds.append(Build(build, sig.commit, "github-actions", signed=signed))
        for w in ds.workloads:
            hit = (w.image_digest.endswith("@" + sig.digest) if match == "digest"
                   else _repo(w.image_digest) == sig.repository)
            if hit and w.image_digest not in seen:
                seen.add(w.image_digest)
                ds.images.append(Image(w.image_digest, w.image_digest, build))
    ds.events = tetragon_events(events)
    return ds


def check(ds: Dataset, *, namespace: str, workload: str, image_digest: str, commit: str,
          gatekeeper: dict | None = None, cosign_ok: bool | None = None, drift: str | None = None,
          prevention: dict | None = None, forged: str | None = None, expect_build: str | None = None) -> dict:
    """Assert on the joined evidence. ``commit`` is only the expected value (``github.sha``)."""
    a = analyze(ds, deny_bases=())
    ns_events = [e for e in ds.events if e.namespace == namespace]
    target = [e for e in ns_events if e.pod.startswith(workload + "-")]
    incs = [i for i in a.incidents if i.detection.event.namespace == namespace]
    on_target = [i for i in incs if i.detection.event.pod.startswith(workload + "-")]
    rules = sorted({i.detection.rule for i in on_target})
    kinds: dict[str, int] = {}
    for e in ns_events:
        kinds[e.kind] = kinds.get(e.kind, 0) + 1
    res = {
        "events_total": len(ds.events), "events_in_namespace": len(ns_events), "event_kinds": kinds,
        "events_on_target": len(target),
        "target_image_digests": sorted({e.image_digest for e in target if e.image_digest}),
        "connects_on_target": sorted({f"{e.dest_ip}:{e.dest_port}" for e in target if e.kind == "connect"}),
        "rules_on_target": rules,
        "incidents_on_target": len(on_target),
        "incidents_other_pods_in_namespace": len(incs) - len(on_target),
        "traced_to_commit": sum(i.root_commit == commit for i in on_target),
        "example_chain": on_target[0].chain if on_target else [],
        "failed_controls": sorted({f.control_id for i in on_target for f in i.failed_controls}),
        "gatekeeper": gatekeeper or {}, "cosign_verified": cosign_ok,
        "commit_source": "cosign certificate (OID 1.3.6.1.4.1.57264.1.3)",
    }
    builds = sorted({c.removeprefix("build:") for i in on_target for c in i.chain if c.startswith("build:")})
    res["builds_on_target"] = builds
    for key, name in (("drift", drift), ("forged", forged)):
        if name:
            d_incs = [i for i in incs if i.detection.event.pod.startswith(name + "-")]
            res[key] = {"workload": name, "incidents": len(d_incs),
                        "traced_to_any_commit": sum(i.root_commit is not None for i in d_incs),
                        "failed_controls": sorted({f.control_id for i in d_incs for f in i.failed_controls})}
    fails = []
    for rule, action in EXPECTED.items():
        if rule not in rules:
            fails.append(f"{rule} not raised ({action})")
    if not on_target or res["traced_to_commit"] != len(on_target):
        fails.append(f"trace-to-commit {res['traced_to_commit']}/{len(on_target)}")
    if image_digest and image_digest not in res["target_image_digests"]:
        fails.append(f"running image digest {image_digest} not seen in events {res['target_image_digests']}")
    if not any(c.endswith(":8080") for c in res["connects_on_target"]):
        fails.append("no connect to the sink (:8080) captured")
    if gatekeeper is not None and not (gatekeeper.get("privileged_denied") and gatekeeper.get("demo_admitted")):
        fails.append(f"gatekeeper: {gatekeeper}")
    if prevention is not None:
        from .incident import replay_with_policy
        pred = replay_with_policy(ds, namespace)
        pred.pop("policy_yaml", None)
        res["prevention"] = {"observed": prevention, "predicted_by_replay": pred}
        if not (prevention.get("before") is True and prevention.get("after") is False
                and prevention.get("in_cluster_after") is True):
            fails.append(f"prevention: {prevention}")
    for key in ("drift", "forged"):
        d = res.get(key)
        if not d:
            continue
        name = d["workload"]
        if not d["incidents"]:
            fails.append(f"negative control: no incident on unsigned workload {name}")
        if d["traced_to_any_commit"]:
            fails.append(f"negative control: unsigned workload {name} traced to a commit")
        if "ZT-PROV-01" not in d["failed_controls"]:
            fails.append(f"negative control: ZT-PROV-01 not named for {name}")
    if expect_build and builds != [expect_build]:
        fails.append(f"certificate run {builds} is not this CI run {expect_build}")
    if cosign_ok is False:
        fails.append("cosign verify failed")
    res["failures"] = fails
    res["passed"] = not fails
    return res


ARMS = {
    "A0": "runtime events only (Tetragon)",
    "A1": "+ cluster state (manifests, pods): pod -> workload -> image digest",
    "A2": "+ label provenance (OCI revision label, unverified)",
    "A3": "+ certificate provenance (cosign/Fulcio, digest-exact): STRATUM",
    "A4": "certificate provenance joined by repository instead of digest",
}


def ablation(manifests, pods_json, events, *, signatures: list[SignedImage], labels: dict[str, str],
             commit: str, namespace: str = "stratum-live", workload: str = "web",
             controls: tuple[str, ...] = ("drift", "forged")) -> dict:
    """Score each join arm on one run's evidence.

    Per arm: did every target incident reach the expected commit (``traced``), did any incident of the
    negative-control workloads (``controls``: an unsigned upstream image and an unsigned image that
    carries the *right* revision label) reach a commit (``false_attribution``), and was a provenance
    control named for every control workload (``prov_named``).
    """
    from .ingest import tetragon_events as _te
    repos = {s.digest: s.repository for s in signatures}
    arms: dict[str, Dataset] = {}
    arms["A0"] = Dataset(events=_te(events))
    arms["A1"] = build_dataset(manifests, pods_json, events, signatures=[])
    arms["A2"] = build_dataset(manifests, pods_json, events, signed=False,
                               signatures=label_signatures(labels, repos))
    arms["A3"] = build_dataset(manifests, pods_json, events, signatures=signatures)
    arms["A4"] = build_dataset(manifests, pods_json, events, signatures=signatures, match="repository")
    out = {}
    for arm, ds in arms.items():
        a = analyze(ds, deny_bases=())
        incs = [i for i in a.incidents if i.detection.event.namespace == namespace]
        tgt = [i for i in incs if i.detection.event.pod.startswith(workload + "-")]
        ctl = {c: [i for i in incs if i.detection.event.pod.startswith(c + "-")] for c in controls}
        out[arm] = {
            "target_incidents": len(tgt),
            "workload_attributed": bool(tgt) and all(i.workload for i in tgt),
            "traced": bool(tgt) and all(i.root_commit == commit for i in tgt),
            "false_attribution": any(i.root_commit for v in ctl.values() for i in v),
            "prov_named": all(v and any(f.control_id in ("ZT-PROV-01", "ZT-PROV-02")
                                        for i in v for f in i.failed_controls) for v in ctl.values()),
        }
    return out


def _kv(d: dict) -> str:
    return ", ".join(f"{k} {str(v).lower() if isinstance(v, bool) else v}" for k, v in d.items())


def markdown(r: dict) -> str:
    lines = [
        "### Live kind + Tetragon run (GitHub Actions)", "",
        "| Check | Result |", "|---|---|",
        f"| Tetragon events (total / demo namespace) | {r['events_total']} / {r['events_in_namespace']} ({_kv(r['event_kinds'])}) |",
        f"| Rules raised on the demo pod | {', '.join(r['rules_on_target']) or '-'} |",
        f"| Incidents traced to the expected commit (commit read from the cosign certificate) | "
        f"{r['traced_to_commit']}/{r['incidents_on_target']} |",
        f"| Detections on the sink pod | {r['incidents_other_pods_in_namespace'] - (r.get('drift') or {}).get('incidents', 0)} |",
    ]
    if r.get("drift"):
        d = r["drift"]
        lines.append(f"| Negative control: unsigned `{d['workload']}` incidents traced to a commit | "
                     f"{d['traced_to_any_commit']}/{d['incidents']} (controls: {', '.join(d['failed_controls'])}) |")
    if r.get("prevention"):
        o = r["prevention"]["observed"]
        lines.append(f"| Policy-as-prevention: connect to external sink before / after `stratum prevent` policy | "
                     f"{'allowed' if o.get('before') else 'blocked'} / {'allowed' if o.get('after') else 'blocked'} "
                     f"(in-cluster sink after: {'allowed' if o.get('in_cluster_after') else 'blocked'}) |")
    lines += [f"| Gatekeeper | {_kv(r['gatekeeper'])} |",
              f"| cosign keyless verify | {str(r['cosign_verified']).lower()} |",
              f"| Result | {'PASS' if r['passed'] else 'FAIL: ' + '; '.join(r['failures'])} |", "",
              f"Trace: `{' -> '.join(r['example_chain'])}`"]
    return "\n".join(lines)


def aggregate(runs: list[dict], run_url: str = "") -> dict:
    """Combine several independent live runs (separate kind clusters) into rates with Wilson 95% CIs."""
    from .bench.metrics import wilson
    n = len(runs)
    inc = sum(r["incidents_on_target"] for r in runs)
    traced = sum(r["traced_to_commit"] for r in runs)
    out = {"runs": n, "passed": sum(bool(r.get("passed")) for r in runs), "run_url": run_url,
           "rule_capture": {}, "incidents_on_target": inc, "traced_to_commit": traced,
           # Incidents within one run share one image digest and one Fulcio certificate, so the
           # trace outcome is decided once per run: the CI is over runs, not over clustered incidents.
           "runs_fully_traced": sum(r["incidents_on_target"] > 0 and r["traced_to_commit"] == r["incidents_on_target"]
                                    for r in runs),
           "commit_head_sha": (runs[0].get("example_chain") or [""])[-1].removeprefix("commit:") if runs else "",
           "sink_detections": sum(r["incidents_other_pods_in_namespace"] - (r.get("drift") or {}).get("incidents", 0)
                                  for r in runs)}
    out["traced_runs_ci95"] = wilson(out["runs_fully_traced"], n) if n else None
    for rule in EXPECTED:
        k = sum(rule in r["rules_on_target"] for r in runs)
        out["rule_capture"][rule] = {"runs": k, "ci95": wilson(k, n)}
    d = [r["drift"] for r in runs if r.get("drift")]
    out["drift"] = {"incidents": sum(x["incidents"] for x in d),
                    "traced_to_any_commit": sum(x["traced_to_any_commit"] for x in d),
                    "zt_prov_01_named": sum("ZT-PROV-01" in x["failed_controls"] for x in d), "runs": len(d)}
    p = [r["prevention"]["observed"] for r in runs if r.get("prevention")]
    out["prevention"] = {"runs": len(p), "blocked_after": sum(x.get("after") is False for x in p),
                         "allowed_before": sum(x.get("before") is True for x in p),
                         "in_cluster_kept": sum(x.get("in_cluster_after") is True for x in p)}
    out["gatekeeper_denied"] = sum(bool((r.get("gatekeeper") or {}).get("privileged_denied")) for r in runs)
    out["cosign_verified"] = sum(r.get("cosign_verified") is True for r in runs)
    out["example_chain"] = runs[0]["example_chain"] if runs else []
    out["distinct_builds"] = sorted({b for r in runs for b in r.get("builds_on_target", [])})
    out["distinct_digests"] = sorted({x for r in runs for x in r.get("target_image_digests", [])})
    f = [r["forged"] for r in runs if r.get("forged")]
    out["forged"] = {"incidents": sum(x["incidents"] for x in f),
                     "traced_to_any_commit": sum(x["traced_to_any_commit"] for x in f),
                     "zt_prov_01_named": sum("ZT-PROV-01" in x["failed_controls"] for x in f), "runs": len(f)}
    ab = [r["ablation"] for r in runs if r.get("ablation")]
    out["ablation"] = {}
    if ab:
        m = len(ab)
        for arm in ARMS:
            row = {"runs": m}
            for k in ("workload_attributed", "traced", "false_attribution", "prov_named"):
                c = sum(bool(x[arm][k]) for x in ab)
                row[k] = {"k": c, "ci95": wilson(c, m)}
            out["ablation"][arm] = row
    out["per_run"] = runs
    return out


def aggregate_markdown(a: dict) -> str:
    n = a["runs"]

    def ci(c):
        return f"[{c[0]:.2f}, {c[1]:.2f}]" if c else "-"
    nb, nd = len(a.get("distinct_builds", [])), len(a.get("distinct_digests", []))
    rows = [f"### Live kind + Tetragon: {n} runs (separate kind clusters on separate runners, one workflow run)", "",
            f"Each run builds its own demo image (a per-run nonce label makes the digest unique) and signs it in "
            f"its own job, so the commit hop is read from {nb} distinct Fulcio certificate(s) over {nd} distinct "
            "digest(s). All runs build the same commit, so the commit itself is one value; the run-level CI "
            "covers detection, capture and the certificate join, not commit diversity.", "",
            "| Check | Result | Wilson 95% CI |", "|---|---:|---:|",
            f"| Runs passing every assertion | {a['passed']}/{n} | {ci(wilson_(a['passed'], n))} |"]
    for rule, v in a["rule_capture"].items():
        rows.append(f"| {rule} raised for its scripted action ({EXPECTED[rule]}) | {v['runs']}/{n} | {ci(v['ci95'])} |")
    rows += [
        f"| Runs whose demo-pod incidents all trace to the expected commit (read from the cosign certificate) | "
        f"{a['runs_fully_traced']}/{n} | {ci(a['traced_runs_ci95'])} |",
        f"| Demo-pod incidents traced (count only; clustered by run, so no CI) | "
        f"{a['traced_to_commit']}/{a['incidents_on_target']} | - |",
        f"| Detections on the benign sink pod | {a['sink_detections']} | - |",
        f"| Unsigned `drift` incidents traced to any commit (negative control, want 0) | "
        f"{a['drift']['traced_to_any_commit']}/{a['drift']['incidents']} | - |",
        f"| `drift` incidents name ZT-PROV-01 | {a['drift']['zt_prov_01_named']}/{a['drift']['runs']} runs | - |",
        *([f"| Unsigned `forged` image with the right revision label: incidents traced to any commit (want 0) | "
           f"{a['forged']['traced_to_any_commit']}/{a['forged']['incidents']} | - |",
           f"| `forged` incidents name ZT-PROV-01 | {a['forged']['zt_prov_01_named']}/{a['forged']['runs']} runs | - |"]
          if a.get("forged", {}).get("runs") else []),
        f"| External egress allowed before, blocked after `stratum prevent` policy | "
        f"{min(a['prevention']['allowed_before'], a['prevention']['blocked_after'])}/{a['prevention']['runs']} | - |",
        f"| In-cluster sink still reachable after the policy | {a['prevention']['in_cluster_kept']}/{a['prevention']['runs']} | - |",
        f"| Gatekeeper denied the privileged pod | {a['gatekeeper_denied']}/{n} | - |",
        f"| cosign keyless verify (right identity passes, wrong identity fails) | {a['cosign_verified']}/{n} | - |",
        "", f"Example trace: `{' -> '.join(a['example_chain'])}`", ""]
    if a.get("ablation"):
        rows += ["#### Ablation: what each join edge adds (per run, Wilson 95% CI)", "",
                 "| Arm | Evidence | Incident -> workload | Incident -> right commit | "
                 "Negative control wrongly traced | Provenance gap named |", "|---|---|---:|---:|---:|---:|"]
        for arm, desc in ARMS.items():
            v = a["ablation"][arm]

            def c(k, v=v):
                return f"{v[k]['k']}/{v['runs']} {ci(v[k]['ci95'])}"
            rows.append(f"| {arm} | {desc} | {c('workload_attributed')} | {c('traced')} | "
                        f"{c('false_attribution')} | {c('prov_named')} |")
        rows.append("")
    rows += [
        f"Results were produced at commit `{a.get('commit_head_sha', '')[:7]}` (the commit the demo image was built from); "
        "later commits changed docs and aggregation only unless noted.", ""]
    if a.get("run_url"):
        rows.append(f"Run: {a['run_url']}")
    return "\n".join(rows)


def wilson_(k: int, n: int):
    from .bench.metrics import wilson
    return wilson(k, n) if n else None
