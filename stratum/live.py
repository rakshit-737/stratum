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

# packaged replay of one live.yml job (``stratum serve --source live`` and the /demo-live/ console)
LIVE_REPLAY = Path(__file__).resolve().parent / "data" / "live"

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


def replay_dataset(root: Path = LIVE_REPLAY) -> Dataset:
    """Dataset of the packaged live replay: manifests, pods, Tetragon events and the cosign certificate."""
    from .sigstore import parse_cosign_verify
    return build_dataset([root / "workloads.yaml"], root / "pods.json", [root / "tetragon-events.json"],
                         signatures=parse_cosign_verify(root / "cosign-verify.json"))


def replay_info(root: Path = LIVE_REPLAY) -> dict:
    """Which CI run and commit the packaged replay comes from."""
    try:
        return json.loads((root / "source.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def check(ds: Dataset, *, namespace: str, workload: str, image_digest: str, commit: str,
          gatekeeper: dict | None = None, cosign_ok: bool | None = None, drift: str | None = None,
          prevention: dict | None = None, forged: str | None = None, expect_build: str | None = None,
          signatures: list[SignedImage] | None = None, sink: str | None = "sink") -> dict:
    """Assert on the joined evidence. ``commit`` is only the expected value (``github.sha``).

    ``signatures`` (the parsed ``cosign verify`` output) are recorded so the aggregate can count distinct
    certificates; ``sink`` is the benign workload whose detections are counted as false positives.
    """
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
    # the certificate(s) whose digest is the running demo image: the evidence the commit hop was read from
    res["certificates_on_target"] = [sig.certificate() for sig in signatures or []
                                     if sig.digest in res["target_image_digests"]]
    res["sink_incidents"] = sum(i.detection.event.pod.startswith(sink + "-") for i in incs) if sink else None
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
    """Markdown summary of one live run's check result."""
    lines = [
        "### Live kind + Tetragon run (GitHub Actions)", "",
        "| Check | Result |", "|---|---|",
        f"| Tetragon events (total / demo namespace) | {r['events_total']} / {r['events_in_namespace']} ({_kv(r['event_kinds'])}) |",
        f"| Rules raised on the demo pod | {', '.join(r['rules_on_target']) or '-'} |",
        f"| Incidents traced to the expected commit (commit read from the cosign certificate) | "
        f"{r['traced_to_commit']}/{r['incidents_on_target']} |",
        f"| Detections on the benign sink pod | {sink_incidents(r)} |",
    ]
    for c in r.get("certificates_on_target") or []:
        lines.append(f"| Certificate the commit hop was read from (serial / Rekor logIndex / CI run) | "
                     f"`{(c.get('cert_serial') or '?')[:16]}` / {c.get('rekor_log_index')} / "
                     f"{c.get('run_id')} attempt {c.get('run_attempt')} |")
    for key, what in (("drift", "unsigned upstream image"), ("forged", "unsigned image with the right revision label")):
        if r.get(key):
            d = r[key]
            lines.append(f"| Negative control `{d['workload']}` ({what}): incidents traced to a commit | "
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
    if r.get("ablation"):
        lines += ["", "| Arm | Incident -> workload | Incident -> right commit | Control wrongly traced | Gap named |",
                  "|---|---|---|---|---|"]
        for arm, v in r["ablation"].items():
            lines.append(f"| {arm} | {_yn(v['workload_attributed'])} | {_yn(v['traced'])} | "
                         f"{_yn(v['false_attribution'])} | {_yn(v['prov_named'])} |")
    return "\n".join(lines)


def _yn(b: bool) -> str:
    return "yes" if b else "no"


def sink_incidents(r: dict) -> int:
    """Detections on the benign sink pod of one run (older results: other pods minus the negative controls)."""
    if r.get("sink_incidents") is not None:
        return r["sink_incidents"]
    return r["incidents_other_pods_in_namespace"] - sum((r.get(k) or {}).get("incidents", 0) for k in ("drift", "forged"))


def aggregate(runs: list[dict], run_url: str | list[str] = "") -> dict:
    """Combine several live runs (separate kind clusters on separate runners) into counts and Wilson 95% CIs.

    A run-level CI on the trace-to-commit, "every assertion" and cosign rows is given only when every run
    read the commit hop from its own certificate over its own image digest (``per_run_signed``); otherwise
    the trace outcome was decided once for all runs and only the count is reported. The CI run ids named by
    the certificates are reported separately: the jobs of one workflow run share one run id by design.
    """
    from .bench.metrics import wilson
    n = len(runs)
    urls = [u for u in ([run_url] if isinstance(run_url, str) else list(run_url)) if u]
    certs = [c for r in runs for c in r.get("certificates_on_target") or []]
    out = {"runs": n, "passed": sum(bool(r.get("passed")) for r in runs),
           "run_url": urls[0] if len(urls) == 1 else "", "source_runs": urls,
           "rule_capture": {}, "incidents_on_target": sum(r["incidents_on_target"] for r in runs),
           "traced_to_commit": sum(r["traced_to_commit"] for r in runs),
           "runs_fully_traced": sum(r["incidents_on_target"] > 0 and r["traced_to_commit"] == r["incidents_on_target"]
                                    for r in runs),
           "commit_head_sha": (runs[0].get("example_chain") or [""])[-1].removeprefix("commit:") if runs else "",
           "sink_detections": sum(sink_incidents(r) for r in runs),
           "distinct_certificates": sorted({c["cert_sha256"] for c in certs if c.get("cert_sha256")}),
           "distinct_certificate_run_ids": sorted({b for r in runs for b in r.get("builds_on_target", [])}),
           "distinct_digests": sorted({x for r in runs for x in r.get("target_image_digests", [])})}
    out["per_run_signed"] = (bool(n) and all(len(r.get("certificates_on_target") or []) == 1 for r in runs)
                             and len(out["distinct_certificates"]) == len(out["distinct_digests"]) == n)
    if not out["per_run_signed"]:
        out["no_trace_ci_reason"] = (f"{len(out['distinct_certificates'])} distinct certificate(s) over "
                                     f"{len(out['distinct_digests'])} distinct digest(s) for {n} runs")
    out["traced_runs_ci95"] = wilson(out["runs_fully_traced"], n) if out["per_run_signed"] else None
    out["passed_ci95"] = wilson(out["passed"], n) if out["per_run_signed"] else None
    for rule in EXPECTED:
        k = sum(rule in r["rules_on_target"] for r in runs)
        out["rule_capture"][rule] = {"runs": k, "ci95": wilson(k, n) if n else None}
    for key in ("drift", "forged"):
        d = [r[key] for r in runs if r.get(key)]
        named = sum("ZT-PROV-01" in x["failed_controls"] for x in d)
        out[key] = {"incidents": sum(x["incidents"] for x in d),
                    "traced_to_any_commit": sum(x["traced_to_any_commit"] for x in d),
                    "runs_with_none_traced": sum(x["incidents"] > 0 and x["traced_to_any_commit"] == 0 for x in d),
                    "zt_prov_01_named": named, "runs": len(d),
                    "zt_prov_01_ci95": wilson(named, len(d)) if d else None}
    p = [r["prevention"]["observed"] for r in runs if r.get("prevention")]
    both = sum(x.get("before") is True and x.get("after") is False for x in p)
    kept = sum(x.get("in_cluster_after") is True for x in p)
    out["prevention"] = {"runs": len(p), "blocked_after": sum(x.get("after") is False for x in p),
                         "allowed_before": sum(x.get("before") is True for x in p), "allowed_before_blocked_after": both,
                         "in_cluster_kept": kept, "ci95": wilson(both, len(p)) if p else None,
                         "in_cluster_ci95": wilson(kept, len(p)) if p else None}
    out["gatekeeper_denied"] = sum(bool((r.get("gatekeeper") or {}).get("privileged_denied")) for r in runs)
    out["gatekeeper_ci95"] = wilson(out["gatekeeper_denied"], n) if n else None
    out["cosign_verified"] = sum(r.get("cosign_verified") is True for r in runs)
    out["cosign_ci95"] = wilson(out["cosign_verified"], n) if out["per_run_signed"] else None
    out["example_chain"] = runs[0]["example_chain"] if runs else []
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

    def _j(r: dict, key: str) -> str:
        return ", ".join(str(c.get(key)) for c in r.get("certificates_on_target") or [])
    out["per_run_summary"] = [{
        "run": r.get("artifact") or str(i + 1), "digest": ", ".join(r.get("target_image_digests", [])),
        "cert_sha256": _j(r, "cert_sha256"), "cert_serial": _j(r, "cert_serial"),
        "rekor_log_index": _j(r, "rekor_log_index"), "certificate_run_id": ", ".join(r.get("builds_on_target", [])),
        "run_attempt": _j(r, "run_attempt"), "incidents": r["incidents_on_target"], "traced": r["traced_to_commit"],
        "passed": bool(r.get("passed")),
    } for i, r in enumerate(runs)]
    out["per_run"] = runs
    return out


def aggregate_markdown(a: dict) -> str:
    """Markdown report for :func:`aggregate` output (results/live.md is written only from this)."""
    n = a["runs"]

    def ci(c):
        return f"[{c[0]:.2f}, {c[1]:.2f}]" if c else "-"
    nc, nd = len(a.get("distinct_certificates", [])), len(a.get("distinct_digests", []))
    run_ids = a.get("distinct_certificate_run_ids", [])
    signed = a.get("per_run_signed")
    rows = [f"### Live kind + Tetragon: {n} runs (one kind cluster per runner)", ""]
    if signed:
        rows += [f"Each run built its own demo image (a per-run nonce makes the digest unique), signed it keyless in "
                 f"its own job and read the commit hop from that job's Fulcio certificate: **{nc} distinct "
                 f"certificates over {nd} distinct image digests**. The certificates name CI run "
                 f"{', '.join(run_ids) or '-'} ({len(run_ids)} workflow run(s); the jobs of one workflow run share its "
                 "run id by design). Every image was built from the same commit, so the commit itself is one value: "
                 "the run-level CIs cover detection, capture and the certificate join, not commit diversity.", ""]
    else:
        rows += [f"The {n} runs read the commit hop from {nc} distinct certificate(s) over {nd} distinct "
                 f"digest(s), so the trace outcome was not decided independently per run: the trace rows give "
                 "counts only, with no run-level CI.", ""]
    why = "-" if signed else "- (shared certificate)"
    pv, dr, fg = a["prevention"], a["drift"], a.get("forged") or {}
    rows += ["| Check | Result | Wilson 95% CI |", "|---|---:|---:|",
             f"| Runs passing every assertion | {a['passed']}/{n} | {ci(a.get('passed_ci95')) if signed else why} |"]
    for rule, v in a["rule_capture"].items():
        rows.append(f"| {rule} raised for its scripted action ({EXPECTED[rule]}) | {v['runs']}/{n} | {ci(v['ci95'])} |")
    rows += [
        f"| Runs whose demo-pod incidents all trace to the expected commit (read from the run's own certificate) | "
        f"{a['runs_fully_traced']}/{n} | {ci(a.get('traced_runs_ci95')) if signed else why} |",
        f"| Demo-pod incidents traced (count only; the incidents of one run share its certificate, so no CI) | "
        f"{a['traced_to_commit']}/{a['incidents_on_target']} | - |",
        f"| Detections on the benign sink pod (count) | {a['sink_detections']} | - |",
        f"| Unsigned upstream `drift` image: incidents traced to any commit (count, want 0) | "
        f"{dr['traced_to_any_commit']}/{dr['incidents']} | - |",
        f"| `drift` incidents name ZT-PROV-01 | {dr['zt_prov_01_named']}/{dr['runs']} runs | {ci(dr.get('zt_prov_01_ci95'))} |",
        *([f"| Unsigned `forged` image with the right revision label: incidents traced to any commit (count, want 0) | "
           f"{fg['traced_to_any_commit']}/{fg['incidents']} | - |",
           f"| `forged` incidents name ZT-PROV-01 | {fg['zt_prov_01_named']}/{fg['runs']} runs | {ci(fg.get('zt_prov_01_ci95'))} |"]
          if fg.get("runs") else []),
        f"| External egress allowed before, blocked after the `stratum prevent` policy | "
        f"{pv.get('allowed_before_blocked_after', min(pv['allowed_before'], pv['blocked_after']))}/{pv['runs']} | "
        f"{ci(pv.get('ci95'))} |",
        f"| In-cluster sink still reachable after the policy | {pv['in_cluster_kept']}/{pv['runs']} | {ci(pv.get('in_cluster_ci95'))} |",
        f"| Gatekeeper denied the privileged pod | {a['gatekeeper_denied']}/{n} | {ci(a.get('gatekeeper_ci95'))} |",
        f"| cosign keyless verify (right identity passes, wrong identity fails) | {a['cosign_verified']}/{n} | "
        f"{ci(a.get('cosign_ci95')) if signed else why} |",
        "", f"Example trace: `{' -> '.join(a['example_chain'])}`", ""]
    if a.get("per_run_summary"):
        rows += ["#### Per run: image digest and the certificate the commit hop was read from", "",
                 "| Run | Image digest | Certificate serial | Rekor logIndex | Certificate SHA-256 | CI run (attempt) | Traced |",
                 "|---|---|---|---:|---|---|---:|"]
        for x in a["per_run_summary"]:
            rows.append(f"| {x['run']} | `{x['digest'][:19]}…` | `{x['cert_serial'][:16]}…` | {x['rekor_log_index']} | "
                        f"`{x['cert_sha256'][:16]}…` | {x['certificate_run_id']} ({x['run_attempt']}) | "
                        f"{x['traced']}/{x['incidents']} |")
        rows.append("")
    if a.get("ablation"):
        m = next(iter(a["ablation"].values()))["runs"]
        rows += ["#### Ablation: what each join edge adds (constructed controls, k/n runs)", "",
                 "Each arm re-joins the same run's evidence with less (or looser) provenance. The negative controls "
                 "are built so that the arms must differ: `forged` carries the right revision label and lives in the "
                 "same repository as the signed image, so label provenance (A2) and a repository join (A4) attribute "
                 "it to the commit by construction. The table shows that the join semantics hold on real sensor "
                 "output in every run; it does not estimate a rate, and the Wilson intervals only bound the "
                 f"pipeline's repeatability over {m} runs.", "",
                 "| Arm | Evidence | Incident -> workload | Incident -> right commit | "
                 "Negative control wrongly traced | Provenance gap named |", "|---|---|---:|---:|---:|---:|"]
        for arm, desc in ARMS.items():
            v = a["ablation"][arm]

            def c(k, v=v):
                return f"{v[k]['k']}/{v['runs']} {ci(v[k]['ci95'])}"
            rows.append(f"| {arm} | {desc} | {c('workload_attributed')} | {c('traced')} | "
                        f"{c('false_attribution')} | {c('prov_named')} |")
        rows += ["", "A2 (label provenance: the OCI revision label that image scanners and SBOM tools read) is the "
                 "realistic baseline; A4 ablates digest-exactness and is not a competing tool.", ""]
    sha = a.get("commit_head_sha", "")
    rows.append(f"Code, images and certificates: commit `{sha[:7]}`" + (" (every certificate names it)." if signed else "."))
    for u in a.get("source_runs") or ([a["run_url"]] if a.get("run_url") else []):
        rows.append(f"Run: {u}")
    return "\n".join(rows)
