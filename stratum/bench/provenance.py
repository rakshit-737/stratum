"""Provenance coverage: how far can a runtime workload be traced back, on real public images?

Hops measured (registry + GitHub API metadata only):
image tag -> digest -> OCI source/revision labels -> verified GitHub commit -> PR,
plus signature / attestation artefact presence (cosign tags, Sigstore bundles, in-toto referrers).

Baseline for trace-to-commit: the naive "image tag == git tag" heuristic,
scored against the commit embedded in the image (where one exists).
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..corpus import manifests_dataset, provenance_path
from ..provenance import load
from ..registry import parse_ref
from .metrics import wilson

# External reference point: Schorlemmer et al., "Signing in Four Public Software Package Registries"
# (arXiv:2401.14635, Table 6): share of Docker Hub tags signed (Docker Content Trust) in 2023.
DOCKER_HUB_SIGNED_2023 = 0.010


def run(root: Path) -> dict:
    provs = load(provenance_path(root))
    n = len(provs)
    ok = [p for p in provs if not p.resolved.get("error")]
    has_src = [p for p in ok if p.repo]
    has_rev = [p for p in ok if p.revision]
    verified = [p for p in ok if p.commit.get("verified")]
    with_pr = [p for p in verified if p.commit.get("pr")]
    signed = [p for p in ok if p.resolved.get("signed")]
    attested = [p for p in ok if p.resolved.get("attested")]
    buildkit = [p for p in ok if p.resolved.get("buildkit_attestation")]
    fmt = {k: dict(Counter(p.resolved.get(f"{k}_format") or "cosign-tag" for p in ps).most_common())
           for k, ps in (("signature", signed), ("attestation", attested))}
    # tag heuristic vs embedded revision
    comparable = [p for p in verified if "tag_sha" in p.commit]
    agree = [p for p in comparable if p.commit.get("tag_sha") == p.commit["sha"]]
    tag_found = [p for p in comparable if p.commit.get("tag_sha")]
    heur_any = [p for p in ok if p.commit.get("tag_sha")]
    # workloads
    ds = manifests_dataset(root)
    by_ref = {p.ref: p for p in provs}
    wl_traced = sum(bool(by_ref.get(w.image_digest) and by_ref[w.image_digest].commit.get("verified"))
                    for w in ds.workloads)
    wl_pr = sum(bool(by_ref.get(w.image_digest) and by_ref[w.image_digest].commit.get("verified")
                     and by_ref[w.image_digest].commit.get("pr")) for w in ds.workloads)
    # workloads are clustered by project (one chart ships several workloads built by the same pipeline)
    projects = {w.source for w in ds.workloads}
    traced_projects = {w.source for w in ds.workloads
                       if by_ref.get(w.image_digest) and by_ref[w.image_digest].commit.get("verified")}
    registries = Counter(parse_ref(p.ref).registry for p in provs)
    pct = lambda a, b: round(100 * a / b, 1) if b else 0.0  # noqa: E731
    return {
        "images": n, "resolved": len(ok), "registries": dict(registries.most_common()),
        "funnel": {
            "manifest resolved to digest": [len(ok), pct(len(ok), n)],
            "OCI source label -> GitHub repo": [len(has_src), pct(len(has_src), n)],
            "revision (label or source URL)": [len(has_rev), pct(len(has_rev), n)],
            "commit verified on GitHub": [len(verified), pct(len(verified), n)],
            "commit linked to a merged PR": [len(with_pr), pct(len(with_pr), n)],
            "signature artefact (cosign / Sigstore)": [len(signed), pct(len(signed), n)],
            "attestation artefact (cosign / Sigstore / in-toto)": [len(attested), pct(len(attested), n)],
            "BuildKit attestation (unsigned)": [len(buildkit), pct(len(buildkit), n)],
        },
        "artefact_formats": fmt,
        "funnel_wilson95": {"commit verified on GitHub": wilson(len(verified), n),
                            "signature artefact": wilson(len(signed), n)},
        "context": {"docker_hub_tags_signed_2023": DOCKER_HUB_SIGNED_2023,
                    "source": "Schorlemmer et al. 2024, arXiv:2401.14635, Table 6 (DCT signatures; different population)"},
        "workloads": len(ds.workloads), "workloads_traced_to_commit": wl_traced,
        "workloads_traced_to_commit_wilson95": wilson(wl_traced, len(ds.workloads)),
        "workloads_traced_to_pr": wl_pr,
        "projects": len(projects), "projects_with_a_traced_workload": len(traced_projects),
        "projects_traced_wilson95": wilson(len(traced_projects), len(projects)),
        "images_of_traced_workloads": len({w.image_digest for w in ds.workloads if by_ref.get(w.image_digest)
                                           and by_ref[w.image_digest].commit.get("verified")}),
        "tag_heuristic": {"comparable": len(comparable), "git_tag_found": len(tag_found),
                          "agrees_with_embedded_revision": len(agree),
                          "images_with_any_tag_commit": len(heur_any),
                          "coverage_wilson95": wilson(len(heur_any), n),
                          "answers_not_verifiable": len(heur_any) - len(tag_found)},
        "stratum_coverage": {"images": len(verified), "wilson95": wilson(len(verified), n)},
        "per_image": [{"ref": p.ref, "repo": p.repo, "revision": p.revision[:12],
                       "verified": bool(p.commit.get("verified")), "author": p.commit.get("author", ""),
                       "pr": p.commit.get("pr"), "signed": p.resolved.get("signed"),
                       "size_mb": round(p.resolved.get("size", 0) / 1e6, 1)} for p in provs],
    }


def markdown(r: dict) -> str:
    lines = [f"### Build-provenance coverage for {r['images']} real images", "",
             "| hop | images | % |", "|---|---:|---:|"]
    for k, (c, p) in r["funnel"].items():
        lines.append(f"| {k} | {c} | {p} |")
    th = r["tag_heuristic"]
    lines += ["", f"Workloads traced end-to-end (pod -> image -> verified commit): "
              f"**{r['workloads_traced_to_commit']} / {r['workloads']}** "
              f"(Wilson 95% CI {r['workloads_traced_to_commit_wilson95']}); {r['workloads_traced_to_pr']} of them on to a merged PR.", "",
              f"Clustering: the {r['workloads_traced_to_commit']} traced workloads come from "
              f"{r['projects_with_a_traced_workload']} of {r['projects']} projects (Wilson 95% CI "
              f"{r['projects_traced_wilson95']}) and {r['images_of_traced_workloads']} images, so the workload-level "
              "interval above treats correlated workloads as independent; the project-level rate is the safer one.", "",
              f"Signature context: {r['funnel']['signature artefact (cosign / Sigstore)'][0]}/{r['images']} "
              f"images carry a signature artefact (Wilson 95% CI {r['funnel_wilson95']['signature artefact']}; formats "
              f"{r['artefact_formats']['signature']}), against "
              f"{100 * r['context']['docker_hub_tags_signed_2023']:.1f}% of Docker Hub tags signed in 2023 "
              f"({r['context']['source']}). This corpus is curated CNCF projects, so the gap is expected; "
              "presence of a signature is not a verified signature.", "",
              f"Baseline, the `image tag == git tag` heuristic. Coverage: it names a commit for "
              f"{th['images_with_any_tag_commit']}/{r['images']} images (Wilson 95% CI {th['coverage_wilson95']}) against "
              f"{r['stratum_coverage']['images']}/{r['images']} for STRATUM's verified embedded revision (Wilson 95% CI "
              f"{r['stratum_coverage']['wilson95']}). Where both answer ({th['git_tag_found']} images) they agree on "
              f"{th['agrees_with_embedded_revision']}; the heuristic gives no answer for "
              f"{th['comparable'] - th['git_tag_found']} of STRATUM's {th['comparable']}, and its other "
              f"{th['answers_not_verifiable']} answers cannot be checked against an embedded revision. The trade-off is "
              "coverage against verifiability: a tag name is a mutable pointer, not evidence of what was built."]
    return "\n".join(lines)
