"""Provenance coverage: how far can a runtime workload be traced back, on real public images?

Hops measured (registry + GitHub API metadata only):
image tag -> digest -> OCI source/revision labels -> verified GitHub commit -> PR,
plus cosign signature / attestation artefact presence.

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
            "cosign signature artefact": [len(signed), pct(len(signed), n)],
            "cosign attestation artefact": [len(attested), pct(len(attested), n)],
        },
        "funnel_wilson95": {"commit verified on GitHub": wilson(len(verified), n),
                            "cosign signature artefact": wilson(len(signed), n)},
        "context": {"docker_hub_tags_signed_2023": DOCKER_HUB_SIGNED_2023,
                    "source": "Schorlemmer et al. 2024, arXiv:2401.14635, Table 6 (DCT signatures; different population)"},
        "workloads": len(ds.workloads), "workloads_traced_to_commit": wl_traced,
        "workloads_traced_to_commit_wilson95": wilson(wl_traced, len(ds.workloads)),
        "workloads_traced_to_pr": wl_pr,
        "tag_heuristic": {"comparable": len(comparable), "git_tag_found": len(tag_found),
                          "agrees_with_embedded_revision": len(agree),
                          "images_with_any_tag_commit": len(heur_any)},
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
              f"Signature context: {r['funnel']['cosign signature artefact'][0]}/{r['images']} images carry a cosign signature "
              f"artefact (Wilson 95% CI {r['funnel_wilson95']['cosign signature artefact']}), against "
              f"{100 * r['context']['docker_hub_tags_signed_2023']:.1f}% of Docker Hub tags signed in 2023 "
              f"({r['context']['source']}). This corpus is curated CNCF projects, so the gap is expected; "
              "presence of a signature is not a verified signature.", "",
              f"Baseline, the `image tag == git tag` heuristic: of {th['comparable']} images with a verified embedded "
              f"commit, a same-named git tag existed for {th['git_tag_found']} and pointed at the embedded commit "
              f"for {th['agrees_with_embedded_revision']}."]
    return "\n".join(lines)
