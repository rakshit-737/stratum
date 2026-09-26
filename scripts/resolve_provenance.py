"""Resolve every image referenced by the downloaded manifests to digest, size,
OCI source/revision labels, cosign artefacts, and the GitHub commit + PR it was
built from. Registry + GitHub API metadata only: no image layers are pulled.

Writes $STRATUM_DATA/provenance/provenance.json.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import data_dir  # noqa: E402

from stratum.corpus import manifests_dataset, provenance_path  # noqa: E402
from stratum.provenance import GitHub, add_tag_baseline, github_token, load, resolve, save  # noqa: E402
from stratum.registry import github_repo, revision  # noqa: E402


def main() -> None:
    root = data_dir()
    ds = manifests_dataset(root)
    refs = sorted({i for w in ds.workloads for i in (w.images or [w.image_digest])})
    out = provenance_path(root)
    cached = {p.ref: p for p in load(out)} if out.exists() else {}
    def stale(p) -> bool:  # registry failure, or a transient (non-4xx) GitHub failure
        err = p.commit.get("error", "")
        return bool(p.resolved.get("error")) or (bool(err) and not err.startswith("HTTPError: HTTP Error 4")) or (
            bool(p.repo and p.revision) and not p.commit)

    for p in cached.values():  # re-derive labels with the current parser
        p.repo, p.revision = github_repo(p.resolved.get("labels", {})), revision(p.resolved.get("labels", {}))
    todo = [r for r in refs if r not in cached or stale(cached[r])]
    print(f"{len(refs)} image refs, {len(refs) - len(todo)} cached, resolving {len(todo)}")

    def prog(i, n, p):
        c = p.commit
        print(f"  [{i:>2}/{n}] {p.ref[:70]:70} repo={p.repo or '-':30} "
              f"commit={'OK ' + (c.get('author') or '') if c.get('verified') else '-'}"
              f"{'  ERR ' + p.resolved['error'] if p.resolved.get('error') else ''}", flush=True)

    gh = GitHub(github_token())
    new = {p.ref: p for p in resolve(todo, gh=gh, progress=prog)}
    provs = [new.get(r) or cached[r] for r in refs]
    add_tag_baseline(provs, gh)
    out.parent.mkdir(parents=True, exist_ok=True)
    save(provs, out)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
