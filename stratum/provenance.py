"""Build provenance for real images: image -> (OCI labels) -> GitHub commit -> PR/author.

This is the "CI provenance" input of the lifecycle graph for images we did not
build ourselves. The chain is only accepted when every hop is verified:

1. the registry manifest for the tag resolves to a linux/amd64 digest,
2. the image config carries ``org.opencontainers.image.source`` (a GitHub
   repo) and ``org.opencontainers.image.revision`` (a commit SHA), and
3. that commit exists in that repo according to the GitHub API
   (author, date, message and associated PR are recorded).

``cosign`` signature / attestation artefacts next to the digest are recorded as
``signed`` / ``attested`` (presence only - signatures are not verified
cryptographically; see docs/adr/0004-provenance-sources.md).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

from .dataset import Dataset
from .models import Build, Commit, Image, ImageReport
from .registry import Registry, Resolved, github_repo, parse_ref, revision


@dataclass
class CommitInfo:
    repo: str
    sha: str
    verified: bool = False
    author: str = ""
    date: str = ""
    message: str = ""
    pr: int | None = None
    error: str = ""


@dataclass
class Provenance:
    ref: str
    resolved: dict = field(default_factory=dict)
    repo: str = ""
    revision: str = ""
    commit: dict = field(default_factory=dict)


def github_token() -> str:
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if not tok and shutil.which("gh"):
        try:
            tok = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            tok = ""
    return tok


class GitHub:
    def __init__(self, token: str = "") -> None:
        self.h = {"Accept": "application/vnd.github+json", "User-Agent": "stratum-provenance/0.2"}
        if token:
            self.h["Authorization"] = f"Bearer {token}"

    def _get(self, path: str, retries: int = 3):
        req = urllib.request.Request("https://api.github.com/" + path, headers=self.h)
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    return json.load(r)
            except urllib.error.HTTPError:
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == retries - 1:
                    raise
                time.sleep(2 * (attempt + 1))

    def commit(self, repo: str, sha: str) -> CommitInfo:
        ci = CommitInfo(repo, sha)
        try:
            c = self._get(f"repos/{repo}/commits/{sha}")
            ci.sha = c["sha"]
            ci.verified = True
            ci.author = (c.get("author") or {}).get("login") or c["commit"]["author"]["name"]
            ci.date = c["commit"]["committer"]["date"]
            ci.message = c["commit"]["message"].splitlines()[0][:200]
            try:
                prs = self._get(f"repos/{repo}/commits/{ci.sha}/pulls")
                merged = [p for p in prs if p.get("merged_at")] or prs
                ci.pr = merged[0]["number"] if merged else None
            except urllib.error.HTTPError:
                pass
        except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
            ci.error = f"{type(e).__name__}: {e}"[:200]
        return ci


def tag_commit(gh: GitHub, repo: str, tag: str) -> str:
    """Naive baseline: the commit a same-named git tag points to (also tries a 'v' prefix)."""
    for t in dict.fromkeys([tag, tag.lstrip("v"), "v" + tag.lstrip("v")]):
        try:
            return gh._get(f"repos/{repo}/commits/{t}")["sha"]
        except (urllib.error.URLError, OSError, KeyError, ValueError):
            continue
    return ""


def add_tag_baseline(provs: list[Provenance], gh: GitHub) -> None:
    """Record what the tag->git-tag heuristic would say, for images whose repo is known."""
    for p in provs:
        tag = parse_ref(p.ref).tag
        if p.repo and tag and tag != "latest" and "tag_sha" not in p.commit:
            p.commit = dict(p.commit, tag_sha=tag_commit(gh, p.repo, tag))


def resolve(refs: list[str], *, registry: Registry | None = None, gh: GitHub | None = None,
            progress=None) -> list[Provenance]:
    registry = registry or Registry()
    out = []
    for i, ref in enumerate(refs):
        r: Resolved = registry.resolve(ref)
        p = Provenance(ref, asdict(r), github_repo(r.labels), revision(r.labels))
        if gh and p.repo and p.revision:
            p.commit = asdict(gh.commit(p.repo, p.revision))
        out.append(p)
        if progress:
            progress(i + 1, len(refs), p)
    return out


def _short(ref: str) -> str:
    r = parse_ref(ref)
    return f"{r.registry}/{r.repo}"


def to_dataset(provs: list[Provenance], reports: list[ImageReport] | None = None) -> Dataset:
    """Images / builds / commits for the lifecycle graph.

    Image node id == the exact ref string used in the manifests, so the graph
    joins manifests (workloads) to provenance without guessing.
    """
    ds = Dataset()
    reps = {r.ref: r for r in reports or []}
    seen_commits: set[str] = set()
    for p in provs:
        res = p.resolved
        rep = reps.get(p.ref)
        base = rep.os if rep and rep.os else None
        build_id = None
        c = p.commit
        if c.get("verified"):
            build_id = f"oci:{res.get('digest', '')[7:19] or p.ref}"
            ds.builds.append(Build(build_id, c["sha"], f"github.com/{p.repo}", signed=bool(res.get("signed"))))
            if c["sha"] not in seen_commits:
                seen_commits.add(c["sha"])
                ds.commits.append(Commit(c["sha"], p.repo, c.get("author", ""), c.get("message", ""), c.get("pr")))
        layers = [f"base:{base}"] if base else []
        ds.images.append(Image(p.ref, _short(p.ref), build_id, base, layers))
    ds.image_reports = list(reports or [])
    return ds


def save(provs: list[Provenance], path) -> None:
    from pathlib import Path
    Path(path).write_text(json.dumps([asdict(p) for p in provs], indent=1), encoding="utf-8")


def load(path) -> list[Provenance]:
    from pathlib import Path
    return [Provenance(**d) for d in json.loads(Path(path).read_text(encoding="utf-8"))]
