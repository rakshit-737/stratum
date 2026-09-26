"""Shared helpers for the download / preparation scripts.

All data lives OUTSIDE the git repo, in ``$STRATUM_DATA`` (default: ``./data``,
which is git-ignored). Every download is verified against a SHA-256 that is
either pinned in ``scripts/checksums.json`` or published by the upstream
project; files whose content legitimately changes (e.g. the daily CISA KEV
feed) have their hash recorded in ``$STRATUM_DATA/MANIFEST.json`` instead.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CHECKSUMS = REPO / "scripts" / "checksums.json"
UA = {"User-Agent": "stratum-dataset-fetcher/0.2 (+https://github.com/rakshit-737/stratum)"}


def data_dir() -> Path:
    d = Path(os.environ.get("STRATUM_DATA", REPO / "data")).resolve()
    d.mkdir(parents=True, exist_ok=True)
    return d


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pinned() -> dict:
    return json.loads(CHECKSUMS.read_text()) if CHECKSUMS.exists() else {}


def record(key: str, digest: str, *, pin: bool) -> None:
    """Remember a hash: in the committed pin file (pin=True) or the local manifest."""
    target = CHECKSUMS if pin else data_dir() / "MANIFEST.json"
    cur = json.loads(target.read_text()) if target.exists() else {}
    cur[key] = digest
    target.write_text(json.dumps(dict(sorted(cur.items())), indent=2) + "\n")


def _download_resumable(url: str, tmp: Path, retries: int = 8) -> None:
    """GET with HTTP Range resume; survives connection resets on slow links."""
    for attempt in range(retries):
        have = tmp.stat().st_size if tmp.exists() else 0
        headers = dict(UA, **({"Range": f"bytes={have}-"} if have else {}))
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120) as r:
                mode = "ab" if have and r.status == 206 else "wb"
                with open(tmp, mode) as fh:
                    while chunk := r.read(1 << 20):
                        fh.write(chunk)
            return
        except urllib.error.HTTPError as e:
            if e.code == 416:  # already complete
                return
            raise
        except (OSError, TimeoutError) as e:
            print(f"  retry {attempt + 1}/{retries} after {type(e).__name__}", file=sys.stderr)
            time.sleep(2 * (attempt + 1))
    raise SystemExit(f"download failed after {retries} attempts: {url}")


def fetch(url: str, dest: Path, *, sha: str | None = None, key: str | None = None,
          pin: bool = True, force: bool = False) -> Path:
    """Download ``url`` to ``dest`` and verify it.

    ``sha``  - expected SHA-256 (e.g. from an upstream checksum file).
    ``key``  - name in scripts/checksums.json; if pinned there it is enforced,
               otherwise the hash is recorded (trust-on-first-use) so later
               runs are reproducible.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    expected = sha or (pinned().get(key) if key else None)
    if dest.exists() and not force:
        got = sha256(dest)
        if expected is None or got == expected:
            return dest
        print(f"  checksum mismatch for cached {dest.name}; re-downloading", file=sys.stderr)
    tmp = dest.with_suffix(dest.suffix + ".part")
    _download_resumable(url, tmp)
    got = sha256(tmp)
    if expected and got != expected:
        tmp.unlink()
        raise SystemExit(f"SHA-256 mismatch for {url}: expected {expected}, got {got}")
    tmp.replace(dest)
    if key and not expected:
        record(key, got, pin=pin)
    print(f"  ok  {dest.relative_to(data_dir()) if dest.is_relative_to(data_dir()) else dest}  sha256={got[:16]}...")
    return dest
