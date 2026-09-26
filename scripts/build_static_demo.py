"""Snapshot the STRATUM API into static JSON and a static copy of the console under docs/demo/.

Usage: python scripts/build_static_demo.py [--source synthetic|real] [--out docs/demo]
The GitHub Pages site serves the result at /demo/ (no server needed).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

STATIC_GET = r'''const slug = (s) => s.replace(/[^A-Za-z0-9._-]+/g, "_");
const get = (u) => { const m = u.match(/^\/api\/blast\?base=(.*)$/);
  const f = m ? "api/blast/" + slug(decodeURIComponent(m[1])) + ".json" : u.replace(/^\//, "") + ".json";
  return fetch(f).then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); }); };'''


def slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="synthetic")
    ap.add_argument("--out", default=str(ROOT / "docs" / "demo"))
    a = ap.parse_args()
    os.environ["STRATUM_SOURCE"] = a.source
    from fastapi.testclient import TestClient

    from stratum.api import WEB, app

    c = TestClient(app)
    out = Path(a.out)
    (out / "api" / "blast").mkdir(parents=True, exist_ok=True)

    def dump(path: str, file: Path) -> object:
        r = c.get(path)
        r.raise_for_status()
        file.write_text(json.dumps(r.json(), separators=(",", ":")), encoding="utf-8")
        return r.json()

    for ep in ("summary", "controls", "workloads", "incidents"):
        dump(f"/api/{ep}", out / "api" / f"{ep}.json")
    for b in dump("/api/bases", out / "api" / "bases.json"):
        dump(f"/api/blast?base={b['id']}", out / "api" / "blast" / f"{slug(b['id'])}.json")
    html = (WEB / "index.html").read_text(encoding="utf-8")
    old = next(line for line in html.splitlines() if line.startswith("const get = "))
    html = html.replace(old, STATIC_GET)
    html = html.replace("<main id=\"view\">", "<p class=\"muted\" style=\"margin:0 1rem\">Static snapshot of the "
                        f"STRATUM console ({a.source} source). Run <code>stratum serve</code> for the live API.</p>\n"
                        "<main id=\"view\">", 1)
    (out / "index.html").write_text(html, encoding="utf-8")
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    digest = hashlib.sha256((out / "api" / "summary.json").read_bytes()).hexdigest()[:12]
    print(f"wrote {out} ({size / 1024:.0f} KB, summary {digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
