"""Aggregate live.yml evidence (live-evidence-*/live-result.json) into results/live.{json,md}.

One dispatch with ``runs=N`` (N matrix jobs of one workflow run):

    gh run download <run-id> -R rakshit-737/stratum -D live-runs
    python scripts/aggregate_live.py live-runs --run-url https://github.com/rakshit-737/stratum/actions/runs/<id>

Several dispatches: download each into its own sub-directory (``live-runs/<run-id>/``) and pass one
``--run-url`` per run. results/live.md is written only by this script.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stratum.live import aggregate, aggregate_markdown  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def load_runs(root: Path) -> list[dict]:
    """Every live-result.json under ``root``, tagged with the artefact (and run directory) it came from."""
    runs = []
    for p in sorted(root.rglob("live-evidence-*/live-result.json")):
        r = json.loads(p.read_text(encoding="utf-8"))
        r["artifact"] = p.parent.relative_to(root).as_posix()
        runs.append(r)
    return runs


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir", help="directory holding the downloaded live-evidence-* artefacts")
    ap.add_argument("--run-url", action="append", default=[], help="workflow run URL (repeat for several runs)")
    ap.add_argument("--out", default=str(ROOT / "results"), help="output directory (default results/)")
    a = ap.parse_args()
    runs = load_runs(Path(a.dir))
    if not runs:
        raise SystemExit("no live-evidence-*/live-result.json found")
    agg = aggregate(runs, a.run_url)
    out = Path(a.out)
    (out / "live.json").write_text(json.dumps(agg, indent=1) + "\n", encoding="utf-8")
    (out / "live.md").write_text(aggregate_markdown(agg) + "\n", encoding="utf-8")
    print(aggregate_markdown(agg))


if __name__ == "__main__":
    main()
