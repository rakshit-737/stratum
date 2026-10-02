"""Aggregate the live-evidence-*/live-result.json artefacts of one live.yml run into results/live.{json,md}.

    gh run download <run-id> -D live-runs
    python scripts/aggregate_live.py live-runs --run-url https://github.com/rakshit-737/stratum/actions/runs/<id>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stratum.live import aggregate, aggregate_markdown  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--run-url", default="")
    a = ap.parse_args()
    runs = [json.loads(p.read_text(encoding="utf-8"))
            for p in sorted(Path(a.dir).glob("live-evidence-*/live-result.json"))]
    if not runs:
        raise SystemExit("no live-evidence-*/live-result.json found")
    agg = aggregate(runs, a.run_url)
    (ROOT / "results" / "live.json").write_text(json.dumps(agg, indent=1) + "\n", encoding="utf-8")
    (ROOT / "results" / "live.md").write_text(aggregate_markdown(agg) + "\n", encoding="utf-8")
    print(aggregate_markdown(agg))


if __name__ == "__main__":
    main()
