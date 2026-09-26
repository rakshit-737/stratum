"""Regenerate docs pages that mirror README sections (index, getting started, benchmarks, limitations)."""
from __future__ import annotations

import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
BLOB = "https://github.com/rakshit-737/stratum/blob/main/"


def main() -> None:
    r = (ROOT / "README.md").read_text(encoding="utf-8")

    def sec(title: str) -> str:
        m = re.search(r"^## " + re.escape(title) + r"\n(.*?)(?=^## )", r, re.S | re.M)
        return m.group(1)

    def fix(t: str) -> str:
        t = t.replace('src="results/figures/', 'src="../figures/').replace("](docs/adr/", "](adr/")
        t = t.replace("](docs/datasets.md)", "](datasets.md)")
        return re.sub(r"\]\(((?:results|benchmarks)/[^)]*)\)", rf"]({BLOB}\1)", t)

    pitch = r[r.index("**An open mini-CNAPP.**"):r.index("## Headline results")]
    pitch = re.sub(r"Documentation: .*\n\n", "", pitch).replace("(#safety)", "(security.md)")
    (DOCS / "index.md").write_text("# STRATUM\n\n" + pitch + """
## Where to go next

- [Getting started](getting-started.md): install, demo, check your own manifests
- [Architecture](architecture.md): the lifecycle graph, 13 Zero-Trust controls, Rego mirror
- [Benchmarks](benchmarks.md): real-data results with confidence intervals
- [Live demo](demo.md): the incident console on a static real-data snapshot
- [Limitations & roadmap](limitations.md)
""", encoding="utf-8")
    (DOCS / "getting-started.md").write_text(fix(
        "# Getting started\n\n## Install and first run\n" + sec("Quickstart") + "## Reproducing the results\n"
        + sec("Reproducing the results") + "## Docker\n\n```bash\n"
        "docker run -p 8000:8000 ghcr.io/rakshit-737/stratum:latest     # synthetic source\n"
        "docker compose up                                              # API + Neo4j 5\n```\n"), encoding="utf-8")
    detail = r[r.index("## Results in detail") + len("## Results in detail"):r.index("## Prior art")]
    (DOCS / "benchmarks.md").write_text(fix(
        "# Benchmarks and results\n\nAll numbers come from `python -m stratum bench` on the real corpus; the raw tables "
        "are in `results/`.\n\n" + sec("Headline results (real data)") + "\n# Results in detail\n" + detail
        + "\n## Prior art\n" + sec("Prior art and how this differs")), encoding="utf-8")
    (DOCS / "limitations.md").write_text(fix(
        "# Limitations and roadmap\n\n## Limitations\n" + sec("Limitations") + "## Roadmap\n" + sec("Roadmap")),
        encoding="utf-8")
    (DOCS / "figures").mkdir(exist_ok=True)
    for png in (ROOT / "results" / "figures").glob("*.png"):
        shutil.copy2(png, DOCS / "figures" / png.name)


if __name__ == "__main__":
    main()
