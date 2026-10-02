"""Regenerate docs pages that mirror README sections (getting started, evaluation, limitations)."""
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
        t = re.sub(r'<img src="results/figures/([^"]+)" width="(\d+)%" alt="([^"]*)">',
                   r'![\3](figures/\1){ width="\2%" }', t)
        t = t.replace("](docs/adr/", "](adr/").replace("](docs/figures/", "](figures/")
        t = re.sub(r"\]\(docs/([a-z-]+\.md)\)", r"](\1)", t)
        t = t.replace("](docs/datasets.md)", "](datasets.md)")
        return re.sub(r"\]\(((?:results|benchmarks|\.github)/[^)]*)\)", rf"]({BLOB}\1)", t)

    # docs/index.md is hand-written (landing page); it is not regenerated here.
    (DOCS / "getting-started.md").write_text(fix(
        "# Getting started\n\n## Install and first run\n" + sec("Quickstart") + "## Reproducing the results\n"
        + sec("Reproducing the results") + "## Docker\n\n```bash\n"
        "docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/stratum:latest   # synthetic source\n"
        "docker compose up                                              # API + Neo4j 5\n```\n"), encoding="utf-8")
    detail = r[r.index("## Results in detail") + len("## Results in detail"):r.index("## Prior art")]
    (DOCS / "benchmarks.md").write_text(fix(
        "# Evaluation\n\nAll numbers come from `python -m stratum bench` on the real corpus, the live CI job and the "
        "reproduction workflow; the raw tables are in `results/`. Each subsection states its method, sample size and "
        "confidence interval.\n\n" + sec("Headline results") + "\n## Results in detail\n" + detail
        + "\n## Prior art\n" + sec("Prior art and how this differs")), encoding="utf-8")
    (DOCS / "limitations.md").write_text(fix(
        "# Limitations and roadmap\n\n## Limitations\n" + sec("Limitations") + "## Roadmap\n" + sec("Roadmap")),
        encoding="utf-8")
    (DOCS / "figures").mkdir(exist_ok=True)
    for png in (ROOT / "results" / "figures").glob("*.png"):
        shutil.copy2(png, DOCS / "figures" / png.name)


if __name__ == "__main__":
    main()
