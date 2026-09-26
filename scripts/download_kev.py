"""CISA Known Exploited Vulnerabilities catalog (public domain, US Gov).

The feed changes daily, so its hash is recorded in $STRATUM_DATA/MANIFEST.json
(not pinned) together with the catalog version for reproducibility.
"""
from __future__ import annotations

import json

from _common import data_dir, fetch, record

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def main() -> None:
    p = fetch(URL, data_dir() / "kev" / "known_exploited_vulnerabilities.json", key="kev/catalog", pin=False,
              force=True)
    kev = json.loads(p.read_text(encoding="utf-8"))
    record("kev/catalogVersion", kev.get("catalogVersion", "?"), pin=False)
    print(f"KEV {kev.get('catalogVersion')}: {len(kev['vulnerabilities'])} CVEs")


if __name__ == "__main__":
    main()
