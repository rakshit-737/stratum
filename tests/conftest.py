import os
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures"
DATA = Path(os.environ.get("STRATUM_DATA", Path(__file__).resolve().parents[1] / "data"))


def pytest_configure(config):
    config.addinivalue_line("markers", "realdata: needs the downloaded corpus in $STRATUM_DATA (skipped otherwise)")


def pytest_collection_modifyitems(config, items):
    if (DATA / "manifests" / "index.json").exists():
        return
    skip = pytest.mark.skip(reason=f"real corpus not found in {DATA} (run scripts/download_all.py)")
    for it in items:
        if "realdata" in it.keywords:
            it.add_marker(skip)


@pytest.fixture
def fix() -> Path:
    return FIX
