"""ADFA-LD (UNSW Canberra) Linux system-call traces, used to evaluate the runtime
anomaly model. Mirror: github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset
(the original UNSW download page has moved several times).

Traces are integer syscall sequences only - there are no executables in the
archive. Cite: G. Creech and J. Hu, "Generation of a new IDS test dataset: Time
to retire the KDD collection", IEEE WCNC 2013.
"""
from __future__ import annotations

import zipfile

from _common import data_dir, fetch

COMMIT = "68bedf561f7b7abe9954a3ddc22dbf24c0d42372"
URL = ("https://raw.githubusercontent.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset/"
       f"{COMMIT}/ADFA-LD.zip")


def main() -> None:
    out = data_dir() / "adfa"
    arc = fetch(URL, out / "ADFA-LD.zip", key="adfa/ADFA-LD.zip")
    with zipfile.ZipFile(arc) as z:
        z.extractall(out)
    n = sum(1 for _ in out.rglob("*.txt"))
    print(f"ADFA-LD: {n} trace files under {out}")


if __name__ == "__main__":
    main()
