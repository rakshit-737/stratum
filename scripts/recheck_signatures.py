"""Re-check the signature / attestation artefacts of every image in $STRATUM_DATA/provenance/provenance.json.

Registry requests only (no GitHub API): legacy cosign ``.sig`` / ``.att`` tags, Sigstore bundles and in-toto
attestations attached as OCI 1.1 referrers (referrers API or the ``sha256-<hex>`` fallback tag), and BuildKit
in-index attestation manifests. Updates the ``resolved`` block of each image in place and prints what changed;
the previous file is kept as provenance.pre-referrers.json.

    python scripts/recheck_signatures.py
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from _common import data_dir  # noqa: E402

from stratum.corpus import provenance_path  # noqa: E402
from stratum.registry import Registry, Resolved, parse_ref  # noqa: E402


def main() -> None:
    path = provenance_path(data_dir())
    provs = json.loads(path.read_text(encoding="utf-8"))
    backup = path.with_name("provenance.pre-referrers.json")
    if not backup.exists():
        shutil.copy2(path, backup)
    reg = Registry()
    changed = 0
    for i, p in enumerate(provs, 1):
        res = p["resolved"]
        if res.get("error") or not str(res.get("index_digest", "")).startswith("sha256:"):
            continue
        ref = parse_ref(p["ref"])
        index = None
        if res["index_digest"] != res.get("digest"):   # the tag pointed at an index: re-read it for BuildKit
            try:
                index = reg._json(ref, f"manifests/{res['index_digest']}")[0]
            except Exception:  # noqa: BLE001 - best effort, the index is only scanned for attestation manifests
                index = None
        r = reg.signature_artifacts(ref, Resolved(p["ref"], digest=res.get("digest", ""),
                                                  index_digest=res["index_digest"]), index)
        new = {"signed": r.signed, "attested": r.attested, "signature_format": r.signature_format,
               "attestation_format": r.attestation_format, "buildkit_attestation": r.buildkit_attestation}
        old = {k: res.get(k) for k in ("signed", "attested")}
        if old != {k: new[k] for k in old}:
            changed += 1
            print(f"[{i:>2}] {p['ref'][:80]}: {old} -> signed={r.signed} ({r.signature_format or '-'}), "
                  f"attested={r.attested} ({r.attestation_format or '-'})", flush=True)
        res.update(new)
    path.write_text(json.dumps(provs, indent=1), encoding="utf-8")
    n = len(provs)
    print(f"{changed} of {n} images changed; signed {sum(p['resolved'].get('signed') is True for p in provs)}, "
          f"attested {sum(p['resolved'].get('attested') is True for p in provs)}, BuildKit in-index attestation "
          f"{sum(p['resolved'].get('buildkit_attestation') is True for p in provs)}")


if __name__ == "__main__":
    main()
