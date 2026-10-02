"""Read build provenance out of a verified cosign signature (Sigstore keyless, GitHub OIDC).

``cosign verify -o json`` prints, for every verified signature, the signed image digest and the
Fulcio certificate's GitHub claims. The certificate is issued to the CI run that signed the image,
so it names the commit (OID 1.3.6.1.4.1.57264.1.3), the repository (.1.5), the ref (.1.6) and the run
(the Run Invocation URI, OID .1.21, read from the certificate inside the Rekor bundle). STRATUM builds
its ``image -> build -> commit`` edges from these fields instead of trusting values passed in by the
workflow, so the live trace-to-commit check can fail if the running image was not built by that commit.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path

OID = "1.3.6.1.4.1.57264.1."
_RUN = re.compile(rb"https://github\.com/[\w.-]+/[\w.-]+/actions/runs/(\d+)")


def _run_uri(der: bytes) -> tuple[str, str] | None:
    """Run Invocation URI from the DER certificate; the DER length byte bounds the string."""
    for m in _RUN.finditer(der):
        s, n = m.start(), der[m.start() - 1] if m.start() else 0
        uri = der[s:s + n] if 0 < n < 0x80 and s + n <= len(der) else m.group(0)
        if uri.startswith(m.group(0)):
            return m.group(1).decode(), uri.decode(errors="replace")
    return None


@dataclass
class SignedImage:
    digest: str
    repository: str  # docker reference (no tag/digest)
    commit: str
    source_repo: str
    ref: str
    issuer: str
    run_id: str | None
    run_url: str | None


def _cert_der(optional: dict) -> bytes:
    """DER bytes of the Fulcio certificate embedded in the Rekor bundle (empty if absent)."""
    try:
        body = json.loads(base64.b64decode(optional["Bundle"]["Payload"]["body"]))
        pem = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"]).decode()
        b64 = "".join(ln for ln in pem.splitlines() if ln and not ln.startswith("-----"))
        return base64.b64decode(b64)
    except (KeyError, ValueError, TypeError):
        return b""


def parse_cosign_verify(doc: list[dict] | str | Path) -> list[SignedImage]:
    """Parse ``cosign verify -o json`` output (a list of verified signature payloads)."""
    if isinstance(doc, str | Path):
        doc = json.loads(Path(doc).read_text(encoding="utf-8"))
    out = []
    for sig in doc or []:
        crit, opt = sig.get("critical") or {}, sig.get("optional") or {}
        digest = (crit.get("image") or {}).get("docker-manifest-digest", "")
        commit = opt.get(OID + "3") or opt.get("githubWorkflowSha", "")
        if not digest or not commit:
            continue
        run = _run_uri(_cert_der(opt))
        out.append(SignedImage(
            digest=digest, repository=(crit.get("identity") or {}).get("docker-reference", ""),
            commit=commit, source_repo=opt.get(OID + "5") or opt.get("githubWorkflowRepository", ""),
            ref=opt.get(OID + "6") or opt.get("githubWorkflowRef", ""), issuer=opt.get(OID + "1") or opt.get("Issuer", ""),
            run_id=run[0] if run else None, run_url=run[1] if run else None))
    return out
