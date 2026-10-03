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
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

OID = "1.3.6.1.4.1.57264.1."
_RUN = re.compile(rb"https://github\.com/[\w.-]+/[\w.-]+/actions/runs/(\d+)")
_ATTEMPT = re.compile(r"/attempts/(\d+)")


def _run_uri(der: bytes) -> tuple[str, str] | None:
    """Run Invocation URI from the DER certificate; the DER length byte bounds the string."""
    for m in _RUN.finditer(der):
        s, n = m.start(), der[m.start() - 1] if m.start() else 0
        uri = der[s:s + n] if 0 < n < 0x80 and s + n <= len(der) else m.group(0)
        if uri.startswith(m.group(0)):
            return m.group(1).decode(), uri.decode(errors="replace")
    return None


def _tlv(der: bytes, i: int) -> tuple[int, int, int]:
    """(tag, content offset, content length) of the DER element starting at ``i``."""
    tag, n = der[i], der[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n = int.from_bytes(der[i:i + k], "big")
        i += k
    return tag, i, n


def _cert_serial(der: bytes) -> str | None:
    """Serial number (upper-case hex) of an X.509 certificate in DER form, or None if it does not parse."""
    try:
        _, i, _ = _tlv(der, 0)          # Certificate ::= SEQUENCE
        _, i, _ = _tlv(der, i)          # tbsCertificate ::= SEQUENCE
        tag, j, n = _tlv(der, i)
        if tag == 0xA0:                 # [0] EXPLICIT version
            tag, j, n = _tlv(der, j + n)
        return der[j:j + n].hex().upper() if tag == 0x02 and n else None
    except IndexError:
        return None


@dataclass
class SignedImage:
    """One verified signature: the signed digest and the claims of the Fulcio certificate that signed it.

    ``cert_sha256`` (SHA-256 of the leaf certificate DER), ``cert_serial`` and ``rekor_log_index`` identify
    the certificate itself; ``run_id`` is the CI run named by the certificate, which every job of one
    workflow run shares.
    """
    digest: str
    repository: str  # docker reference (no tag/digest)
    commit: str
    source_repo: str
    ref: str
    issuer: str
    run_id: str | None
    run_url: str | None
    cert_sha256: str | None = None
    cert_serial: str | None = None
    rekor_log_index: int | None = None
    run_attempt: str | None = None

    def certificate(self) -> dict:
        """The certificate identity and the CI run it names, for evidence files."""
        return {"digest": self.digest, "cert_sha256": self.cert_sha256, "cert_serial": self.cert_serial,
                "rekor_log_index": self.rekor_log_index, "run_id": self.run_id, "run_attempt": self.run_attempt,
                "commit": self.commit}


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
        der = _cert_der(opt)
        run = _run_uri(der)
        attempt = _ATTEMPT.search(run[1]) if run else None
        log_index = ((opt.get("Bundle") or {}).get("Payload") or {}).get("logIndex")
        out.append(SignedImage(
            digest=digest, repository=(crit.get("identity") or {}).get("docker-reference", ""),
            commit=commit, source_repo=opt.get(OID + "5") or opt.get("githubWorkflowRepository", ""),
            ref=opt.get(OID + "6") or opt.get("githubWorkflowRef", ""), issuer=opt.get(OID + "1") or opt.get("Issuer", ""),
            run_id=run[0] if run else None, run_url=run[1] if run else None,
            cert_sha256=hashlib.sha256(der).hexdigest() if der else None, cert_serial=_cert_serial(der) if der else None,
            rekor_log_index=int(log_index) if isinstance(log_index, int | str) and str(log_index).isdigit() else None,
            run_attempt=attempt.group(1) if attempt else None))
    return out
