"""Minimal read-only OCI / Docker registry client (anonymous pulls only).

Used by the provenance resolver to learn, for a public image reference, *without
pulling any layers*:

* the immutable digest a tag currently points to (linux/amd64 manifest),
* the compressed image size,
* the OCI config labels ``org.opencontainers.image.source`` / ``.revision``
  that link an image to the commit it was built from, and
* whether a cosign signature or attestation is published next to it: the legacy cosign tags
  ``sha256-<digest>.sig`` / ``.att``, or (cosign v3, ``--new-bundle-format``) a Sigstore bundle attached
  through the OCI 1.1 referrers API or its ``sha256-<digest>`` fallback-tag index. BuildKit's in-index
  attestation manifests (unsigned SLSA provenance / SBOM) are recorded separately.

Only standard Distribution API GETs/HEADs are issued; no credentials are used.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

ACCEPT = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
UA = "stratum-provenance/0.2 (+https://github.com/rakshit-737/stratum-cloud-security)"


@dataclass
class ImageRef:
    registry: str
    repo: str
    tag: str = ""
    digest: str = ""

    @property
    def display(self) -> str:
        s = f"{self.registry}/{self.repo}"
        return s + (f"@{self.digest}" if self.digest else f":{self.tag or 'latest'}")


def parse_ref(ref: str) -> ImageRef:
    """Normalise ``nginx``, ``ghcr.io/o/r:1.0``, ``quay.io/x/y@sha256:..`` etc."""
    digest = ""
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    first, _, rest = ref.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, path = first, rest
    else:
        registry, path = "docker.io", ref
    tag = ""
    if ":" in path.rsplit("/", 1)[-1]:
        path, tag = path.rsplit(":", 1)
    if registry == "docker.io" and "/" not in path:
        path = "library/" + path
    if not tag and not digest:
        tag = "latest"
    return ImageRef(registry, path, tag, digest)


@dataclass
class Resolved:
    ref: str
    digest: str = ""                 # platform manifest digest actually run on linux/amd64
    index_digest: str = ""           # digest the tag points to (index or manifest)
    size: int = 0                    # compressed bytes of all layers
    labels: dict = field(default_factory=dict)
    created: str = ""
    signed: bool = False             # signature artefact published (cosign tag or Sigstore bundle)
    attested: bool = False           # attestation artefact published (cosign tag, bundle or in-toto)
    signature_format: str = ""       # "cosign-tag" (.sig) or "sigstore-bundle" (OCI referrer)
    attestation_format: str = ""     # "cosign-tag" (.att), "sigstore-bundle" or "in-toto" (OCI referrer)
    buildkit_attestation: bool = False  # unsigned attestation manifest inside the image index
    error: str = ""


SIGSTORE_BUNDLE = "application/vnd.dev.sigstore.bundle"
COSIGN_SIG_ARTIFACT = "application/vnd.dev.cosign.artifact.sig"
COSIGN_SIGN_PREDICATE = "https://sigstore.dev/cosign/sign/v1"   # cosign v3 `sign`: a DSSE-wrapped signature
INTOTO_TYPES = ("application/vnd.in-toto", "application/vnd.dsse.envelope")
EMPTY = ("", "application/vnd.oci.empty.v1+json")


def classify_referrers(index: dict, fetch=None, max_fetch: int = 10) -> tuple[str, str]:
    """(signature_format, attestation_format) from an OCI referrers / fallback-tag index.

    A Sigstore bundle is a signature when it carries no predicate type or cosign's own sign predicate
    (``https://sigstore.dev/cosign/sign/v1``, what cosign v3 ``sign`` writes), and an attestation for any
    other predicate (SLSA provenance, SBOM, ...). ``application/vnd.dev.cosign.artifact.sig*`` is cosign's
    OCI 1.1 signature type. When an index entry has no artifact type (some registries and the fallback
    tag schema leave it empty), ``fetch(digest)`` reads the referrer manifest itself.
    """
    sig = att = ""
    for m in index.get("manifests") or []:
        t, ann = (m.get("artifactType") or "").lower(), m.get("annotations") or {}
        if t in EMPTY and fetch and max_fetch > 0:
            max_fetch -= 1
            body = fetch(m.get("digest", "")) or {}
            t = (body.get("artifactType") or (body.get("config") or {}).get("artifactType") or "").lower()
            ann = {**ann, **(body.get("annotations") or {})}
        pred = next((v for k, v in ann.items() if k.lower().endswith("predicatetype")), "")
        if t.startswith(SIGSTORE_BUNDLE):
            if pred and pred != COSIGN_SIGN_PREDICATE:
                att = att or "sigstore-bundle"
            else:
                sig = sig or "sigstore-bundle"
        elif t.startswith(COSIGN_SIG_ARTIFACT):
            sig = sig or "cosign-oci11"
        elif t.startswith(INTOTO_TYPES):
            att = att or "in-toto"
    return sig, att


class Registry:
    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout
        self._tokens: dict[tuple[str, str], str] = {}

    @staticmethod
    def _host(registry: str) -> str:
        return "registry-1.docker.io" if registry == "docker.io" else registry

    def _token(self, www: str) -> str:
        m = dict(re.findall(r'(\w+)="([^"]*)"', www))
        q = {k: m[k] for k in ("service", "scope") if k in m}
        realm = urllib.parse.urlsplit(m.get("realm", ""))
        if realm.scheme != "https" or not realm.hostname:
            raise ValueError(f"refusing token realm {m.get('realm')!r}: must be an https URL")
        url = m["realm"] + ("?" + urllib.parse.urlencode(q) if q else "")
        # https only: no file://, ftp:// or plain http handlers for a server-chosen URL
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler)
        opener.handlers = [h for h in opener.handlers if not isinstance(
            h, urllib.request.FileHandler | urllib.request.FTPHandler | urllib.request.HTTPHandler
                | urllib.request.DataHandler)]
        with opener.open(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=self.timeout) as r:
            body = json.load(r)
        return body.get("token") or body.get("access_token") or ""

    def _req(self, ref: ImageRef, path: str, method: str = "GET", accept: str = ACCEPT, retries: int = 3):
        for attempt in range(retries):
            try:
                return self._req_once(ref, path, method, accept)
            except urllib.error.HTTPError:
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == retries - 1:
                    raise
                time.sleep(2 * (attempt + 1))
        raise RuntimeError("unreachable")

    def _req_once(self, ref: ImageRef, path: str, method: str, accept: str):
        url = f"https://{self._host(ref.registry)}/v2/{ref.repo}/{path}"
        key = (ref.registry, ref.repo)
        for _ in range(2):
            h = {"User-Agent": UA, "Accept": accept}
            if key in self._tokens:
                h["Authorization"] = f"Bearer {self._tokens[key]}"
            try:
                return urllib.request.urlopen(urllib.request.Request(url, headers=h, method=method),
                                              timeout=self.timeout)
            except urllib.error.HTTPError as e:
                www = e.headers.get("WWW-Authenticate", "")
                if e.code == 401 and www.lower().startswith("bearer") and key not in self._tokens:
                    self._tokens[key] = self._token(www[len("bearer "):])
                    continue
                raise
        raise RuntimeError("unreachable")

    def _json(self, ref: ImageRef, path: str, accept: str = ACCEPT) -> tuple[dict, str]:
        with self._req(ref, path, accept=accept) as r:
            return json.loads(r.read()), r.headers.get("Docker-Content-Digest", "")

    def exists(self, ref: ImageRef, tag: str) -> bool:
        try:
            with self._req(ref, f"manifests/{tag}", method="HEAD"):
                return True
        except urllib.error.HTTPError:
            return False

    def referrers(self, ref: ImageRef, digest: str) -> dict:
        """OCI 1.1 referrers of ``digest``: the ``sha256-<hex>`` fallback-tag index, else the referrers API.

        The fallback tag is probed with HEAD first, so an image without referrers costs no manifest pull.
        """
        tag = "sha256-" + digest.split(":", 1)[1]
        if self.exists(ref, tag):
            try:
                doc, _ = self._json(ref, f"manifests/{tag}")
                if doc.get("manifests"):
                    return doc
            except (urllib.error.URLError, OSError, ValueError):
                pass
        try:
            doc, _ = self._json(ref, f"referrers/{digest}", accept="application/vnd.oci.image.index.v1+json")
            return doc if doc.get("manifests") else {}
        except (urllib.error.URLError, OSError, ValueError):   # 404: the registry has no referrers API
            return {}

    def signature_artifacts(self, ref: ImageRef, out: Resolved, index: dict | None = None) -> Resolved:
        """Fill ``out.signed`` / ``out.attested`` (and their formats) for ``out.index_digest``.

        Legacy cosign tags first, then Sigstore bundles and in-toto attestations attached as OCI referrers.
        ``index`` (the image index, if the tag pointed at one) is scanned for BuildKit attestation manifests.
        """
        h = out.index_digest.split(":", 1)[1]
        if self.exists(ref, f"sha256-{h}.sig"):
            out.signed, out.signature_format = True, "cosign-tag"
        if self.exists(ref, f"sha256-{h}.att"):
            out.attested, out.attestation_format = True, "cosign-tag"
        if not (out.signed and out.attested):
            def fetch(digest: str) -> dict:
                try:
                    return self._json(ref, f"manifests/{digest}", accept="application/vnd.oci.image.manifest.v1+json")[0]
                except (urllib.error.URLError, OSError, ValueError):
                    return {}
            sig, att = classify_referrers(self.referrers(ref, out.index_digest), fetch)
            if sig and not out.signed:
                out.signed, out.signature_format = True, sig
            if att and not out.attested:
                out.attested, out.attestation_format = True, att
        if index is not None:
            out.buildkit_attestation = any((m.get("annotations") or {}).get("vnd.docker.reference.type")
                                           == "attestation-manifest" for m in index.get("manifests") or [])
        return out

    def resolve(self, image: str, *, arch: str = "amd64", check_signatures: bool = True) -> Resolved:
        ref = parse_ref(image)
        out = Resolved(image)
        try:
            doc, top = self._json(ref, f"manifests/{ref.digest or ref.tag}")
            out.index_digest = ref.digest or top
            index = doc if "manifests" in doc else None
            if "manifests" in doc:  # index / manifest list -> pick linux/<arch>
                cand = [m for m in doc["manifests"]
                        if (m.get("platform") or {}).get("os") == "linux"
                        and (m.get("platform") or {}).get("architecture") == arch]
                if not cand:
                    out.error = "no linux/" + arch
                    return out
                out.digest = cand[0]["digest"]
                doc, _ = self._json(ref, f"manifests/{out.digest}")
            else:
                out.digest = out.index_digest
            out.size = sum(int(layer.get("size", 0)) for layer in doc.get("layers", []))
            cfg_digest = (doc.get("config") or {}).get("digest")
            if cfg_digest:
                cfg, _ = self._json(ref, f"blobs/{cfg_digest}", accept="*/*")
                out.labels = ((cfg.get("config") or {}).get("Labels")) or {}
                out.created = cfg.get("created", "")
            out.labels = {**(doc.get("annotations") or {}), **out.labels}
            if check_signatures and out.index_digest.startswith("sha256:"):
                self.signature_artifacts(ref, out, index)
        except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
            out.error = f"{type(e).__name__}: {e}"[:200]
        return out


SOURCE_KEYS = ("org.opencontainers.image.source", "org.opencontainers.image.url", "org.label-schema.vcs-url")
REVISION_KEYS = ("org.opencontainers.image.revision", "org.label-schema.vcs-ref", "vcs-ref")


def github_repo(labels: dict) -> str:
    """owner/name of the GitHub repo an image claims to come from, or ''."""
    for k in SOURCE_KEYS:
        v = labels.get(k, "")
        m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#:]|$)", v)
        if m:
            return f"{m.group(1)}/{m.group(2)}"
    return ""


def revision(labels: dict) -> str:
    """Commit SHA from revision labels, or embedded in the source URL (``/commit/<sha>``, ``#<sha>``)."""
    for k in REVISION_KEYS:
        v = labels.get(k, "")
        if re.fullmatch(r"[0-9a-f]{7,40}", v or ""):
            return v
    for k in SOURCE_KEYS:
        m = re.search(r"(?:/commit/|/tree/|#)([0-9a-f]{40})\b", labels.get(k, ""))
        if m:
            return m.group(1)
    return ""
