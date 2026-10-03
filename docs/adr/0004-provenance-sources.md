# ADR 0004: Build provenance from OCI labels + GitHub API; cosign presence only

- Status: accepted (v0.2); partly superseded by [ADR 0007](0007-certificate-derived-provenance.md) for images signed by the STRATUM pipeline
- Date: 2026-09-26

## Context

Tracing a running pod to a commit needs an image -> commit edge, including for images we did not build. There are three candidate sources:

1. OCI config labels `org.opencontainers.image.source` and `org.opencontainers.image.revision`. Most CI templates set them (docker/metadata-action, ko, goreleaser).
2. SLSA / in-toto provenance attestations (cosign `.att`, BuildKit attestation manifests).
3. A guess that the image tag equals a git tag.

## Decision

- Resolve every image with anonymous registry GETs (`stratum/registry.py`): tag -> linux/amd64 digest, config labels and compressed size. No layers are pulled.
- Accept an image -> commit edge only when all three hold:
  - the source label names a GitHub repo;
  - a revision is present, either as a label or as a SHA embedded in the source URL;
  - the GitHub API confirms that the commit exists in that repo.
- For each accepted edge, record the author, the commit message and the merged PR.
- Record whether a signature artefact and an attestation artefact exist, and in which format:
  - legacy cosign tags `sha256-<digest>.sig` / `.att`;
  - OCI 1.1 referrers (cosign v3 `--new-bundle-format`, in-toto attestations), read from the `sha256-<digest>`
    fallback-tag index (probed with HEAD first) or the referrers API. A Sigstore bundle is a signature when it
    carries no predicate type or cosign's own `https://sigstore.dev/cosign/sign/v1`, and an attestation otherwise;
  - BuildKit attestation manifests inside the image index, recorded separately because they are unsigned.

  For third-party images STRATUM does **not** verify any of them cryptographically (for the live pipeline see
  ADR 0007). `ZT-PROV-02` therefore means "no signature artefact published", not "signature invalid".
- Keep the tag heuristic as a measured baseline (`results/provenance.md`). It is never used to create an edge.

## Consequences

- The trace is honest. For an image without verifiable metadata the trace stops at the image node, and the incident reports "no pipeline provenance" (`ZT-PROV-01`).
- Coverage depends on how well upstream projects label their images. The provenance benchmark reports this as a coverage funnel, which is a useful supply-chain metric in its own right.
- Until 1.1.x only the legacy tags were probed, so cosign v3 bundle signatures were missed: STRATUM reported its
  own signed v1.1.0 image as unsigned. Re-checking the 86 corpus images (`scripts/recheck_signatures.py`) changed
  22 of them: signature artefacts 32 -> 39, attestation artefacts 28 -> 44.
- Next: parse SLSA provenance from attestations and verify signatures with sigstore-python.
