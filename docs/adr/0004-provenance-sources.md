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
- Record whether a cosign signature artefact (`sha256-<digest>.sig`) and an attestation artefact (`.att`) exist. For third-party images STRATUM does **not** verify them cryptographically (for the live pipeline see ADR 0007). `ZT-PROV-02` therefore means "no signature artefact published", not "signature invalid".
- Keep the tag heuristic as a measured baseline (`results/provenance.md`). It is never used to create an edge.

## Consequences

- The trace is honest. For an image without verifiable metadata the trace stops at the image node, and the incident reports "no pipeline provenance" (`ZT-PROV-01`).
- Coverage depends on how well upstream projects label their images. The provenance benchmark reports this as a coverage funnel, which is a useful supply-chain metric in its own right.
- Next: parse SLSA provenance from attestations and verify signatures with sigstore-python.
