# ADR 0007: Certificate-derived provenance for the live pipeline

- Status: accepted (on main after v1.0.0)
- Date: 2026-10-02

## Context

ADR 0004 builds `image -> commit` edges from OCI labels confirmed by the GitHub API, and only records
whether a signature artefact exists. In the live CI job that is circular or forgeable: the workflow
knows `github.sha`, and anyone who can build an image can write the right `org.opencontainers.image.revision`
label.

## Decision

- For images signed by the STRATUM pipeline, the `image -> build -> commit` edges come only from
  `cosign verify -o json` (keyless, GitHub OIDC, identity pinned to the workflow): the commit from the
  Fulcio extension OID 1.3.6.1.4.1.57264.1.3, the repository from .1.5, the ref from .1.6 and the CI run
  from the Run Invocation URI (.1.21) inside the Rekor bundle's certificate (`stratum/sigstore.py`).
- A signature joins a workload only on the exact image digest. `github.sha` is passed only as the
  expected value of the assertion; `github.run_id` must equal the run named by the certificate.
- Every live run builds its own image (a per-run nonce label gives a unique digest) and signs it, so
  runs do not share one certificate.
- Two negative controls: an upstream image the pipeline never built (`drift`) and an unsigned image
  built from the same Dockerfile with the right revision label (`forged`). Neither may reach a commit.
- The A0-A4 ablation in `stratum/live.py` scores runtime-only, +cluster state, +label provenance,
  +certificate provenance and a repository-level (not digest-exact) certificate join on the same events.

## Consequences

- A label or a workflow variable can no longer make an alert reach a commit in the live check.
- Third-party images still use ADR 0004; their signatures are not verified.
- cosign is pinned to v2 because v3's `verify -o json` drops the Fulcio claims this parser reads.
