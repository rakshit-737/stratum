# ADR 0002: Python policy engine, mirrored in Rego and diffed in CI

- Status: accepted (v0.2)
- Date: 2026-09-26

## Context

The spec asks for Zero-Trust checks "as OPA policies evaluated against the graph". But if every test run and every user needed an `opa` binary, STRATUM would be harder to install on a laptop or on Windows. Rego, on the other hand, is what platform teams deploy (Gatekeeper, Conftest, OPA sidecars).

## Decision

- `stratum/policy.py` is the reference implementation. Every rule maps to a named control (`ZT-NET-01` ... `ZT-IMG-03`) with a severity and an external reference (NIST SP 800-207, CIS Kubernetes Benchmark, SLSA, CISA BOD 22-01).
- `policies/stratum.rego` (Rego v1) implements the same rules over the same JSON document (`stratum export --format rego-input`).
- `stratum opa-check` evaluates both engines and diffs the `(control, subject)` sets. CI runs it with OPA 1.21 on the synthetic scenario and on committed real-manifest fixtures. On the full real corpus both engines produce the same 292 findings.

## Consequences

- The Python engine needs no extra binaries. The Rego can be dropped into OPA or Conftest pipelines.
- There are now two implementations to keep in step. The CI diff turns any drift into a failing build.
- The Pod Security Standards checks are not re-implemented in Rego. Rego takes their results (`pss_violations`, `pss_level`) as input. Upstream PSA, Kyverno and Gatekeeper already enforce PSS at admission. What STRATUM adds is linking those results to the lifecycle.
