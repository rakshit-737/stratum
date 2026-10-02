# ADR 0003: Re-implement Pod Security Standards and test them against upstream fixtures

- Status: accepted (v0.2); still in force in v1.x
- Date: 2026-09-26

## Context

v0.1 judged workload hardening with three booleans: privileged, root and hostNetwork. Real charts fail in subtler ways, such as a missing `runAsNonRoot`, capabilities that are not dropped, an unset `seccompProfile`, or hostPath volumes. The Kubernetes Pod Security Standards (PSS) are the community baseline for this. `k8s.io/pod-security-admission` ships labelled pass/fail fixtures for every check and every version.

## Decision

Port the 19 checks (12 baseline, 7 restricted-only) to pure Python with v1.37 semantics. That includes the user-namespace relaxations, the Windows exemptions, the 1.34 probe-host check and the 1.37 sysctl allow-list.

Score the port against the upstream fixtures with `stratum bench pss`. Keep a small subset of those fixtures in `tests/fixtures/pss` so CI covers both levels.

## Consequences

- On the v1.37 fixtures (148 files) STRATUM reaches F1 = 1.000 at both levels. The v0.1 heuristic reaches recall 0.147 (baseline) and 0.105 (restricted). A faithful port should score 1.0, so this is a conformance and regression gate, not a claim about detection skill.
- Only the latest semantics are implemented, so older versions' fixtures would show version-specific differences. Pinning older semantics is on the roadmap.
