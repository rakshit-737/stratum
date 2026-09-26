# ADR 0006: Deterministic runtime rules first, anomaly scoring second

- Status: accepted (v0.2)
- Date: 2026-09-26

## Context

The spec's principle is "AI flags, the graph explains". On ADFA-LD, unsupervised syscall models reach a ROC-AUC of about 0.80 to 0.83 (`results/adfa.md`). That is useful for ranking, but far too noisy to page on: TPR at 1% FPR is at most 0.18.

## Decision

- Detections come from nine named rules. Each rule maps to the Zero-Trust control that should have prevented the event:
  - shell
  - container escape (`nsenter -t 1`)
  - service-account token read
  - credential-file read
  - write to system auth files
  - unmanaged container
  - execution from a temp directory
  - network tools
  - external egress
- The per-workload novelty model runs only when a baseline window exists, and its detections are `medium` severity.
- The syscall models (STIDE, n-gram surprisal, Isolation Forest) are provided and benchmarked, but not wired to alerting.

## Consequences

- On the real Tetragon attack chain the v0.2 rules reach recall 0.80 at precision 0.89. The v0.1 rules reached recall 0.40 at precision 0.80. The v0.2 rules were written with these events in view, so this demonstrates coverage; it is not a held-out result.
- Better anomaly models (sequence models, LID-DS container traces) are future work. They would not change the incident pipeline.
