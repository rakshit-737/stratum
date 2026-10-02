# ADR 0005: Real-data corpus and safety boundaries

- Status: accepted (v0.2); still in force in v1.x
- Date: 2026-09-26

## Decision

STRATUM v0.2 is evaluated only on public, redistributable data. Scripts fetch everything with SHA-256 checks and store it outside git (`$STRATUM_DATA`).

| Input | Source | Why |
|---|---|---|
| Cluster state | 21 upstream release manifests, plus 10 Helm charts rendered with default values | The defaults that users actually `kubectl apply` |
| Policy ground truth | kubernetes/pod-security-admission v0.37.1 fixtures | Labelled pass/fail for every PSS check |
| Build provenance | Registry manifests and configs, plus the GitHub commits API | Real image -> commit links |
| Vulnerabilities | Trivy 0.74 scans (smallest image first, within a download budget), plus CISA KEV | Real CVE exposure and blast radius |
| Runtime | Cilium Tetragon public sample events (container escape, C2 agent) | The real sensor schema and a real attack chain |
| Anomaly model | ADFA-LD syscall traces | The standard public HIDS benchmark |

## Safety

- No malware binaries, exploit code or live attack traffic. ADFA-LD contains integer syscall sequences, and the Tetragon samples are JSON event logs.
- Images are pulled only from public registries, and only as files for Trivy to read. Nothing is executed.
- Registry and GitHub access is read-only and anonymous. A GitHub token is optional and only raises rate limits.

## Consequences

- Bandwidth limits the scans, so they run within a download budget. Skipped images are listed in `scans/index.json` and in the results.
- Rendering Helm charts with default values is a known bias. Production values usually harden them, or sometimes weaken them.
