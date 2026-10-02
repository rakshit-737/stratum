# Threat Model

## Scope

STRATUM consumes the following inputs and produces findings and incidents:

- Kubernetes state: manifests or `kubectl get -o yaml`.
- Image provenance: registry metadata and the GitHub API.
- Vulnerability scans: Trivy output and CISA KEV.
- Runtime events: Tetragon JSON.

STRATUM runs offline on a downloaded real-data corpus or on the synthetic scenario; a CI job (`live.yml`) also runs it against a live kind cluster with Tetragon and Gatekeeper.

## Threats STRATUM helps defend against

| Threat | Signal | Control |
| --- | --- | --- |
| Shell / RCE in a container | `exec` of a shell or network tool | ZT-IMG-02 |
| Container escape to the node | `nsenter -t 1 ...` from a privileged pod | ZT-WL-01 |
| C2 / exfiltration egress | `connect` to a non-private address | ZT-NET-01 |
| Credential theft | SA token, keystore or ssh key read | ZT-ID-02, ZT-ID-04 |
| Persistence via system files | write to `/etc/passwd`, `/etc/shadow`, ... | ZT-WL-02 |
| Untrusted or unmanaged workload (drift) | no verified build provenance; container outside Kubernetes | ZT-PROV-01 |
| Mutable image references | tag instead of `@sha256` digest | ZT-PROV-03 |
| Unsigned artefacts | no cosign signature artefact | ZT-PROV-02 |
| Vulnerable / KEV-listed images | Trivy CVEs, KEV join, blast radius by base OS | ZT-IMG-01, ZT-IMG-03 |
| Over-privileged workload or identity | PSS violations, cluster-admin, cluster-wide secret read | ZT-WL-01/02, ZT-ID-03/04 |

## Threats to STRATUM itself

| Threat | Impact | Mitigation (current / planned) |
| --- | --- | --- |
| Forged OCI labels (fake source/revision) | Wrong root-cause commit | The commit must exist in the named repo (GitHub API). Planned: verify SLSA attestations and cosign signatures cryptographically. |
| Tampered downloads | Poisoned corpus | SHA-256 pins in `scripts/checksums.json`; upstream checksum files for tools |
| Attacker evades the rules (renamed binary, internal pivot) | Missed detection | Novelty scoring as a second layer; documented gap. ADFA-LD shows unsupervised models alone are weak (`results/adfa.md`). |
| Baseline poisoning | Novelty model learns the attack as normal | Baseline only from a trusted window; drift checks planned |
| Hostile YAML / JSON | Parser abuse | Safe loaders only; no `eval` or pickle |
| Sensitive data in reports | Leakage | Reports hold IDs and metadata, never secret values. Tetragon arguments are shown as captured, so redact them before sharing. |

## Assumptions and limitations

- The graph is only as good as its collectors. The CLI reads static manifests or `kubectl get -o yaml`; there is no continuous kube-API watcher.
- Egress enforcement is simulated and covers IP/CIDR only. It does not model ports, DNS or L7.
- Helm charts are rendered with default values, which may differ from production.
- The perfect PSS conformance score measures faithfulness to the upstream implementation. It is not evidence of real-world detection skill.
