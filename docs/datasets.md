# Datasets

Everything is downloaded by `scripts/` into `$STRATUM_DATA` (default `./data`, git-ignored), and each file is verified against a SHA-256 checksum:

- **Pinned checksums** are in `scripts/checksums.json` and are checked on every run.
- **Upstream checksums** (the tool binaries) are fetched from each project's published checksum file.
- **Daily-changing feeds** (KEV, Helm renders) get their hash recorded in `$STRATUM_DATA/MANIFEST.json` instead.

| # | Dataset | Version / pin | Size | Licence | Script |
|---|---|---|---:|---|---|
| 1 | Kubernetes Pod Security Admission test fixtures | `kubernetes/pod-security-admission` tag v0.37.1 | 0.3 MB (4,537 YAML) | Apache-2.0 | `download_pss.py` |
| 2 | Upstream install manifests (21 projects) | pinned release tags, see `download_manifests.py` | 19 MB | Apache-2.0 (each project) | `download_manifests.py` |
| 3 | Helm charts rendered with default values (10 charts) | pinned chart versions, see `render_helm.py` | 3 MB | Apache-2.0 (most), MPL-2.0 (vault-helm) | `render_helm.py` |
| 4 | Image provenance (86 images) | registry + GitHub API snapshot | 0.3 MB | metadata only | `resolve_provenance.py` |
| 5 | Trivy scans of those images | Trivy 0.74.0, trivy-db v2 | ~1.5 GB layer cache | Apache-2.0 (tool/DB) | `scan_images.py` |
| 6 | CISA Known Exploited Vulnerabilities | daily feed; version recorded | 1.5 MB | Public domain (US Gov) | `download_kev.py` |
| 7 | Cilium Tetragon sample events | `cilium/tetragon` @ 1911464 | 0.1 MB (33 files) | Apache-2.0 | `download_tetragon.py` |
| 8 | ADFA-LD syscall traces | mirror `verazuo/a-labelled-version-of-the-ADFA-LD-dataset` @ 68bedf5 | 2.4 MB zip | UNSW Canberra, free for research, cite below | `download_adfa.py` |

Tools (not data): Trivy 0.74.0, Syft 1.52.0, Helm 4.3.0 and OPA 1.21.0 are fetched by `download_tools.py` into `$STRATUM_DATA/tools`.

## What each dataset is used for

1. **PSS fixtures** are the ground truth for the policy engine. Each YAML is a Pod that the upstream admission plugin must accept (`pass/`) or reject (`fail/`) at a given level and version. The filename prefix names the violated check.
2. **Manifests** and 3. **Helm renders** stand in for the *cluster state* of a notional cluster running all 31 projects in their default configuration. They feed the collector (`stratum/k8s.py`), the posture benchmark and the lifecycle graph.
4. **Provenance** holds the image -> digest -> OCI labels -> GitHub commit -> PR edges for every image the manifests reference.
5. **Trivy** plus 6. **KEV** provide the vulnerability and "shell present" facts per image, and the base OS release (family + version) used for blast radius.
7. **Tetragon events** are real runtime sensor output. They include an attack chain from *Security Observability with eBPF* (Isovalent, 2022): a privileged pod, `nsenter` into the host, a Merlin C2 agent, then exfiltration with 7z, scp and an ssh tunnel. Our per-file labels are in `benchmarks/labels/tetragon.json`.
8. **ADFA-LD** is the standard host IDS benchmark: 833 normal training traces, 4,372 normal validation traces and 746 attack traces in 6 families. It is used to evaluate the runtime anomaly models.

## Citations

- G. Creech and J. Hu. "Generation of a new IDS test dataset: Time to retire the KDD collection." IEEE WCNC 2013.
- G. Creech and J. Hu. "A Semantic Approach to Host-Based Intrusion Detection Systems Using Contiguous and Discontiguous System Call Patterns." IEEE Transactions on Computers 63(4), 2014.
- S. Forrest, S. Hofmeyr, A. Somayaji, T. Longstaff. "A Sense of Self for Unix Processes." IEEE S&P 1996 (STIDE).
- Kubernetes SIG Auth. *Pod Security Standards*, https://kubernetes.io/docs/concepts/security/pod-security-standards/
- CISA. *Known Exploited Vulnerabilities Catalog*, https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- J. Salazar and N. R. Ivánkó. *Security Observability with eBPF*, O'Reilly / Isovalent 2022 (Tetragon sample events).

## Safety notes

- None of the datasets contains executables. ADFA-LD holds integer syscall numbers. The Tetragon files are JSON logs, and the "Merlin agent" appears only as process names and arguments.
- Image scanning pulls public images as tarballs for static analysis. Nothing is run.
