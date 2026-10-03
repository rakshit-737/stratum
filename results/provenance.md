### Build-provenance coverage for 86 real images

| hop | images | % |
|---|---:|---:|
| manifest resolved to digest | 86 | 100.0 |
| OCI source label -> GitHub repo | 43 | 50.0 |
| revision (label or source URL) | 27 | 31.4 |
| commit verified on GitHub | 25 | 29.1 |
| commit linked to a merged PR | 21 | 24.4 |
| signature artefact (cosign / Sigstore) | 39 | 45.3 |
| attestation artefact (cosign / Sigstore / in-toto) | 44 | 51.2 |
| BuildKit attestation (unsigned) | 31 | 36.0 |

Workloads traced end-to-end (pod -> image -> verified commit): **23 / 87** (Wilson 95% CI [0.1831, 0.3656]); 19 of them on to a merged PR.

Clustering: the 23 traced workloads come from 11 of 31 projects (Wilson 95% CI [0.2112, 0.5305]) and 22 images, so the workload-level interval above treats correlated workloads as independent; the project-level rate is the safer one.

Signature context: 39/86 images carry a signature artefact (Wilson 95% CI [0.3525, 0.5584]; formats {'cosign-tag': 32, 'sigstore-bundle': 7}), against 1.0% of Docker Hub tags signed in 2023 (Schorlemmer et al. 2024, arXiv:2401.14635, Table 6 (DCT signatures; different population)). This corpus is curated CNCF projects, so the gap is expected; presence of a signature is not a verified signature.

Baseline, the `image tag == git tag` heuristic. Coverage: it names a commit for 36/86 images (Wilson 95% CI [0.32, 0.5242]) against 25/86 for STRATUM's verified embedded revision (Wilson 95% CI [0.2053, 0.394]). Where both answer (21 images) they agree on 21; the heuristic gives no answer for 4 of STRATUM's 25, and its other 15 answers cannot be checked against an embedded revision. The trade-off is coverage against verifiability: a tag name is a mutable pointer, not evidence of what was built.
