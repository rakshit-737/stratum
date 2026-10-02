### Build-provenance coverage for 86 real images

| hop | images | % |
|---|---:|---:|
| manifest resolved to digest | 86 | 100.0 |
| OCI source label -> GitHub repo | 43 | 50.0 |
| revision (label or source URL) | 27 | 31.4 |
| commit verified on GitHub | 25 | 29.1 |
| commit linked to a merged PR | 21 | 24.4 |
| cosign signature artefact | 32 | 37.2 |
| cosign attestation artefact | 28 | 32.6 |

Workloads traced end-to-end (pod -> image -> verified commit): **23 / 87** (Wilson 95% CI [0.1831, 0.3656]); 19 of them on to a merged PR.

Signature context: 32/86 images carry a cosign signature artefact (Wilson 95% CI [0.2775, 0.4777]), against 1.0% of Docker Hub tags signed in 2023 (Schorlemmer et al. 2024, arXiv:2401.14635, Table 6 (DCT signatures; different population)). This corpus is curated CNCF projects, so the gap is expected; presence of a signature is not a verified signature.

Baseline, the `image tag == git tag` heuristic: of 25 images with a verified embedded commit, a same-named git tag existed for 21 and pointed at the embedded commit for 21.
