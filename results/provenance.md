### Build-provenance coverage for 86 real images

| hop | images | % |
|---|---:|---:|
| manifest resolved to digest | 86 | 100.0 |
| OCI source label -> GitHub repo | 43 | 50.0 |
| OCI revision label | 27 | 31.4 |
| commit verified on GitHub | 25 | 29.1 |
| commit linked to a merged PR | 21 | 24.4 |
| cosign signature artefact | 32 | 37.2 |
| cosign attestation artefact | 28 | 32.6 |

Workloads traced end-to-end (pod -> image -> verified commit): **23 / 87**.

Baseline, the `image tag == git tag` heuristic: of 25 images with a verified embedded commit, a same-named git tag existed for 21 and pointed at the embedded commit for 21.
