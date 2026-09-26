# Security Policy

## Intended use

STRATUM is a defensive portfolio and research tool. Use it only on clusters and data you own or are authorised to assess. Keep attack emulation in an isolated local lab such as kind or minikube.

## Reporting a vulnerability

Open a private GitHub security advisory on this repository, or email the maintainer. Please do not file public issues for vulnerabilities. We aim to acknowledge reports within 7 days.

## Design choices

- The only runtime dependency is PyYAML. The API, benchmarks and Neo4j support are optional extras.
- Input parsing:
  - JSON is parsed with the stdlib `json` module.
  - YAML is parsed with a `SafeLoader` subclass. It adds one extra constructor, which reads the YAML 1.1 `=` tag as a plain string.
  - Nothing uses pickle or `eval`.
- The analysis path (`analyze`, `trace`, `blast`, `prevent`, the API) makes no network connections and never calls anything that changes a cluster. Generated NetworkPolicies are printed for a human to review. They are never applied.
- Only the data scripts (`scripts/`) touch the network:
  - They make anonymous, read-only requests to public registries, GitHub and CISA.
  - They verify SHA-256 checksums.
  - They pull images only so that Trivy can read them as files. Nothing is executed.
- The Docker image runs as UID 10001. The compose file drops all capabilities and mounts the corpus read-only.
