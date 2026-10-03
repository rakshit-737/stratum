# Security Policy

## Intended use

STRATUM is a defensive portfolio and research tool. Use it only on clusters and data you own or are authorised to assess. Keep attack emulation in an isolated local lab such as kind or minikube.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting: [open a draft security advisory](https://github.com/rakshit-737/stratum-cloud-security/security/advisories/new) (Security tab, "Report a vulnerability"). Please do not file public issues for vulnerabilities. We aim to acknowledge reports within 7 days.

The repository has Dependabot alerts and security updates, secret scanning and push protection enabled.

## Design choices

- The only runtime dependency is PyYAML. The API, benchmarks and Neo4j support are optional extras.
- Input parsing:
  - JSON is parsed with the stdlib `json` module.
  - YAML is parsed with a `SafeLoader` subclass. It adds one extra constructor, which reads the YAML 1.1 `=` tag as a plain string.
  - Nothing uses pickle or `eval`.
- The analysis path (`analyze`, `trace`, `blast`, `prevent`, the API) makes no network connections and never calls anything that changes a cluster. Generated NetworkPolicies are printed for a human to review. STRATUM never applies them; only the live CI job applies one, to its own throwaway kind cluster.
- Only the data scripts (`scripts/`) touch the network:
  - They make read-only requests to public registries, GitHub and CISA. GitHub API calls are anonymous unless you set `STRATUM_GITHUB_TOKEN` (a fine-grained token with public read-only access is enough); the gh CLI token is never picked up automatically.
  - The live CI job (`.github/workflows/live.yml`) publishes, per job, a signed demo image (`run-<nonce>`) and a deliberately unsigned negative-control image (`forged-<nonce>`, labelled as such) to the public package `ghcr.io/rakshit-737/stratum-live-demo`, and a keyless signature entry to the public Sigstore Rekor log, on every push to main and on every dispatch, using the job token (`packages: write`, `id-token: write`). Both images are `busybox` running `sleep infinity`. Only benign scripted actions run, inside the ephemeral runner; artefacts are kept 90 days and contain only the demo namespace.
  - They verify SHA-256 checksums.
  - They pull images only so that Trivy can read them as files. Nothing is executed.
- The Docker image runs as UID 10001. The compose file drops all capabilities and mounts the corpus read-only.
