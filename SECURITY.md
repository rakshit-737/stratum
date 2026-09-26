# Security Policy

## Intended use
STRATUM is a defensive portfolio and research tool. Use it only on clusters and data you own or are authorised to assess. Attack emulation belongs in an isolated local lab such as kind or minikube.

## Reporting a vulnerability
Open a private GitHub security advisory on this repository, or email the maintainer. Please do not file public issues for vulnerabilities. We aim to acknowledge reports within 7 days.

## Design choices
- The runtime has no third-party dependencies (stdlib only).
- Input is JSON parsed with the `json` module only. There is no pickle, `eval` or unsafe YAML.
- The tool never makes network connections and never runs cluster-mutating calls. Generated NetworkPolicies are printed for a human to review, not applied.
