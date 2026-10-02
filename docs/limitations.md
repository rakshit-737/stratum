# Limitations and roadmap

## Limitations

- **Cluster state.** The CLI reads manifests or `kubectl get -o yaml` output; there is no continuous kube-API watcher. Helm charts are rendered with default values.
- **Provenance trust.** Certificate-verified provenance exists only for the CI demo image in the live job. For the 86 third-party images, cosign signatures and attestations are only detected, and the commit edge rests on OCI labels confirmed by the GitHub API; labels could be forged.
- **Runtime evaluation.** The Tetragon sample has 30 labelled events and the rules were written with them in view (in-sample). The live job is a scripted check with three known actions, not a held-out detection study. On the public sample 0 of 18 incidents reach a commit, because those images carry no provenance; runtime → commit is shown only on the live job.
- **No container syscall dataset.** LID-DS is distributed only through Proton Drive shares (client-side encrypted, no direct URL) and no public CB-DS download exists, so neither could be fetched non-interactively. ADFA-LD is host-based, not container workloads.
- **Weak syscall models**, and the Kim et al. LSTM reproduction falls well short of the paper (CPU-limited training).
- **Scan budget.** The largest images (for example Jenkins, argo-cd and the Falco driver loader) were skipped.
- **Prevention.** The replay models egress by CIDR only (no DNS, ports or L7); the live job checks one external and one in-cluster destination.
- **PSS semantics.** Only v1.37 semantics; the Gatekeeper export covers 8 of 19 checks.
- **Not done:** a mean-time-to-root-cause study with people; VANTAGE and ROOTLINE are not integrated; the console is a no-build page rather than React.

## Roadmap

- [x] Live kind + Tetragon + Gatekeeper job with certificate-derived trace-to-commit and negative controls
- [x] Gatekeeper `ConstraintTemplate` export, enforcing on a live Gatekeeper
- [ ] Verify cosign signatures and SLSA provenance for third-party images (sigstore-python); parse BuildKit attestations
- [ ] Continuous kube-API watch plus Tetragon gRPC streaming
- [ ] Labelled benign/attack action sets in the live job for per-rule FPR
- [ ] Rego for the remaining 11 PSS checks; per-version PSS semantics
- [ ] Mean-time-to-root-cause user study: STRATUM vs siloed tools

