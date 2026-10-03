# Limitations and roadmap

## Limitations

- **Cluster state.** The CLI reads manifests or `kubectl get -o yaml` output; there is no continuous kube-API watcher. Helm charts are rendered with default values.
- **Provenance trust.** Certificate-verified provenance exists only for the CI demo image in the live job. For the 86 third-party images, signatures and attestations (cosign tags, Sigstore bundles, in-toto referrers) are only detected, never verified, and the commit edge rests on OCI labels confirmed by the GitHub API; labels can be forged, which is exactly what the live `forged` control shows.
- **Runtime evaluation.** The Tetragon sample has 30 labelled events and the rules were written with them in view (in-sample). The live job is a scripted check with three known actions and one commit, not a held-out detection study, and its ablation arms are constructed controls, not rates. On the public sample 0 of 18 incidents reach a commit, because those images carry no provenance; runtime → commit is shown only on the live job.
- **Container syscall data.** LID-DS is distributed only through Proton Drive shares (client-side encrypted, no direct URL) and no public CB-DS download exists, so neither could be fetched non-interactively. The substitute recorded in CI is small and scripted (5 attack-shaped actions, 14 distinct normal sequences, `strace` names without arguments): it separates action types, not intrusions. ADFA-LD is host-based, not container workloads.
- **Weak syscall models.** STRATUM's novelty model is not better than STIDE: it loses on the official ADFA-LD split and on the container traces and wins only on random ADFA-LD re-splits. The Kim et al. LSTM reproduction does not reach the paper (0.812 vs 0.928).
- **Scan budget.** The largest images (for example Jenkins, argo-cd and the Falco driver loader) were skipped.
- **Prevention.** The replay models egress by CIDR only (no DNS, ports or L7); the live job checks one external and one in-cluster destination.
- **PSS semantics.** Only v1.37 semantics; the Gatekeeper export covers 8 of 19 checks.
- **Platforms.** The container image is linux/amd64 only.
- **Not done:** a mean-time-to-root-cause study with people; VANTAGE and ROOTLINE are not integrated; the console is a no-build page rather than React.

## Roadmap

- [x] Live kind + Tetragon + Gatekeeper job with certificate-derived trace-to-commit and negative controls
- [x] Gatekeeper `ConstraintTemplate` export, enforcing on a live Gatekeeper
- [x] Ablation on the live runs: runtime-only vs +cluster state vs +label provenance vs +certificate provenance (A0-A4), with a forged-label control, 5 per-run-signed jobs
- [x] Container syscall traces recorded in Actions over 5 runs (`strace` in Docker); LID-DS and CB-DS are not fetchable non-interactively
- [ ] Richer container syscall data: Tetragon raw syscalls with arguments, more and unscripted actions, or DongTing fetched in Actions
- [x] Detect cosign v3 Sigstore bundles, in-toto referrers and BuildKit attestations
- [ ] Verify signatures and SLSA provenance for third-party images (sigstore-python)
- [ ] Continuous kube-API watch plus Tetragon gRPC streaming
- [ ] Labelled benign/attack action sets in the live job for per-rule FPR
- [ ] Rego for the remaining 11 PSS checks; per-version PSS semantics
- [ ] Mean-time-to-root-cause user study: STRATUM vs siloed tools

