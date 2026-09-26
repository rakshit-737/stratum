# Limitations and roadmap

## Limitations

- **Static cluster state.** v0.2 reads manifests (or `kubectl get -o yaml` output). There is no live watcher yet. Helm charts are rendered with default values.
- **Provenance trust.** cosign signatures and attestations are checked for presence, not verified cryptographically. An image → commit edge requires the commit to exist in the named repo, but the labels themselves could be forged. The fix is to verify SLSA provenance (roadmap).
- **Small runtime set.** The runtime evaluation has only 30 labelled events, and the rules were written with them in view. No public, labelled, container-native runtime dataset was downloadable here: LID-DS is behind an interactive file host.
- **Weak syscall models on ADFA-LD.** They are also not container workloads.
- **Scan budget.** Image scans are budget-limited because of bandwidth. The largest images (for example Jenkins, argo-cd and the Falco driver loader) were skipped; see the scans section.
- **Simulated egress enforcement.** It models CIDR only (no DNS, ports or L7).
- **PSS semantics.** Only the latest (v1.37) semantics are implemented. The Gatekeeper export covers 8 of 19 checks and has not been applied to a live Gatekeeper install (no cluster on the dev machine).
- **Needs hardware or people.** Live kube-API/Tetragon collectors need a running Linux cluster with eBPF; the mean-time-to-root-cause study needs human participants. Both stay on the roadmap.

## Roadmap

- [ ] Live collectors: a kube API watch plus Tetragon gRPC streaming
- [ ] Verify cosign signatures and SLSA/in-toto provenance (sigstore-python); parse BuildKit attestations
- [ ] Container-native runtime evaluation (LID-DS 2021, CB-DS) and sequence models
- [ ] Mean-time-to-root-cause user study: STRATUM vs siloed tools (the spec's research question)
- [x] Gatekeeper `ConstraintTemplate` export (`stratum gatekeeper`) for the 8 field-test PSS checks, Rego diffed against Python in tests
- [ ] Rego for the remaining 11 PSS checks (AppArmor, SELinux, seccomp, sysctls, ...)
- [ ] Per-version PSS semantics; RBAC path analysis in Neo4j

