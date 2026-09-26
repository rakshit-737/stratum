# STRATUM

**An open mini-CNAPP.** STRATUM puts `commit → CI build → image → Kubernetes workload → pod → runtime event` into one graph and checks 13 Zero-Trust controls against it. The controls are written in Python and mirrored in Rego. When a runtime alert fires, STRATUM traces it back to the commit and PR that shipped the code and names the control that should have stopped it. It also lists every other workload built on the same base OS release (the blast radius).

v0.2 runs on real public data:

- 31 real open-source install manifests and Helm charts (87 workloads)
- 86 real container images, resolved to verified GitHub commits and scanned with Trivy and CISA KEV
- the upstream Kubernetes Pod Security Admission conformance fixtures
- real Cilium Tetragon events from a container-escape and C2 attack chain
- the ADFA-LD syscall benchmark

> Lab-only, defensive tool. It reads public manifests, registry metadata and published event logs, and it never changes a cluster. See [Safety](security.md).


## Where to go next

- [Getting started](getting-started.md): install, demo, check your own manifests
- [Architecture](architecture.md): the lifecycle graph, 13 Zero-Trust controls, Rego mirror
- [Benchmarks](benchmarks.md): real-data results with confidence intervals
- [Live demo](demo.md): the incident console on a static real-data snapshot
- [Limitations & roadmap](limitations.md)
