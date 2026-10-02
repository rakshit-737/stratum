# STRATUM

**STRATUM joins each runtime eBPF alert, edge by edge and with checkable evidence, to the running image digest, the Sigstore-certified CI run and commit that built it, and the named Zero-Trust control that should have stopped it.**
On a live kind + Tetragon cluster in CI, 55 of 55 alerts over 5 independent runs trace to the right commit read
from the signing certificate, while an unsigned look-alike workload traces to none.

[Try it in 60 seconds](#try-it-in-60-seconds){ .md-button .md-button--primary }
[How it works](how-it-works.md){ .md-button }
[Evaluation](benchmarks.md){ .md-button }
[Console demo](live-demo.md){ .md-button }

![Live-cluster console: incidents traced to the CI run and commit](figures/console_live_incidents.png)

STRATUM is an open mini-CNAPP, not a Wiz. It puts `commit → CI build → image → Kubernetes workload → pod →
runtime event` into one graph and checks 13 Zero-Trust controls against it, in Python and mirrored in Rego
(also exported as a Gatekeeper ConstraintTemplate).

## Headline results

| What | Result |
|---|---|
| Live cluster: runtime alert → commit from the Sigstore certificate | **55 / 55** incidents over 5 kind clusters (Wilson 95% CI 0.93-1.00); unsigned control 0 / 5 traced |
| Policy-as-prevention on the live cluster | `stratum prevent` egress policy blocks the external sink 5 / 5, in-cluster traffic kept 5 / 5 |
| Exported Gatekeeper template, live | denies the privileged pod 5 / 5 |
| PSS engine vs upstream conformance fixtures | F1 1.000 (a conformance gate) |
| Rego mirror vs Python, full real corpus | 292 / 292 identical findings |
| 87 workloads from 31 real projects traced pod → verified commit | 23 / 87 (CI 0.18-0.37); 0 of 18 public Tetragon incidents reach a commit |
| ADFA-LD syscall models | STIDE n=6 AUC 0.827 edges novelty n=5 0.822 (paired diff +0.005, significant) |
| Reproduction of Kim et al. 2016 LSTM ensemble | not reproduced: AUC 0.709 vs 0.928 published |

Every number, with its method and caveats, is on the [Evaluation](benchmarks.md) page; the
[Limitations](limitations.md) page lists what is not shown.

## Try it in 60 seconds

```bash
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/stratum:latest   # console on http://127.0.0.1:8000
```

or

```bash
git clone https://github.com/rakshit-737/stratum && cd stratum
pip install -e . && python -m stratum demo
```

Then: [Getting started](getting-started.md) to check your own manifests, and [Reproduce](reproduce.md) to
regenerate every result.

> Lab-only, defensive tool. It reads public manifests, registry metadata and published event logs, and it never
> changes a cluster. See [Security](security.md).
