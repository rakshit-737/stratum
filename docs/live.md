# Live CI: kind + Tetragon + Gatekeeper + cosign

`.github/workflows/live.yml` runs on every push to `main`. It replaces the "no cluster on this machine"
gap with a real Kubernetes cluster on the GitHub runner. Everything happens inside the runner; the only
outside hosts are image/chart registries (GHCR, Docker Hub, helm.cilium.io, the Gatekeeper chart repo)
and Sigstore (Fulcio/Rekor) for keyless signing.

1. **Build + sign.** `deploy/live/Dockerfile` (busybox, OCI `revision` label = the commit) is pushed to
   `ghcr.io/rakshit-737/stratum-live-demo:<sha>`. `cosign sign` signs the digest keyless with the job's
   GitHub OIDC token. `cosign verify` must pass with the exact workflow identity
   (`https://github.com/<workflow_ref>`, issuer `token.actions.githubusercontent.com`), and a wrong
   identity must fail (negative control).
2. **Cluster.** kind, Tetragon (Helm chart 1.7.1) with `deploy/live/tracingpolicy.yaml` (`fd_install` on
   files ending in `/token`, `tcp_connect`), and OPA Gatekeeper 3.20.0.
3. **Admission.** `stratum gatekeeper --action deny` output is applied. The privileged `hostPID` pod in
   `deploy/live/denied-pod.yaml` must be rejected by the `stratum-pss-restricted` constraint, and the
   two demo deployments (PSS restricted) must be admitted.
4. **Actions.** `deploy/live/actions.sh` runs benign but attack-shaped commands in the `web` pod: a shell,
   `cat` of the projected service-account token (to `/dev/null`), and `nc` to an in-cluster `httpd` sink.
5. **Prevention.** `stratum prevent stratum-live` emits a default-deny egress NetworkPolicy that keeps
   in-cluster traffic. The job starts a second sink on the runner's `kind` Docker network (outside the cluster
   CIDRs) and checks that `nc` to it works before and fails after the policy, while the in-cluster sink stays
   reachable. kind enforces NetworkPolicy natively.
6. **Detection + trace.** The Tetragon export stream is filtered to the demo namespace and fed to
   `stratum live-check`, which joins the rendered manifests, the live pod list and the events, and builds the
   `image -> CI run -> commit` edges **only from the verified cosign certificate** (`stratum/sigstore.py`:
   commit OID `1.3.6.1.4.1.57264.1.3`, run-invocation URI). `github.sha` is passed only as the expected value.
   The job fails unless R-SHELL, R-SA-TOKEN and R-NETTOOL fire on the web pod, every web-pod incident traces to
   the expected commit, the event image digest equals the pushed digest, a connect to `:8080` is captured,
   Gatekeeper denied/admitted as expected, cosign verified, prevention behaved as predicted, and the
   **negative control** holds: a digest-pinned upstream busybox workload (`drift`) that runs the same command
   reaches no commit and names ZT-PROV-01.

`gatekeeper-result.json` derives `demo_admitted` from `kubectl rollout status`. Waits use `kubectl wait` and
polling loops that fail the job on timeout.

## Result: one signed image replayed in 5 clusters (results predate per-run signing)

--8<-- "results/live.md"

Each run is a separate job with its own kind cluster. Runs that build the same commit produce the same image
digest, so the certificate can name an earlier run of that commit (as in the example trace); the commit is what
is asserted. Re-run with `gh workflow run live.yml -f runs=5` and `scripts/aggregate_live.py`
([Reproduce](reproduce.md)).

## What the live run found

- **Gatekeeper rejected the exported template.** Gatekeeper parses template Rego as v0 and reported
  `invalid import: bad import: "rego.v1"`, so the constraint never enforced and the privileged pod was
  admitted (run 36318856374). The export now rewrites `import rego.v1` to `import future.keywords`. A test
  pins this.
- **Projected token paths.** The kernel resolves the token to
  `.../serviceaccount/..<timestamp>/token`, which the old substring rule (`serviceaccount/token`) would miss.
  R-SA-TOKEN now matches the `..<timestamp>/token` form.
- The first run's assertion failure did not fail the job because the step piped into `tee` without
  `pipefail`. Fixed.

- **cosign v3 changed `verify -o json`.** With cosign v3 the output no longer carries the Fulcio claims, so
  trace-to-commit dropped to 0/11 and the job failed (as it should). The job pins cosign v2.6.1.

The demo namespace has no egress NetworkPolicy until the prevention step, so the incidents also name ZT-NET-01;
the sink pod raised no detections. This is a scripted check of the pipeline on real sensor output, not a
detection-rate study: the three actions are known in advance and there is no labelled benign set.
