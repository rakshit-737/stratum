# Live CI: kind + Tetragon + Gatekeeper + cosign

`.github/workflows/live.yml` runs on every push to `main` (one job) and on demand with `runs=N` (N matrix
jobs). Each job is a separate GitHub runner with its own kind cluster, and it replaces the "no cluster on this
machine" gap with real Kubernetes and a real eBPF sensor. Everything happens inside the runner; the only outside
hosts are image/chart registries (GHCR, Docker Hub, helm.cilium.io, the Gatekeeper chart repo) and Sigstore
(Fulcio/Rekor) for keyless signing.

1. **Build + sign, per job.** `deploy/live/Dockerfile` (busybox, OCI `revision` label = the commit) is built
   with a per-job nonce (`<run id>.<attempt>.<job>`, stored in the `org.opencontainers.image.version` label),
   so every job's image has its own digest. It is pushed as `ghcr.io/rakshit-737/stratum-live-demo:run-<nonce>`
   and signed keyless by `cosign sign` with that job's GitHub OIDC token, so every job gets its own Fulcio
   certificate and Rekor entry. `cosign verify` must pass with the exact workflow identity
   (`https://github.com/<workflow_ref>`, issuer `token.actions.githubusercontent.com`), and a wrong identity must
   fail. The same step builds a second image from the same Dockerfile **with the same revision label**, pushes it
   as `forged-<nonce>` and never signs it (the forged-label control).
2. **Cluster.** kind, Tetragon (Helm chart 1.7.1) with `deploy/live/tracingpolicy.yaml` (`fd_install` on
   files ending in `/token`, `tcp_connect`), and OPA Gatekeeper 3.20.0.
3. **Admission.** `stratum gatekeeper --action deny` output is applied. The privileged `hostPID` pod in
   `deploy/live/denied-pod.yaml` must be rejected by the `stratum-pss-restricted` constraint, and the four demo
   deployments (`web`, `sink`, `drift`, `forged`, all PSS restricted) must be admitted.
4. **Actions.** `deploy/live/actions.sh` runs benign but attack-shaped commands in the `web` pod: a shell,
   `cat` of the projected service-account token (to `/dev/null`), and `nc` to an in-cluster `httpd` sink. It runs
   the same shell command in the two control pods: `drift` (the upstream, digest-pinned `busybox:1.36.1`, no
   revision label, unsigned) and `forged` (unsigned, but carrying the right revision label).
5. **Prevention.** `stratum prevent stratum-live` emits a default-deny egress NetworkPolicy that keeps
   in-cluster traffic. The job starts a second sink on the runner's `kind` Docker network (outside the cluster
   CIDRs) and checks that `nc` to it works before and fails after the policy, while the in-cluster sink stays
   reachable. kind enforces NetworkPolicy natively.
6. **Detection, trace and controls.** The Tetragon export stream is filtered to the demo namespace and fed to
   `stratum live-check`, which joins the rendered manifests, the live pod list and the events, and builds the
   `image -> CI run -> commit` edges **only from the verified cosign certificate** (`stratum/sigstore.py`:
   commit OID `1.3.6.1.4.1.57264.1.3`, run-invocation URI). `github.sha` is passed only as the expected value,
   and `--expect-build <run id>` fails the job if the certificate names another CI run, so a certificate from an
   earlier run cannot be reused. The job records the certificate itself (SHA-256 of the DER, serial number,
   Rekor logIndex) so that the aggregate can count distinct certificates. It fails unless R-SHELL, R-SA-TOKEN
   and R-NETTOOL fire on the web pod, every web-pod incident traces to the expected commit, the event image
   digest equals the pushed digest, a connect to `:8080` is captured, Gatekeeper denied/admitted as expected,
   cosign verified, prevention behaved as predicted, and **both negative controls** hold: the `drift` and
   `forged` incidents reach no commit and name ZT-PROV-01.
7. **Ablation.** On the same evidence, `stratum.live.ablation` re-joins the incidents five ways (A0-A4, see
   [How it works](how-it-works.md#4-image-to-ci-run-to-commit)) using the revision labels the job read from both
   images.

`gatekeeper-result.json` derives `demo_admitted` from `kubectl rollout status`. Waits use `kubectl wait` and
polling loops that fail the job on timeout.

## Result: 5 jobs, 5 images, 5 certificates

--8<-- "results/live.md"

The five jobs belong to one workflow run, so their certificates name the same CI run id (that is how GitHub's
OIDC claims work); the per-run table shows that each job still read the commit from its **own** certificate over
its **own** digest. Every image was built from the same commit, so the commit value itself is one value: the
run-level CIs cover detection, capture and the certificate join, not commit diversity. Re-run with
`gh workflow run live.yml -f runs=5` and `scripts/aggregate_live.py` ([Reproduce](reproduce.md)).

The A2 and A4 false attributions happen **by construction**: `forged` carries the right revision label and lives
in the same repository as the signed image, so any provenance that trusts the label, or that joins signatures by
repository instead of digest, attributes it to the commit. The table shows that the join semantics hold on real
sensor output in every run; it does not estimate a rate. A2 (the OCI revision label that image scanners and SBOM
tools read) is the realistic baseline; A4 ablates digest-exactness and is not a competing tool.

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
- **The sink count included a control.** Before the per-job certificate change, "detections on the sink pod"
  was computed as other-pod incidents minus `drift`, so the `forged` control's incident would have been counted
  as a false positive on the benign sink. The check now counts incidents on `sink-*` pods directly.

The demo namespace has no egress NetworkPolicy until the prevention step, so the incidents also name ZT-NET-01;
the sink pod raised no detections. This is a scripted check of the pipeline on real sensor output, not a
detection-rate study: the three actions are known in advance and there is no labelled benign set.

## Published artefacts

Each job pushes two images to the public package `ghcr.io/rakshit-737/stratum-live-demo`: the signed
`run-<nonce>` demo image and the deliberately unsigned `forged-<nonce>` control (labelled "negative control:
deliberately unsigned (lab only)"). Both are `busybox` running `sleep infinity`. Evidence artefacts
(`live-evidence-N`) are kept for 90 days.
