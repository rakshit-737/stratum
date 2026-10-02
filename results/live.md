### Live kind + Tetragon run (GitHub Actions)

- Tetragon events: 23 total, 23 in the demo namespace ({'exec': 21, 'open': 1, 'connect': 1})
- Rules raised on the demo pod: R-NETTOOL, R-SA-TOKEN, R-SHELL
- Incidents traced to the CI commit: 5/5
- Detections on other pods in the namespace (sink): 0
- Trace: pod:stratum-live/web-9dc6879bb-xl5nl -> workload:stratum-live/web -> image:ghcr.io/rakshit-737/stratum-live-demo@sha256:a1e2a762c940879b79e09773574759805b898a89b914062949948f262c972ff1 -> build:36319470255 -> commit:6dd4b9b30f2404a974b0198a021ced3963a55516
- Gatekeeper: {'privileged_denied': True, 'demo_admitted': True}
- cosign keyless verify: True
- Result: PASS

Run: https://github.com/rakshit-737/stratum/actions/runs/36319470255 (artefact live-evidence).
