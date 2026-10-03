# CLI reference

`python -m stratum <command>` (or the `stratum` entry point). Global options: `--seed` for the synthetic generator, `--version`. File arguments of `collect` and `pss` accept wildcards, expanded by STRATUM itself, so `deploy/k8s/*.yaml` also works in PowerShell and cmd. Errors exit with status 2.

| command | what it does |
|---|---|
| `demo` | synthetic walkthrough of the five spec scenarios (no downloads) |
| `generate --out scenario.json` | write the synthetic dataset |
| `analyze [--data FILE\|real] [--json]` | posture findings, runtime detections, incidents |
| `trace NS/POD [--data]` | pod → image → build → commit chain |
| `blast BASE [--data]` | workloads sharing a base OS release |
| `prevent NAMESPACE [--data]` | replay: which control would have prevented the incident, generated NetworkPolicy (`NAMESPACE` must be an RFC 1123 label, at most 63 characters) |
| `collect FILES... [--tetragon EVENTS...] --out cluster.json` | real manifests (+ Tetragon JSON) → dataset JSON |
| `pss FILES... --level baseline\|restricted [--strict]` | Pod Security Standards check; `--strict` exits 1 on violations |
| `export [--data] --format cypher\|json\|rego-input [--out]` | Neo4j Cypher / JSON / OPA input export |
| `opa-check [--data]` | diff the Python engine against `stratum/policies/stratum.rego` (needs `opa`) |
| `gatekeeper [--level] [--action dryrun\|warn\|deny] [--out]` | export PSS Rego as a Gatekeeper ConstraintTemplate + Constraint |
| `bench [NAMES...] [--data-dir] [--out results]` | real-data benchmarks → `results/` |
| `live-check --manifests --pods --events --cosign-json --digest --expect-commit [--expect-build] [--drift] [--forged] [--sink] [--labels] [--gatekeeper] [--prevention]` | CI: join live kind + Tetragon evidence, assert detection and certificate-derived trace-to-commit, record the certificate (SHA-256, serial, Rekor logIndex), score the negative controls and the A0-A4 ablation (used by `live.yml`) |
| `serve [--source synthetic\|real\|live\|FILE] [--host] [--port]` | FastAPI + incident console on 127.0.0.1 by default (`live` replays job 1 of the committed live run, packaged in `stratum/data/live`) |

## HTTP API (`stratum serve`)

| endpoint | returns |
|---|---|
| `GET /api/summary` | graph size, findings by control, PSS level histogram; for `live`, the replayed CI run and commit |
| `GET /api/controls` | the 13 controls with finding counts |
| `GET /api/findings?control=&limit=` | posture findings (`limit` 1-10000, default 500) |
| `GET /api/workloads` | workloads, PSS level, lifecycle trace |
| `GET /api/incidents` | runtime detections traced to commit, failed controls, blast radius, fix |
| `GET /api/trace?node=` | lifecycle chain for a node |
| `GET /api/blast?base=` / `GET /api/bases` | blast radius per base OS release |
| `POST /api/prevent/{namespace}` | policy-as-prevention replay (422 unless the namespace is an RFC 1123 label) |
| `GET /api/export/cypher` | Neo4j Cypher script |

OpenAPI docs are served at `/docs` by FastAPI.
