# CLI reference

`python -m stratum <command>` (or the `stratum` entry point). Global option: `--seed` for the synthetic generator.

| command | what it does |
|---|---|
| `demo` | synthetic walkthrough of the five spec scenarios (no downloads) |
| `generate --out scenario.json` | write the synthetic dataset |
| `analyze [--data FILE\|real] [--json]` | posture findings, runtime detections, incidents |
| `trace NS/POD [--data]` | pod → image → build → commit chain |
| `blast BASE [--data]` | workloads sharing a base OS release |
| `prevent NAMESPACE [--data]` | replay: which control would have prevented the incident, generated NetworkPolicy |
| `collect FILES... [--tetragon EVENTS...] --out cluster.json` | real manifests (+ Tetragon JSON) → dataset JSON |
| `pss FILES... --level baseline\|restricted [--strict]` | Pod Security Standards check; `--strict` exits 1 on violations |
| `export [--data] --format cypher\|json\|rego-input [--out]` | Neo4j Cypher / JSON / OPA input export |
| `opa-check [--data]` | diff the Python engine against `policies/stratum.rego` (needs `opa`) |
| `gatekeeper [--level] [--action dryrun\|warn\|deny] [--out]` | export PSS Rego as a Gatekeeper ConstraintTemplate + Constraint |
| `bench [NAMES...] [--data-dir] [--out results]` | real-data benchmarks → `results/` |
| `serve [--source synthetic\|real\|FILE] [--host] [--port]` | FastAPI + incident console |

## HTTP API (`stratum serve`)

| endpoint | returns |
|---|---|
| `GET /api/summary` | graph size, findings by control, PSS level histogram |
| `GET /api/controls` | the 13 controls with finding counts |
| `GET /api/findings?control=&limit=` | posture findings |
| `GET /api/workloads` | workloads, PSS level, lifecycle trace |
| `GET /api/incidents` | runtime detections traced to commit, failed controls, blast radius, fix |
| `GET /api/trace?node=` | lifecycle chain for a node |
| `GET /api/blast?base=` / `GET /api/bases` | blast radius per base OS release |
| `POST /api/prevent/{namespace}` | policy-as-prevention replay |
| `GET /api/export/cypher` | Neo4j Cypher script |

OpenAPI docs are served at `/docs` by FastAPI.
