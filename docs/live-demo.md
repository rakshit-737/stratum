# Live demo

The STRATUM incident console, running entirely in your browser from a static snapshot of the API taken on the **real-data corpus** (31 upstream manifests/charts, 86 images, Tetragon attack-chain events):

[Open the real-data console](demo/index.html){ .md-button .md-button--primary }
[Open the live-cluster console](demo-live/index.html){ .md-button }

**Real-data console** (`python scripts/build_static_demo.py --source real`, about 80 KB of JSON). Tabs: overview, incidents, workloads with PSS level and lifecycle trace, blast radius per base OS release, and control coverage. None of its 18 runtime incidents reaches a commit: the public Tetragon sample runs `nginx:latest`, an Isovalent demo image and two unmanaged containers, none of which carries build provenance. Commit traces appear in the Workloads tab (23 of 87 manifest workloads). The console also counts 8 runtime-only pods and 5 images seen only in the Tetragon sample, hence 95 workloads / 91 images rather than the 87 / 86 in the README.

**Live-cluster console** (`--source live --out docs/demo-live`): a replay of job 1 of live run [37085766270](https://github.com/rakshit-737/stratum-cloud-security/actions/runs/37085766270) (commit `38cc4a3`, one of the five jobs aggregated in [Live CI](live.md)); the console header names the run. It is the same replay that `stratum serve --source live` loads from the package (`stratum/data/live/`). Every incident on the demo pod (11) traces `pod -> workload -> image digest -> CI run -> commit`, with the run and commit read from that job's Sigstore certificate. The two negative controls are there too: the `drift` (upstream busybox) and `forged` (unsigned, right revision label) incidents reach no commit and name ZT-PROV-01.

To run the live API instead:

```bash
pip install -e ".[api]"
python -m stratum serve --source synthetic   # or --source live (packaged CI replay), or --source real with $STRATUM_DATA
```
