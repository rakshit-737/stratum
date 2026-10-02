# Live demo

The STRATUM incident console, running entirely in your browser from a static snapshot of the API taken on the **real-data corpus** (31 upstream manifests/charts, 86 images, Tetragon attack-chain events):

[Open the real-data console](demo/index.html){ .md-button .md-button--primary }
[Open the live-cluster console](demo-live/index.html){ .md-button }

**Real-data console** (`python scripts/build_static_demo.py --source real`, about 80 KB of JSON). Tabs: overview, incidents, workloads with PSS level and lifecycle trace, blast radius per base OS release, and control coverage. None of its 18 runtime incidents reaches a commit: the public Tetragon sample runs `nginx:latest`, an Isovalent demo image and two unmanaged containers, none of which carries build provenance. Commit traces appear in the Workloads tab (23 of 87 manifest workloads). The console also counts 8 runtime-only pods and 5 images seen only in the Tetragon sample, hence 95 workloads / 91 images rather than the 87 / 86 in the README.

**Live-cluster console** (`--source live --out docs/demo-live`): a replay of a committed [live CI run](live.md). Every incident on the demo pod traces `pod -> workload -> image digest -> CI run -> commit`, with the run and commit read from the image's Sigstore certificate.

To run the live API instead:

```bash
pip install -e ".[api]"
python -m stratum serve --source synthetic   # or --source real with $STRATUM_DATA
```
