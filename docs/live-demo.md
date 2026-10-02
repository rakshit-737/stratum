# Live demo

The STRATUM incident console, running entirely in your browser from a static snapshot of the API taken on the **real-data corpus** (31 upstream manifests/charts, 86 images, Tetragon attack-chain events):

[Open the console :material-open-in-new:](demo/index.html){ .md-button .md-button--primary }

The snapshot is produced by `python scripts/build_static_demo.py --source real` (about 80 KB of JSON). Tabs: overview, incidents traced to commits, workloads with PSS level and lifecycle trace, blast radius per base OS release, and control coverage.

To run the live API instead:

```bash
pip install -e ".[api]"
python -m stratum serve --source synthetic   # or --source real with $STRATUM_DATA
```
