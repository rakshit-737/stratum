"""PNG figures for the README (matplotlib, optional)."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

INK, MUTED, GRID = "#1b1f24", "#5d6673", "#e3e6ea"
SERIES = ["#2458d6", "#c2570c", "#1f7a3d", "#8a3ffc", "#b3261e"]


def _roc_label(name: str, d: dict) -> str:
    seeds = (f", median seed {d['shown_seed']}; mean {d['auc_seed_mean']:.3f} ± {d['auc_seed_sd']:.3f} over seeds"
             if "auc_seed_mean" in d else "")
    return f"{name} (AUC {d['auc']:.3f}{seeds})"


def _style(ax):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.spines["left"].set_color(MUTED)
    ax.spines["bottom"].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.grid(axis="y" if ax.name == "rectilinear" else "both", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def render(results: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    if "adfa" in results:
        fig, ax = plt.subplots(figsize=(5.2, 4.2), dpi=130)
        for i, (name, d) in enumerate(results["adfa"]["detectors"].items()):
            xs, ys = zip(*d["_roc"])
            ax.plot(xs, ys, color=SERIES[i % len(SERIES)], lw=1.8, label=_roc_label(name, d))
        ax.plot([0, 1], [0, 1], color=MUTED, lw=0.8, ls="--")
        ax.set_xlabel("false-positive rate (normal traces)", color=INK)
        ax.set_ylabel("detection rate (attack traces)", color=INK)
        ax.set_title("ADFA-LD: syscall anomaly models", color=INK, fontsize=11, loc="left")
        ax.legend(fontsize=7, frameon=False, loc="lower right")
        _style(ax)
        fig.tight_layout()
        fig.savefig(out / "adfa_roc.png")
        plt.close(fig)
    if "pss" in results:
        fig, ax = plt.subplots(figsize=(5.2, 3.2), dpi=130)
        lv = results["pss"]["levels"]
        labels = list(lv)
        x = range(len(labels))
        for i, (key, name) in enumerate((("stratum", "STRATUM"), ("legacy_mvp", "v0.1 heuristic"))):
            vals = [lv[level][key]["f1"] for level in labels]
            bars = ax.bar([j + (i - 0.5) * 0.36 for j in x], vals, width=0.34, color=SERIES[i], label=name)
            ax.bar_label(bars, fmt="%.2f", fontsize=8, color=INK, padding=2)
        ax.set_xticks(list(x), [f"PSS {level}" for level in labels])
        ax.set_ylim(0, 1.12)
        ax.set_ylabel("F1 vs upstream fixtures", color=INK)
        ax.set_title("Policy-engine conformance (k8s PSA fixtures v1.37)", color=INK, fontsize=11, loc="left")
        ax.legend(fontsize=8, frameon=False, loc="upper left", ncol=2)
        _style(ax)
        fig.tight_layout()
        fig.savefig(out / "pss_conformance.png")
        plt.close(fig)
    if "posture" in results:
        fc = results["posture"]["findings_by_control"]
        fig, ax = plt.subplots(figsize=(5.6, 3.4), dpi=130)
        items = sorted(fc.items(), key=lambda kv: kv[1])
        bars = ax.barh([k for k, _ in items], [v for _, v in items], color=SERIES[0], height=0.6)
        ax.bar_label(bars, fontsize=8, color=INK, padding=2)
        ax.set_xlabel("findings across real manifests", color=INK)
        ax.set_title(f"Zero-Trust findings, {results['posture']['n_projects']} projects", color=INK,
                     fontsize=11, loc="left")
        _style(ax)
        ax.grid(axis="x", color=GRID)
        ax.grid(axis="y", visible=False)
        fig.tight_layout()
        fig.savefig(out / "posture_controls.png")
        plt.close(fig)
    if "provenance" in results:
        fn = results["provenance"]["funnel"]
        fig, ax = plt.subplots(figsize=(6.4, 3.4), dpi=130)
        items = list(fn.items())[::-1]
        bars = ax.barh([k for k, _ in items], [v[1] for _, v in items], color=SERIES[2], height=0.6)
        ax.bar_label(bars, labels=[f"{v[0]} ({v[1]:.0f}%)" for _, v in items], fontsize=8, color=INK, padding=2)
        ax.set_xlim(0, 125)
        ax.set_xlabel("% of images referenced by the manifests", color=INK)
        ax.set_title("Provenance coverage: image -> commit", color=INK, fontsize=11, loc="left")
        _style(ax)
        ax.grid(axis="x", color=GRID)
        ax.grid(axis="y", visible=False)
        fig.tight_layout()
        fig.savefig(out / "provenance_funnel.png")
        plt.close(fig)

    if "scans" in results and results["scans"]["per_image"]:
        rows = sorted(results["scans"]["per_image"], key=lambda x: (x["CRITICAL"], x["HIGH"]), reverse=True)[:15][::-1]
        fig, ax = plt.subplots(figsize=(6.4, 4.4), dpi=130)
        names = ["/".join(r["ref"].split("@")[0].split("/")[-2:])[-42:] for r in rows]
        left = [0] * len(rows)
        for i, sev in enumerate(("CRITICAL", "HIGH", "MEDIUM")):
            vals = [r[sev] for r in rows]
            ax.barh(names, vals, left=left, color=["#b3261e", "#c2570c", "#d9b44a"][i], height=0.62, label=sev.lower())
            left = [a + b for a, b in zip(left, vals)]
        ax.set_xlabel("vulnerabilities (Trivy, unique CVE x package)", color=INK)
        ax.set_title(f"Most-exposed images ({results['scans']['images_scanned']} scanned)", color=INK,
                     fontsize=11, loc="left")
        ax.legend(fontsize=8, frameon=False, loc="lower right")
        _style(ax)
        ax.tick_params(axis="y", labelsize=7)
        ax.grid(axis="x", color=GRID)
        ax.grid(axis="y", visible=False)
        fig.tight_layout()
        fig.savefig(out / "scans_top_images.png")
        plt.close(fig)
