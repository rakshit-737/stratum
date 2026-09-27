"""Reproduction of Kim et al. (2016), LSTM system-call language models + leaky-ReLU ensemble, on ADFA-LD.

G. Kim, H. Yi, J. Lee, Y. Paek, S. Yoon. "LSTM-Based System-Call Language Modeling and Robust Ensemble
Method for Designing Host-Based Intrusion Detection Systems." arXiv:1611.01726, 2016.

Setup taken from the paper (Sec. 2-3): train on the 833 ADFA-LD training traces only; evaluate on the
4,372 validation (normal) traces vs the 746 attack traces; ROC-AUC. Three LSTM language models
(1x200, 1x400, 2x400 cells; embedding size = cells), GO token prepended, uniform init in [-0.1, 0.1],
Adam lr 1e-4, gradient-norm clip 5, dropout 0.5. Score = average negative log-likelihood per call.
Ensemble f(x) = sum_i w_i * leaky_relu(f_i(x) - b_i), slope 0.001, b_i = median f_i on the training
traces, w_i = 1/m. Averaging ensemble = mean of the raw f_i.

Not specified in the paper, chosen here: epochs (early stop on a 10 % held-out slice of the *training
normals*, max ``epochs``), batch size 32 of length-sorted traces, no truncation. Needs torch (CPU is fine).
"""
from __future__ import annotations

import math
import random
import time
from pathlib import Path

from ..syscall import bootstrap_ci, load_adfa, roc_auc

PAPER = {"LSTM ensemble (proposed)": 0.928, "averaging ensemble": 0.890, "voting ensemble": 0.859}
CONFIGS = [(200, 1), (400, 1), (400, 2)]


def _model(vocab: int, cells: int, layers: int):
    import torch.nn as nn

    class LM(nn.Module):
        def __init__(self):
            super().__init__()
            self.emb = nn.Embedding(vocab, cells, padding_idx=0)
            self.lstm = nn.LSTM(cells, cells, layers, batch_first=True, dropout=0.5 if layers > 1 else 0.0)
            self.drop = nn.Dropout(0.5)
            self.out = nn.Linear(cells, vocab)
            for p in self.parameters():
                nn.init.uniform_(p, -0.1, 0.1)

        def forward(self, x):
            h, _ = self.lstm(self.drop(self.emb(x)))
            return self.out(self.drop(h))
    return LM()


def _batches(traces, bs, shuffle, rng):
    idx = sorted(range(len(traces)), key=lambda i: len(traces[i]))
    groups = [idx[i:i + bs] for i in range(0, len(idx), bs)]
    if shuffle:
        rng.shuffle(groups)
    return groups


def _tensor(traces, ids, go):
    import torch
    L = max(len(traces[i]) for i in ids) + 1
    x = torch.zeros(len(ids), L, dtype=torch.long)
    y = torch.zeros(len(ids), L, dtype=torch.long)
    for r, i in enumerate(ids):
        t = [s + 1 for s in traces[i]]           # 0 = padding
        x[r, :len(t)] = torch.tensor([go] + t[:-1]) if t else torch.tensor([go])
        y[r, :len(t)] = torch.tensor(t)
    return x, y


def score(model, traces, go, bs=64):
    """Average negative log-likelihood per call for each trace."""
    import torch
    import torch.nn.functional as F
    model.eval()
    out = [0.0] * len(traces)
    with torch.no_grad():
        for ids in _batches(traces, bs, False, None):
            x, y = _tensor(traces, ids, go)
            nll = F.cross_entropy(model(x).transpose(1, 2), y, ignore_index=0, reduction="none")
            n = (y != 0).sum(1).clamp(min=1)
            for r, i in enumerate(ids):
                out[i] = float(nll[r].sum() / n[r])
    return out


def train(traces, vocab, cells, layers, seed, epochs=30, bs=32, log=print):
    import torch
    import torch.nn.functional as F
    torch.manual_seed(seed)
    rng = random.Random(seed)
    order = list(range(len(traces)))
    rng.shuffle(order)
    k = max(1, len(traces) // 10)
    held, fit = [traces[i] for i in order[:k]], [traces[i] for i in order[k:]]
    go = vocab - 1
    model = _model(vocab, cells, layers)
    opt = torch.optim.Adam(model.parameters(), lr=1e-4)
    best, best_state, bad = math.inf, None, 0
    for ep in range(epochs):
        model.train()
        t0 = time.time()
        for ids in _batches(fit, bs, True, rng):
            x, y = _tensor(fit, ids, go)
            loss = F.cross_entropy(model(x).transpose(1, 2), y, ignore_index=0)
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 5.0)
            opt.step()
        h = sum(score(model, held, go)) / len(held)
        log(f"  LSTM {layers}x{cells} seed {seed} epoch {ep + 1}: held-out NLL {h:.4f} ({time.time() - t0:.0f}s)")
        if h < best - 1e-4:
            best, bad = h, 0
            best_state = {k2: v.clone() for k2, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= 3:
                break
    model.load_state_dict(best_state)
    return model


def _leaky(v):
    return v if v > 0 else 0.001 * v


def run(root: Path, seeds=(0, 1, 2), epochs=30, log=print) -> dict:
    d = load_adfa(root / "adfa")
    tr, val = d["train"], d["val"]
    att = [t for _, t in d["attack"]]
    vocab = max(max(t) for t in tr + val + att if t) + 3      # +1 shift, pad=0, GO=last
    go = vocab - 1
    per_seed = []
    for seed in seeds:
        fs = []
        for cells, layers in CONFIGS:
            m = train(tr, vocab, cells, layers, seed, epochs, log=log)
            s_tr, s_val, s_att = score(m, tr, go), score(m, val, go), score(m, att, go)
            b = sorted(s_tr)[len(s_tr) // 2]
            fs.append({"cfg": f"{layers}x{cells}", "b": b, "val": s_val, "att": s_att,
                       "auc": roc_auc(s_val, s_att)})
            log(f"  -> {layers}x{cells} seed {seed}: AUC {fs[-1]['auc']:.3f}")
        m = len(fs)
        ens_v = [sum(_leaky(f["val"][i] - f["b"]) for f in fs) / m for i in range(len(val))]
        ens_a = [sum(_leaky(f["att"][i] - f["b"]) for f in fs) / m for i in range(len(att))]
        avg_v = [sum(f["val"][i] for f in fs) / m for i in range(len(val))]
        avg_a = [sum(f["att"][i] for f in fs) / m for i in range(len(att))]
        per_seed.append({
            "seed": seed, "single": {f["cfg"]: f["auc"] for f in fs},
            "ensemble": roc_auc(ens_v, ens_a), "averaging": roc_auc(avg_v, avg_a),
            "ensemble_ci": bootstrap_ci(ens_v, ens_a, roc_auc, n_boot=200, seed=seed)})
        log(f"seed {seed}: ensemble AUC {per_seed[-1]['ensemble']:.3f}, averaging {per_seed[-1]['averaging']:.3f}")

    def ms(xs):
        mu = sum(xs) / len(xs)
        sd = (sum((x - mu) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5 if len(xs) > 1 else 0.0
        return {"mean": mu, "sd": sd}
    return {"paper": PAPER, "seeds": list(seeds), "per_seed": per_seed,
            "ensemble": ms([p["ensemble"] for p in per_seed]),
            "averaging": ms([p["averaging"] for p in per_seed]),
            "single": {c: ms([p["single"][c] for p in per_seed]) for c in per_seed[0]["single"]},
            "split": {"train": len(tr), "val_normal": len(val), "attack": len(att)}}


def markdown(r: dict) -> str:
    e, a = r["ensemble"], r["averaging"]
    s = r["split"]
    lines = ["### Reproduction: Kim et al. 2016 (LSTM system-call language model ensemble) on ADFA-LD", "",
             f"Split as in the paper: {s['train']} training normals, {s['val_normal']} validation normals, "
             f"{s['attack']} attacks. Seeds {r['seeds']}; mean ± sd over seeds.", "",
             "| method | paper AUC | our reproduction AUC |", "|---|---:|---:|",
             f"| proposed leaky-ReLU ensemble (3 LSTMs) | {r['paper']['LSTM ensemble (proposed)']:.3f} | "
             f"{e['mean']:.3f} ± {e['sd']:.3f} |",
             f"| averaging ensemble | {r['paper']['averaging ensemble']:.3f} | {a['mean']:.3f} ± {a['sd']:.3f} |",
             f"| voting ensemble | {r['paper']['voting ensemble']:.3f} | not reproduced (procedure not specified) |"]
    for c, v in r["single"].items():
        lines.append(f"| single LSTM {c} | (figure only) | {v['mean']:.3f} ± {v['sd']:.3f} |")
    return "\n".join(lines)


if __name__ == "__main__":  # python -m stratum.bench.kim_lstm [epochs] [seeds...]
    import json
    import sys

    import torch

    from ..corpus import data_dir
    torch.set_num_threads(max(1, torch.get_num_threads()))
    ep = int(sys.argv[1]) if len(sys.argv) > 1 else 15
    sd = tuple(int(x) for x in sys.argv[2:]) or (0, 1, 2)
    res = run(data_dir(), seeds=sd, epochs=ep, log=lambda m: print(m, flush=True))
    out = Path("results")
    (out / "kim_lstm.json").write_text(json.dumps(res | {"epochs_max": ep}, indent=1), encoding="utf-8")
    (out / "kim_lstm.md").write_text(markdown(res) + "\n", encoding="utf-8")
    print(markdown(res))
