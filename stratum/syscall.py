"""Syscall-sequence anomaly models for the runtime sensor ("AI flags, the graph explains").

Evaluated on ADFA-LD (see ``stratum.bench.adfa``). Three detectors, all trained
on *normal traces only* (no attack labels are ever used for fitting):

* :class:`Stide` - the classic baseline (Forrest et al., 1996): a database of
  length-``n`` windows seen in normal traces; the anomaly score of a trace is
  the fraction of its windows missing from the database.
* :class:`NgramNovelty` - STRATUM's frequency novelty model generalised from
  (process, event, port) tuples to syscall n-grams: the score is the mean
  surprisal ``-log P(window)`` under an add-k smoothed model of normal
  behaviour, so *rare* windows count as well as never-seen ones.
* :class:`NgramIsolationForest` - an Isolation Forest over hashed, TF-IDF
  weighted 1..n-gram counts (needs scikit-learn; optional).

Traces are plain integer sequences.
"""
from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path

Trace = Sequence[int]


def windows(trace: Trace, n: int) -> Iterable[tuple[int, ...]]:
    if len(trace) < n:
        if trace:
            yield tuple(trace)
        return
    for i in range(len(trace) - n + 1):
        yield tuple(trace[i:i + n])


class Stide:
    name = "STIDE"

    def __init__(self, n: int = 6) -> None:
        self.n = n
        self.db: set[tuple[int, ...]] = set()

    def fit(self, traces: Iterable[Trace]) -> Stide:
        for t in traces:
            self.db.update(windows(t, self.n))
        return self

    def score(self, trace: Trace) -> float:
        ws = list(windows(trace, self.n))
        return sum(w not in self.db for w in ws) / len(ws) if ws else 0.0


class NgramNovelty:
    name = "n-gram novelty"

    def __init__(self, n: int = 3, k: float = 0.01, agg: str = "mean") -> None:
        self.n, self.k, self.agg = n, k, agg
        self.counts: Counter = Counter()
        self.total = 0
        self.vocab = 1

    def fit(self, traces: Iterable[Trace]) -> NgramNovelty:
        syms: set[int] = set()
        for t in traces:
            syms.update(t)
            for w in windows(t, self.n):
                self.counts[w] += 1
                self.total += 1
        self.vocab = max(len(syms), 1) ** self.n
        return self

    def surprisal(self, w: tuple[int, ...]) -> float:
        return -math.log((self.counts.get(w, 0) + self.k) / (self.total + self.k * self.vocab))

    def score(self, trace: Trace) -> float:
        s = [self.surprisal(w) for w in windows(trace, self.n)]
        if not s:
            return 0.0
        if self.agg == "max":
            return max(s)
        if self.agg == "p90":
            s.sort()
            return s[int(0.9 * (len(s) - 1))]
        return sum(s) / len(s)


class NgramIsolationForest:
    name = "Isolation Forest (1..n-gram TF-IDF)"

    def __init__(self, n: int = 3, seed: int = 0, n_features: int = 2 ** 16) -> None:
        self.n, self.seed, self.n_features = n, seed, n_features

    def _docs(self, traces: Iterable[Trace]) -> list[str]:
        return [" ".join(f"s{x}" for x in t) for t in traces]

    def fit(self, traces: Iterable[Trace]) -> NgramIsolationForest:
        from sklearn.ensemble import IsolationForest
        from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer

        self.vec = HashingVectorizer(ngram_range=(1, self.n), n_features=self.n_features, alternate_sign=False,
                                     token_pattern=r"\S+", norm=None)
        self.tfidf = TfidfTransformer()
        x = self.tfidf.fit_transform(self.vec.transform(self._docs(traces)))
        self.model = IsolationForest(n_estimators=300, random_state=self.seed).fit(x)
        return self

    def score_many(self, traces: Sequence[Trace]) -> list[float]:
        x = self.tfidf.transform(self.vec.transform(self._docs(traces)))
        return list(-self.model.score_samples(x))

    def score(self, trace: Trace) -> float:
        return self.score_many([trace])[0]


# ------------------------------------------------------------------ ADFA-LD
def read_trace(path: Path) -> list[int]:
    return [int(x) for x in path.read_text().split()]


def load_adfa(root: str | Path) -> dict[str, list]:
    """{'train': [trace], 'val': [trace], 'attack': [(family, trace)]} from an ADFA-LD folder."""
    root = Path(root)
    if (root / "ADFA-LD").is_dir():
        root = root / "ADFA-LD"
    train = [read_trace(p) for p in sorted((root / "Training_Data_Master").glob("*.txt"))]
    val = [read_trace(p) for p in sorted((root / "Validation_Data_Master").glob("*.txt"))]
    attack = []
    for d in sorted((root / "Attack_Data_Master").iterdir()):
        if d.is_dir():
            fam = d.name.rsplit("_", 1)[0]
            attack += [(fam, read_trace(p)) for p in sorted(d.glob("*.txt"))]
    return {"train": train, "val": val, "attack": attack}


# ------------------------------------------------------------------ metrics
def roc_auc(neg: Sequence[float], pos: Sequence[float]) -> float:
    """Mann-Whitney U estimate of ROC-AUC (ties count 1/2); no sklearn needed."""
    allv = sorted([(v, 0) for v in neg] + [(v, 1) for v in pos])
    i, rank_sum = 0, 0.0
    while i < len(allv):
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        avg = (i + j + 1) / 2
        rank_sum += avg * sum(1 for k in range(i, j) if allv[k][1] == 1)
        i = j
    npos, nneg = len(pos), len(neg)
    return (rank_sum - npos * (npos + 1) / 2) / (npos * nneg) if npos and nneg else float("nan")


def tpr_at_fpr(neg: Sequence[float], pos: Sequence[float], fpr: float) -> tuple[float, float]:
    """Threshold = the (1-fpr) quantile of normal scores; returns (TPR, realised FPR)."""
    s = sorted(neg)
    idx = min(len(s) - 1, max(0, math.ceil((1 - fpr) * len(s)) - 1))
    thr = s[idx]
    tpr = sum(p > thr for p in pos) / len(pos)
    real = sum(n > thr for n in neg) / len(neg)
    return tpr, real


def bootstrap_ci(neg: Sequence[float], pos: Sequence[float], stat, n_boot: int = 500, seed: int = 0,
                 alpha: float = 0.05) -> tuple[float, float]:
    """Stratified percentile bootstrap CI for ``stat(neg, pos)`` (normal and attack resampled separately)."""
    import random

    rng = random.Random(seed)
    vals = []
    for _ in range(n_boot):
        bn = [neg[rng.randrange(len(neg))] for _ in neg]
        bp = [pos[rng.randrange(len(pos))] for _ in pos]
        vals.append(stat(bn, bp))
    vals.sort()
    lo = vals[int(alpha / 2 * (n_boot - 1))]
    hi = vals[int((1 - alpha / 2) * (n_boot - 1))]
    return lo, hi
