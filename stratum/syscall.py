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


def roc_curve(neg: Sequence[float], pos: Sequence[float]) -> list[tuple[float, float]]:
    """ROC vertices (FPR, TPR) for "score >= threshold", thresholds descending; tied scores form one
    diagonal segment, i.e. the curve a random tie-break gives in expectation."""
    from collections import Counter
    cn, cp = Counter(neg), Counter(pos)
    fp = tp = 0
    pts = [(0.0, 0.0)]
    for t in sorted(set(cn) | set(cp), reverse=True):
        fp += cn.get(t, 0); tp += cp.get(t, 0)
        pts.append((fp / len(neg), tp / len(pos)))
    return pts


def _interp(pts: list[tuple[float, float]], x: float, by: int) -> float:
    o = 1 - by
    for (a, b) in zip(pts, pts[1:]):
        if a[by] <= x <= b[by]:
            return a[o] if b[by] == a[by] else a[o] + (b[o] - a[o]) * (x - a[by]) / (b[by] - a[by])
    return pts[-1][o]


def tpr_at_fpr_interp(neg: Sequence[float], pos: Sequence[float], fpr: float) -> float:
    """TPR at exactly ``fpr`` on the tie-interpolated ROC curve."""
    return _interp(roc_curve(neg, pos), fpr, 0)


def fpr_at_tpr(neg: Sequence[float], pos: Sequence[float], tpr: float) -> float:
    """False-alarm rate needed to reach detection rate ``tpr`` (tie-interpolated ROC)."""
    pts = roc_curve(neg, pos)
    for (a, b) in zip(pts, pts[1:]):
        if a[1] <= tpr <= b[1] and b[1] > a[1]:
            return a[0] + (b[0] - a[0]) * (tpr - a[1]) / (b[1] - a[1])
    return 1.0


def paired_bootstrap_diff(neg_a, pos_a, neg_b, pos_b, stat, n_boot: int = 1000, seed: int = 0,
                          alpha: float = 0.05) -> dict:
    """Paired, stratified bootstrap of ``stat(A) - stat(B)`` for two detectors scored on the same traces.
    Returns the observed difference, its percentile CI and a two-sided bootstrap p-value,
    ``min(1, 2 (k + 1) / (B + 1))`` with ``k`` the smaller tail count."""
    import random
    rng = random.Random(seed)
    obs = stat(neg_a, pos_a) - stat(neg_b, pos_b)
    diffs = []
    for _ in range(n_boot):
        ni = [rng.randrange(len(neg_a)) for _ in neg_a]
        pi = [rng.randrange(len(pos_a)) for _ in pos_a]
        diffs.append(stat([neg_a[i] for i in ni], [pos_a[i] for i in pi])
                     - stat([neg_b[i] for i in ni], [pos_b[i] for i in pi]))
    diffs.sort()
    lo, hi = diffs[int(alpha / 2 * (n_boot - 1))], diffs[int((1 - alpha / 2) * (n_boot - 1))]
    # Monte Carlo p-value with the +1 correction (Davison & Hinkley 1997): never 0 for a finite B.
    k = min(sum(d <= 0 for d in diffs), sum(d >= 0 for d in diffs))
    p = min(1.0, 2 * (k + 1) / (n_boot + 1))
    return {"diff": obs, "ci95": [lo, hi], "p_boot": p, "n_boot": n_boot}
