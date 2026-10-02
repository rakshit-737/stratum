"""Small, dependency-free classification metrics."""
from __future__ import annotations


def confusion(y_true: list[bool], y_pred: list[bool]) -> dict:
    tp = sum(t and p for t, p in zip(y_true, y_pred))
    fp = sum((not t) and p for t, p in zip(y_true, y_pred))
    fn = sum(t and (not p) for t, p in zip(y_true, y_pred))
    tn = sum((not t) and (not p) for t, p in zip(y_true, y_pred))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / len(y_true) if y_true else 0.0
    return {"n": len(y_true), "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(prec, 4),
            "recall": round(rec, 4), "f1": round(f1, 4), "accuracy": round(acc, 4)}


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    """Wilson score 95% interval for a proportion k/n."""
    if not n:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]
