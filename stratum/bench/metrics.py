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
