from stratum.syscall import NgramNovelty, Stide, load_adfa, roc_auc, tpr_at_fpr, windows


def test_windows():
    assert list(windows([1, 2, 3, 4], 3)) == [(1, 2, 3), (2, 3, 4)]
    assert list(windows([1, 2], 3)) == [(1, 2)]


def test_stide_and_novelty():
    normal = [[1, 2, 3, 1, 2, 3, 1, 2, 3]] * 5
    s = Stide(3).fit(normal)
    assert s.score([1, 2, 3, 1]) == 0.0 and s.score([9, 9, 9, 9]) == 1.0
    m = NgramNovelty(2).fit(normal)
    assert m.score([9, 8, 7]) > m.score([1, 2, 3])


def test_metrics():
    assert roc_auc([0, 1], [2, 3]) == 1.0 and roc_auc([2, 3], [0, 1]) == 0.0 and roc_auc([1], [1]) == 0.5
    tpr, fpr = tpr_at_fpr([0.1 * i for i in range(100)], [5, 20], 0.05)
    assert tpr == 0.5 and fpr <= 0.05


def test_adfa_loader(fix):
    d = load_adfa(fix / "adfa")
    assert len(d["train"]) == 4 and len(d["val"]) == 2
    assert {f for f, _ in d["attack"]} == {"Adduser", "Web_Shell"}
    m = Stide(6).fit(d["train"])
    assert all(0 <= m.score(t) <= 1 for _, t in d["attack"])
