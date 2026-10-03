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


def test_container_syscalls_leave_one_run_out(tmp_path):
    from stratum.bench.container_syscalls import evaluate, load, markdown
    for r in (1, 2):
        d = tmp_path / f"run-{r}"
        d.mkdir()
        for i in range(6):
            (d / f"normal-{i}.txt").write_text("openat read close write " * 3)
        (d / "attack0-1.txt").write_text("execve clone connect execve socket")
    res = evaluate(load(tmp_path))
    v = res["detectors"]["STIDE n=3"]
    assert res["runs"] == 2 and len(v["folds"]) == 2 and v["auc_mean"] == 1.0
    assert "2 runs" in markdown(res)


def test_container_syscalls_per_action_and_cluster_ci(tmp_path):
    from stratum.bench.container_syscalls import evaluate, load, markdown
    for r in (1, 2, 3):
        d = tmp_path / f"run-{r}"
        d.mkdir()
        for i in range(6):
            (d / f"normal-{i}.txt").write_text("openat read close write " * 3 if i % 2 else "stat close write")
        for i in range(3):
            (d / f"attack0-{i}.txt").write_text("execve clone connect execve socket")   # novel calls
            (d / f"attack1-{i}.txt").write_text("stat close write")                      # same as a normal trace
    res = evaluate(load(tmp_path), n_boot=50)
    assert res["seeds"] == [1, 2, 3] and res["distinct_normal_sequences"] == 2
    v = res["detectors"]["STIDE n=3"]
    assert v["per_action"]["0"]["separated_in_every_fold"] and not v["per_action"]["1"]["separated_in_every_fold"]
    assert v["actions_separated"] == 1 and v["actions"] == 2 and v["clusters"] == {"normal": 6, "attack": 6}
    lo, hi = v["auc_cluster_ci95"]
    assert 0 <= lo <= v["auc_mean"] <= hi <= 1
    md = markdown(res)
    assert "1/2" in md and "strace" in md and "not eBPF" in md


def test_paired_bootstrap_p_value_never_zero():
    from stratum.syscall import paired_bootstrap_diff, roc_auc
    neg, good, bad = [0.0, 0.1, 0.2, 0.3], [0.9, 0.8, 0.95, 0.85], [-1.0, -2.0, -3.0, -4.0]
    r = paired_bootstrap_diff(neg, good, neg, bad, roc_auc, n_boot=99)
    assert r["diff"] > 0 and r["p_boot"] == 2 / 100   # every resample favours A: p = 2 (0 + 1) / (B + 1)


def test_t_and_sign_test():
    from stratum.bench.metrics import sign_test_p, t_two_sided_p
    assert abs(t_two_sided_p(2.262, 9) - 0.05) < 1e-3 and abs(t_two_sided_p(2.776, 4) - 0.05) < 1e-3
    assert t_two_sided_p(0.0, 5) == 1.0
    assert sign_test_p(10, 10) == 2 / 1024 and sign_test_p(5, 10) == 1.0
