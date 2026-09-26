from pathlib import Path

import pytest
import yaml

from stratum.pss import evaluate_pod, highest_level, legacy_check

PSS = Path(__file__).parent / "fixtures" / "pss"


def _load(fix, name):
    return yaml.safe_load((fix / "pss" / name).read_text())


@pytest.mark.parametrize("name", sorted(p.name for p in PSS.glob("*.yaml")))
def test_upstream_fixture(fix, name):
    level, expect, check = name.split("_", 2)
    check = check.rsplit(".", 1)[0].rstrip("0123456789")
    v = evaluate_pod(_load(fix, name), level)
    if expect == "pass":
        assert v == {}
    else:
        assert check in v


def test_levels_and_legacy(fix):
    priv = _load(fix, "restricted_fail_privileged0.yaml")
    assert highest_level(priv) == "privileged"
    assert legacy_check(priv) is True
    ok = _load(fix, "restricted_pass_base_linux.yaml")
    assert highest_level(ok) == "restricted"
    assert legacy_check(ok) is False
    # runAsNonRoot missing: baseline-OK but not restricted; the v0.1 heuristic misses it
    rn = _load(fix, "restricted_fail_runasnonroot0.yaml")
    assert highest_level(rn) == "baseline" and legacy_check(rn) is False


def test_user_namespace_relaxes_procmount(fix):
    pod = _load(fix, "baseline_pass_procmount1.yaml")
    assert "procmount" not in evaluate_pod(pod, "baseline")
    assert "procmount_restricted" in evaluate_pod(pod, "restricted")


def test_windows_pods_exempt_from_linux_only_checks():
    pod = {"spec": {"os": {"name": "windows"}, "securityContext": {"runAsNonRoot": True},
                    "containers": [{"name": "c", "image": "x"}]}}
    v = evaluate_pod(pod, "restricted")
    assert not {"allowprivilegeescalation", "capabilities_restricted", "seccompprofile_restricted"} & set(v)
