# Gatekeeper export

`stratum/policies/pss/pss.rego` re-implements the eight Pod Security Standards checks that are plain field tests
(`hostnamespaces`, `privileged`, `capabilities_baseline`, `hostpathvolumes`, `hostports`,
`allowprivilegeescalation`, `runasuser`, `runasnonroot`) in Rego v1, with the same check ids as `stratum/pss.py`.
It accepts Pods and pod-template workloads (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob).

```bash
python -m stratum gatekeeper --level restricted --action dryrun --out stratum-pss.yaml
kubectl apply -f stratum-pss.yaml     # lab cluster with Gatekeeper installed
```

The output holds a `ConstraintTemplate` (kind `StratumPodSecurity`) and a `Constraint` with `enforcementAction`
`dryrun` by default, excluding `kube-system`.

## Equivalence with the Python engine

`tests/test_gatekeeper.py` evaluates the Rego with `opa` and compares the failing check set per object with
`stratum.pss.evaluate_pod` restricted to those eight checks:

- on the committed PSS fixtures plus a hand-built multi-violation pod, and on the same pod wrapped in a Deployment and a CronJob (runs in CI);
- on all Pod objects in the upstream `pod-security-admission` v0.37.1 testdata when the corpus is present (`realdata`): no disagreements.

Not ported: AppArmor, SELinux, `/proc` mount, seccomp, sysctls, Windows HostProcess, host probes, restricted volume types,
restricted capabilities. Those checks depend on version-specific annotation handling and are still Python-only.
The template has not been applied to a live Gatekeeper install here (no cluster on this machine).
