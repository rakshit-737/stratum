### Posture of 31 real projects (87 workloads)

Pod Security level reached: restricted **55**, baseline **25**, privileged **7**.  
Workloads needing hardening flagged by the v0.1 heuristic vs full PSS: v0.1 heuristic = 7, PSS restricted (v0.2) = 32.

| project | version | workloads | PSS (R/B/P) | findings by control |
|---|---|---:|---|---|
| argo-cd | v3.5.3 | 7 | 7/0/0 | ZT-ID-02:6, ZT-NET-01:1, ZT-PROV-03:7 |
| calico | v3.32.2 | 2 | 0/1/1 | ZT-ID-02:1, ZT-NET-01:1, ZT-PROV-03:2, ZT-WL-01:1, ZT-WL-02:1 |
| cert-manager | v1.21.2 | 3 | 3/0/0 | ZT-ID-02:3, ZT-ID-04:2, ZT-NET-01:1, ZT-PROV-03:3 |
| cloudnative-pg | v1.30.1 | 1 | 1/0/0 | ZT-ID-02:1, ZT-ID-04:1, ZT-NET-01:1, ZT-PROV-03:1 |
| external-secrets | external-secrets-2.11.0 | 3 | 3/0/0 | ZT-ID-02:2, ZT-ID-04:2, ZT-NET-01:1, ZT-PROV-03:3 |
| falco | falco-9.2.0 | 1 | 0/0/1 | ZT-NET-01:1, ZT-PROV-03:1, ZT-WL-01:1 |
| flannel | v0.28.9 | 1 | 0/0/1 | ZT-NET-01:1, ZT-PROV-03:1, ZT-WL-01:1 |
| flux2 | v2.9.5 | 7 | 7/0/0 | ZT-ID-02:7, ZT-ID-03:2, ZT-ID-04:5, ZT-PROV-03:7 |
| gatekeeper | v3.23.1 | 2 | 2/0/0 | ZT-ID-02:2, ZT-ID-04:2, ZT-NET-01:1, ZT-PROV-03:2 |
| harbor | harbor-1.19.2 | 7 | 7/0/0 | ZT-ID-01:7, ZT-NET-01:1, ZT-PROV-03:7 |
| ingress-nginx | controller-v1.15.1 | 3 | 3/0/0 | ZT-ID-02:3, ZT-ID-04:1, ZT-NET-01:1 |
| jenkins | jenkins-5.9.64 | 2 | 0/2/0 | ZT-ID-01:1, ZT-ID-02:1, ZT-NET-01:1, ZT-PROV-03:2, ZT-WL-02:2 |
| keda | v2.21.0 | 2 | 2/0/0 | ZT-ID-02:2, ZT-ID-04:2, ZT-NET-01:1, ZT-PROV-03:2 |
| knative-serving | v1.23.0 | 4 | 4/0/0 | ZT-ID-02:1, ZT-NET-01:1 |
| kube-state-metrics | v2.20.0 | 1 | 1/0/0 | ZT-ID-02:1, ZT-ID-04:1, ZT-NET-01:1, ZT-PROV-03:1 |
| kubernetes-dashboard | v2.7.0 | 2 | 0/2/0 | ZT-ID-02:2, ZT-NET-01:1, ZT-PROV-03:2, ZT-WL-02:2 |
| kyverno | v1.19.1 | 4 | 4/0/0 | ZT-ID-02:4, ZT-NET-01:1, ZT-PROV-03:4 |
| local-path-provisioner | v0.0.37 | 1 | 0/1/0 | ZT-NET-01:1, ZT-PROV-03:1, ZT-WL-02:1 |
| longhorn | v1.12.1 | 3 | 0/2/1 | ZT-ID-02:2, ZT-ID-04:2, ZT-NET-01:1, ZT-PROV-03:3, ZT-WL-01:2, ZT-WL-02:1 |
| metallb | v0.16.0 | 2 | 0/0/2 | ZT-ID-02:2, ZT-NET-01:1, ZT-PROV-03:2, ZT-WL-01:2 |
| metrics-server | v0.9.0 | 1 | 1/0/0 | ZT-NET-01:1, ZT-PROV-03:1 |
| online-boutique | v0.10.7 | 12 | 0/12/0 | ZT-ID-01:1, ZT-NET-01:1, ZT-PROV-03:12, ZT-WL-02:12 |
| postgresql-bitnami | postgresql-18.12.2 | 1 | 1/0/0 | ZT-PROV-03:1 |
| prometheus-operator | v0.94.1 | 1 | 1/0/0 | ZT-ID-02:1, ZT-ID-04:1, ZT-NET-01:1, ZT-PROV-03:1 |
| redis-bitnami | redis-28.2.4 | 2 | 2/0/0 | ZT-PROV-03:2 |
| sealed-secrets | v0.40.0 | 1 | 1/0/0 | ZT-ID-02:1, ZT-ID-04:1, ZT-NET-01:1, ZT-PROV-03:1 |
| tekton-pipelines | v1.16.0 | 4 | 4/0/0 | ZT-ID-02:3, ZT-ID-04:2, ZT-NET-01:2 |
| tetragon | tetragon-1.7.1 | 2 | 0/1/1 | ZT-NET-01:1, ZT-PROV-03:2, ZT-WL-01:1, ZT-WL-02:1 |
| traefik | traefik-41.6.0 | 1 | 1/0/0 | ZT-ID-02:1, ZT-ID-04:1, ZT-NET-01:1, ZT-PROV-03:1 |
| trivy-operator | trivy-operator-0.36.0 | 1 | 0/1/0 | ZT-ID-02:1, ZT-ID-04:1, ZT-NET-01:1, ZT-PROV-03:1, ZT-WL-02:1 |
| vault | vault-0.34.1 | 3 | 0/3/0 | ZT-ID-01:1, ZT-NET-01:1, ZT-PROV-03:3, ZT-WL-02:3 |

Findings per control are summed per project (a namespace shared by several projects, e.g. kube-system, is counted once per project). On the merged corpus, 26 of 29 distinct namespaces have no default-deny egress policy (ZT-NET-01).

| control | title | findings (per-project sum) |
|---|---|---:|
| ZT-PROV-03 | Images pinned by immutable digest | 76 |
| ZT-ID-02 | Disable SA token automount unless needed | 47 |
| ZT-NET-01 | Default-deny egress NetworkPolicy per namespace | 29 |
| ZT-ID-04 | No cluster-wide secret read / RBAC escalation for workloads | 24 |
| ZT-WL-02 | Workload meets Pod Security Standard 'restricted' | 24 |
| ZT-ID-01 | Dedicated workload identity (no default SA) | 10 |
| ZT-WL-01 | No privileged / root containers | 8 |
| ZT-ID-03 | Least-privilege RBAC (no cluster-admin workloads) | 2 |
