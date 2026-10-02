### Trivy scans of 49 real images (+ CISA KEV join)

| count | critical | high | medium | low |
|---|---:|---:|---:|---:|
| findings summed over images (each image counts a CVE x package pair once) | 15 | 432 | 342 | 326 |
| unique CVE x package pairs across the corpus | 10 | 156 | 157 | 98 |

Images with a critical CVE: 7; with a CISA KEV CVE: 0; shipping a shell: 18. Trivy 0.74.0; KEV catalog 2026.09.25 (1726 CVEs).

Blast radius by base OS release as reported by Trivy (workloads whose image is built on it; grouped by OS family + version, not by layer digest):

| base | workloads | examples |
|---|---:|---|
| `base:alpine 3.24.1` | 8 | jenkins/jenkins-ui-test-rixly, kube-flannel/kube-flannel-ds, online-boutique/currencyservice, online-boutique/emailservice, online-boutique/loadgenerator, online-boutique/paymentservice |
| `base:debian 13.6` | 5 | cert-manager/cert-manager, cert-manager/cert-manager-cainjector, cert-manager/cert-manager-webhook, kube-system/kube-state-metrics, kube-system/sealed-secrets-controller |
| `base:debian 13.7` | 5 | cnpg-system/cnpg-controller-manager, online-boutique/checkoutservice, online-boutique/frontend, online-boutique/productcatalogservice, online-boutique/shippingservice |
| `base:alpine 3.24.0` | 4 | knative-serving/activator, knative-serving/autoscaler, knative-serving/controller, knative-serving/webhook |
| `base:alpine 3.25.0_alpha20260805` | 4 | kyverno/kyverno-admission-controller, kyverno/kyverno-background-controller, kyverno/kyverno-cleanup-controller, kyverno/kyverno-reports-controller |
| `base:alpine 3.23.5` | 3 | flux-system/image-automation-controller, flux-system/image-reflector-controller, flux-system/source-watcher |
| `base:debian 12.14` | 2 | gatekeeper-system/gatekeeper-audit, gatekeeper-system/gatekeeper-controller-manager |
| `base:debian 13.5` | 2 | kube-system/metrics-server, metallb-system/controller |
| `base:photon 5.0` | 2 | redis-bitnami/redis-bitnami-master, redis-bitnami/redis-bitnami-replicas |
| `base:debian 13.4` | 2 | ingress-nginx/ingress-nginx-admission-create, ingress-nginx/ingress-nginx-admission-patch |
