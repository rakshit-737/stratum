#!/usr/bin/env bash
# Benign but attack-shaped actions inside the demo pod. Nothing leaves the cluster.
set -euo pipefail
NS=stratum-live
POD=$(kubectl -n $NS get pod -l app=web -o jsonpath='{.items[0].metadata.name}')
kubectl -n $NS exec "$POD" -- sh -c 'id; uname -a'                                     # shell spawn
kubectl -n $NS exec "$POD" -- sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null'  # SA token read
kubectl -n $NS exec "$POD" -- sh -c 'echo ping | nc -w 3 sink.stratum-live.svc.cluster.local 8080 || true' # egress to local sink
