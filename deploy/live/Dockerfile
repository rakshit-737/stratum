# Demo workload image for the live CI job (.github/workflows/live.yml). busybox = shell + nc + httpd.
FROM busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/stratum" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.description="STRATUM live-CI demo workload (lab only)"
USER 65534:65534
CMD ["sleep", "infinity"]
