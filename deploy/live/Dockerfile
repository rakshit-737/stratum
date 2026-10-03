# Demo workload image for the live CI job (.github/workflows/live.yml). busybox = shell + nc + httpd.
FROM busybox:1.38.0@sha256:fd7dc98638c8e305f4dc34e979f1c0fdfdcaeb0fbf8fcff77ae834b6da3d7e6e
ARG REVISION=unknown
# per-run nonce: every live run gets its own digest, so each run reads its own Fulcio certificate
ARG NONCE=none
ARG DESCRIPTION="STRATUM live-CI demo workload (lab only)"
LABEL org.opencontainers.image.source="https://github.com/rakshit-737/stratum-cloud-security" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${NONCE}" \
      org.opencontainers.image.description="${DESCRIPTION}"
USER 65534:65534
CMD ["sleep", "infinity"]
