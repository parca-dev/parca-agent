# https://github.com/hadolint/hadolint/issues/861
# hadolint ignore=DL3029
FROM --platform="${BUILDPLATFORM:-linux/amd64}" docker.io/library/busybox:1.36.1@sha256:82078ce09d47857439e17eb6a35b0c24ad5be8cde11f56f81c4e293029da727b as builder
RUN mkdir /.cache && touch -t 202101010000.00 /.cache

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT

RUN echo "Building for ${TARGETOS}/${TARGETARCH}/${TARGETVARIANT:-v1}"

WORKDIR /app
COPY goreleaser/dist dist

# NOTICE: See goreleaser.yml for the build paths.
RUN if [ "${TARGETARCH}" = 'amd64' ]; then \
        cp "dist/parca-agent-${TARGETARCH}_${TARGETOS}_${TARGETARCH}_${TARGETVARIANT:-v1}/parca-agent" . ; \
    elif [ "${TARGETARCH}" = 'arm' ]; then \
        cp "dist/parca-agent-${TARGETARCH}_${TARGETOS}_${TARGETARCH}_${TARGETVARIANT##v}/parca-agent" . ; \
    else \
        cp "dist/parca-agent-${TARGETARCH}_${TARGETOS}_${TARGETARCH}/parca-agent" . ; \
    fi
RUN chmod +x parca-agent

# hadolint ignore=DL3029
FROM --platform="${TARGETPLATFORM:-linux/amd64}" gcr.io/distroless/static@sha256:41972110a1c1a5c0b6adb283e8aa092c43c31f7c5d79b8656fbffff2c3e61f05

LABEL \
    org.opencontainers.image.source="https://github.com/parca-dev/parca-agent" \
    org.opencontainers.image.url="https://github.com/parca-dev/parca-agent" \
    org.opencontainers.image.description="eBPF based always-on profiler auto-discovering targets in Kubernetes and systemd, zero code changes or restarts needed!" \
    org.opencontainers.image.licenses="Apache-2.0"

COPY --chown=0:0 --from=builder /app/parca-agent /bin/parca-agent
COPY --chown=0:0 parca-agent.yaml /bin/parca-agent.yaml

CMD ["/bin/parca-agent"]
