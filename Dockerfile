# https://github.com/hadolint/hadolint/issues/861
# hadolint ignore=DL3029
FROM --platform="${BUILDPLATFORM:-linux/amd64}" docker.io/library/busybox:1.35.0@sha256:8ea4da552e6f32d24f366f3517170f045354d45adad3434843bf0fbb9c002638 as builder
RUN mkdir /.cache && touch -t 202101010000.00 /.cache

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TARGETVARIANT

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
FROM --platform="${TARGETPLATFORM:-linux/amd64}" gcr.io/distroless/static@sha256:f4787e810dbc39dd59fcee319cf88e8a01181e1758dbd07c32ed4e14a9ba8904
COPY --chown=0:0 --from=builder /app/parca-agent /bin/parca-agent
CMD ["/bin/parca-agent"]
