FROM --platform="${BUILDPLATFORM:-linux/amd64}" docker.io/golang:1.18.3-bullseye@sha256:d146bc2ee9b0691f4f787bd9a8bf12e3c01a4618ea982d11fe9401b86211e2a7 AS builder
RUN mkdir /.cache && chown nobody:nogroup /.cache && touch -t 202101010000.00 /.cache

WORKDIR /app

COPY ./dist /app/dist
RUN if [ "amd64" = "$(go env GOARCH)" ]; then \
        cp "dist/parca-agent-amd64_$(go env GOOS)_$(go env GOARCH)_$(go env GOAMD64)/parca-agent" parca-agent; \
    else \
        cp "dist/parca-agent-arm64_$(go env GOOS)_$(go env GOARCH)/parca-agent" parca-agent; \
    fi

FROM --platform="${TARGETPLATFORM:-linux/amd64}" gcr.io/distroless/static@sha256:2ad95019a0cbf07e0f917134f97dd859aaccc09258eb94edcb91674b3c1f448f
COPY --chown=0:0 --from=builder /app/parca-agent /bin/parca-agent
CMD ["/bin/parca-agent"]
