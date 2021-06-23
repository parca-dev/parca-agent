# Equivalent of docker.io/golang:1.16-alpine
FROM docker.io/golang@sha256:34e3951701d7cc4153ca322933ed82edf8575af0d3f5c40362dca3b3c2bc425e as build
RUN apk --no-cache update && apk --no-cache add curl git clang llvm make gcc libc6-compat coreutils linux-headers musl-dev elfutils-dev libelf-static zlib-static && \
        mkdir -p /go/bin && curl -sL https://github.com/iovisor/bcc/raw/e83019bdf6c400b589e69c7d18092e38088f89a8/libbpf-tools/bin/bpftool > /go/bin/bpftool
WORKDIR /parca-agent
COPY . /parca-agent
RUN make bpf build

# Equivalent of docker.io/alpine:3.14.0
FROM docker.io/alpine@sha256:234cb88d3020898631af0ccbbcca9a66ae7306ecd30c9720690858c1b007d2a0
RUN apk --no-cache update && apk --no-cache add libc6-compat elfutils-dev binutils
COPY --from=build /parca-agent/dist/parca-agent /bin/parca-agent
CMD ["/bin/parca-agent"]
