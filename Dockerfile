FROM golang:1.16-alpine as build
RUN apk --no-cache update && apk --no-cache add curl git clang llvm make gcc libc6-compat coreutils linux-headers musl-dev elfutils-dev libelf-static zlib-static && \
        mkdir -p /go/bin && curl -sL https://github.com/iovisor/bcc/raw/e83019bdf6c400b589e69c7d18092e38088f89a8/libbpf-tools/bin/bpftool > /go/bin/bpftool
WORKDIR /polarsignals-agent
COPY . /polarsignals-agent
RUN make bpf build

FROM alpine
RUN apk --no-cache update && apk --no-cache add libc6-compat elfutils-dev
COPY --from=build /polarsignals-agent/dist/polarsignals-agent /bin/polarsignals-agent
CMD ["/bin/polarsignals-agent"]
