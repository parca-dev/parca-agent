FROM --platform="${BUILDPLATFORM:-linux/amd64}" docker.io/golang:1.18.3-bullseye@sha256:d146bc2ee9b0691f4f787bd9a8bf12e3c01a4618ea982d11fe9401b86211e2a7 AS build

# renovate: datasource:github-releases depName=rust-lang/rustup
ARG RUSTUP_VERSION=1.24.3

# For more information about the snapshots, see: https://snapshot.debian.org/
RUN printf '\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye main\n\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye-updates main\n\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye-backports main\n\
deb http://snapshot.debian.org/archive/debian-security/20220420T025302Z bullseye-security main\n\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z sid main\n\
' > /etc/apt/sources.list

# NOTICE: -o Acquire::Check-Valid-Until="false" added as a mitigation,
# see https://github.com/parca-dev/parca-agent/issues/10 for further details.
# hadolint ignore=DL3008
RUN apt-get -o Acquire::Check-Valid-Until="false" update -y && \
    apt-get install --no-install-recommends -yq \
        llvm-14-dev \
        libclang-14-dev \
        clang-14 \
        make \
        gcc \
        coreutils \
        zlib1g-dev \
        libelf-dev \
        ca-certificates \
        netbase && \
    ln -s /usr/bin/clang-14 /usr/bin/clang && \
    ln -s /usr/bin/llc-14 /usr/bin/llc

WORKDIR /parca-agent

# Install Rust
COPY rust-toolchain.toml /parca-agent
# SHELL is not supported for OCI image format
# https://github.com/containers/buildah/blob/v1.26.1/config.go#L366-L377
# hadolint ignore=DL4006
RUN curl --proto '=https' --tlsv1.2 -sSf "https://raw.githubusercontent.com/rust-lang/rustup/${RUSTUP_VERSION}/rustup-init.sh" \
    | sh -s -- --default-toolchain none -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup show

COPY go.mod go.sum /parca-agent/
RUN go mod download -modcacherw

COPY Makefile /parca-agent
COPY bpf /parca-agent/bpf
RUN make -C bpf setup
# hadolint ignore=DL3059
RUN make bpf

COPY . /parca-agent
RUN git submodule init && git submodule update

ARG TARGETARCH=amd64
ENV ARCH="${TARGETARCH}"
ENV GOOS=linux
ENV GOARCH="${TARGETARCH}"

# hadolint ignore=DL3008
RUN apt-get install --no-install-recommends -yq "libc6-dev-${TARGETARCH}-cross"

RUN export CC='clang'; \
    case "${TARGETARCH}" in \
      amd64) \
        export CPPFLAGS='--target=x86_64-pc-linux-gnu --sysroot=/usr/x86_64-linux-gnu -I/usr/include/x86_64-linux-gnu -I/usr/include'; \
        ;; \
      arm64) \
        export CPPFLAGS='--target=aarch64-pc-linux-gnu --sysroot=/usr/aarch64-linux-gnu -I/usr/include/aarch64-linux-gnu -I/usr/include'; \
        ;; \
      *) \
        export CPPFLAGS="--target=${TARGETARCH}-pc-linux-gnu --sysroot=/usr/${TARGETARCH}-linux-gnu -I/usr/include/${TARGETARCH}-linux-gnu -I/usr/include"; \
        ;; \
    esac; \
    make build

FROM --platform="${TARGETPLATFORM:-linux/amd64}" docker.io/debian:bullseye-slim@sha256:f6957458017ec31c4e325a76f39d6323c4c21b0e31572efa006baa927a160891 AS all

COPY --from=build /etc/nsswitch.conf /etc/nsswitch.conf
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /parca-agent/dist/parca-agent /bin/parca-agent

FROM scratch

COPY --chown=0:0 --from=all / /

CMD ["/bin/parca-agent"]
