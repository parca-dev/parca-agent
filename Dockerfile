ARG GOLANG_BASE
ARG DEBIAN_BASE

FROM ${GOLANG_BASE} as build

# For more information about the snapshots, see: https://snapshot.debian.org/
RUN echo "\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye main\n\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye-updates main\n\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye-backports main\n\
deb http://snapshot.debian.org/archive/debian-security/20220420T025302Z bullseye-security main\n\
deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main\n\
deb-src http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main\n\
" > /etc/apt/sources.list

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - 

# NOTICE: -o Acquire::Check-Valid-Until="false" added as a mitigation, see https://github.com/parca-dev/parca-agent/issues/10 for further details.
RUN apt-get -o Acquire::Check-Valid-Until="false" update -y && \
      apt-get install --no-install-recommends -y clang-14 llvm-14 make gcc coreutils elfutils binutils zlib1g-dev libelf-dev ca-certificates netbase && \
      ln -s /usr/bin/clang-14 /usr/bin/clang && \
      ln -s /usr/bin/llc-14 /usr/bin/llc

WORKDIR /parca-agent

# Install Rust
COPY rust-toolchain.toml /parca-agent
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain none -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN RUSTUP_TOOLCHAIN="$(awk -F= '/channel/{channel=gsub("\"","",$2);print $channel}' rust-toolchain.toml)" \
    && rustup toolchain install "${RUSTUP_TOOLCHAIN}" --allow-downgrade --profile=minimal --component clippy

ARG ARCH
ENV GOOS=linux
ENV ARCH=$ARCH
ENV GOARCH=$ARCH

COPY go.mod go.sum /parca-agent/
RUN go mod download -modcacherw

COPY Makefile /parca-agent/
COPY bpf /parca-agent/bpf
RUN make -C bpf setup
RUN make bpf

COPY . /parca-agent
RUN git submodule init && git submodule update
RUN make build

FROM ${DEBIAN_BASE} as all

COPY --from=build /etc/nsswitch.conf /etc/nsswitch.conf
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /usr/bin/objcopy /usr/bin/objcopy
COPY --from=build /usr/bin/eu-strip /usr/bin/eu-strip
COPY --from=build /parca-agent/dist/parca-agent /bin/parca-agent

FROM scratch

COPY --chown=0:0 --from=all / /
RUN chown -R nobody:nogroup /tmp

CMD ["/bin/parca-agent"]
