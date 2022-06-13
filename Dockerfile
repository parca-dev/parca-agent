ARG GOLANG_BASE
ARG DEBIAN_BASE

FROM ${GOLANG_BASE} as build

# tag=1.24.3
ARG RUSTUP_VERSION=ce5817a94ac372804babe32626ba7fd2d5e1b6ac

# For more information about the snapshots, see: https://snapshot.debian.org/
RUN echo "\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye main\n\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye-updates main\n\
deb http://snapshot.debian.org/archive/debian/20220420T025302Z bullseye-backports main\n\
deb http://snapshot.debian.org/archive/debian-security/20220420T025302Z bullseye-security main\n\
" > /etc/apt/sources.list

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -

RUN echo "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-14 main\n" > /etc/apt/sources.list.d/llvm.list

# NOTICE: -o Acquire::Check-Valid-Until="false" added as a mitigation, see https://github.com/parca-dev/parca-agent/issues/10 for further details.
RUN apt-get -o Acquire::Check-Valid-Until="false" update -y && \
      apt-get install --no-install-recommends -yq llvm-14-dev libclang-14-dev clang-14 make gcc coreutils elfutils binutils zlib1g-dev libelf-dev ca-certificates netbase && \
      ln -s /usr/bin/clang-14 /usr/bin/clang && \
      ln -s /usr/bin/llc-14 /usr/bin/llc

WORKDIR /parca-agent

# Install Rust
COPY rust-toolchain.toml /parca-agent
RUN curl --proto '=https' --tlsv1.2 -sSf "https://raw.githubusercontent.com/rust-lang/rustup/${RUSTUP_VERSION}/rustup-init.sh" \
    | sh -s -- --default-toolchain none -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup show

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

ARG LINUX_ARCH
ENV LINUX_ARCH=$LINUX_ARCH

# Dependencies for objcopy and eu-strip.
COPY --from=build /lib/${LINUX_ARCH}-linux-gnu/libpthread.so.0 /lib/${LINUX_ARCH}-linux-gnu/libpthread.so.0
COPY --from=build /usr/lib/${LINUX_ARCH}-linux-gnu/libelf-0.183.so /usr/lib/${LINUX_ARCH}-linux-gnu/libelf-0.183.so
COPY --from=build /usr/lib/${LINUX_ARCH}-linux-gnu/libdw.so.1 /usr/lib/${LINUX_ARCH}-linux-gnu/libdw.so.1
RUN ln -s /usr/lib/${LINUX_ARCH}-linux-gnu/libelf-0.183.so /usr/lib/${LINUX_ARCH}-linux-gnu/libelf.so.1
COPY --from=build /lib/${LINUX_ARCH}-linux-gnu/libz.so.1 /lib/${LINUX_ARCH}-linux-gnu/libz.so.1
COPY --from=build /lib/${LINUX_ARCH}-linux-gnu/libc.so.6 /lib/${LINUX_ARCH}-linux-gnu/libc.so.6
COPY --from=build /usr/lib/${LINUX_ARCH}-linux-gnu/libbfd-2.35.2-system.so /usr/lib/${LINUX_ARCH}-linux-gnu/libbfd-2.35.2-system.so
COPY --from=build /lib/${LINUX_ARCH}-linux-gnu/libdl.so.2 /lib/${LINUX_ARCH}-linux-gnu/libdl.so.2

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
