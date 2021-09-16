# Equivalent of docker.io/golang:1.16.5-buster on June 24 2021
FROM docker.io/golang@sha256:ff1931f625a79c1030d01979d8a70fa31a78d3827a69fc48f403cd5d8dbf9861 as build
ARG TOKEN

RUN echo "\
deb http://snapshot.debian.org/archive/debian/20210621T000000Z buster main\n\
deb http://snapshot.debian.org/archive/debian-security/20210621T000000Z buster/updates main\n\
deb http://snapshot.debian.org/archive/debian/20210621T000000Z buster-updates main\n\
deb http://snapshot.debian.org/archive/debian/20210621T000000Z buster-backports main\
" > /etc/apt/sources.list

# NOTICE: -o Acquire::Check-Valid-Until="false" added as a mitigation, see https://github.com/parca-dev/parca-agent/issues/10 for further details.
RUN apt-get -o Acquire::Check-Valid-Until="false" update -y && apt-get install -y clang-11 make gcc coreutils elfutils binutils zlib1g-dev libelf-dev ca-certificates netbase && \
        ln -s /usr/bin/clang-11 /usr/bin/clang && \
        ln -s /usr/bin/llc-11 /usr/bin/llc
WORKDIR /parca-agent

RUN go env -w GOPRIVATE=github.com/parca-dev && git config --global url."https://parca:${TOKEN}@github.com".insteadOf "https://github.com"
COPY go.mod go.sum /parca-agent/
RUN go mod download -modcacherw

COPY parca-agent.bpf.c vmlinux.h Makefile /parca-agent/
COPY ./3rdparty /parca-agent/3rdparty
RUN make bpf

COPY . /parca-agent
RUN make build

# Equivalent of docker.io/debian:10.10-slim on June 24 2021
FROM docker.io/debian@sha256:c6e92d5b7730fdfc2753c4cce68c90d6c86a6a3391955549f9fe8ad6ce619ce0 as all
COPY --from=build /etc/nsswitch.conf /etc/nsswitch.conf
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /etc/services /etc/services
COPY --from=build /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/libpthread.so.0
COPY --from=build /usr/lib/x86_64-linux-gnu/libelf-0.176.so /usr/lib/x86_64-linux-gnu/libelf-0.176.so
COPY --from=build /usr/lib/x86_64-linux-gnu/libdw.so.1 /usr/lib/x86_64-linux-gnu/libdw.so.1
RUN ln -s /usr/lib/x86_64-linux-gnu/libelf-0.176.so /usr/lib/x86_64-linux-gnu/libelf.so.1
COPY --from=build /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1
COPY --from=build /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
COPY --from=build /usr/lib/x86_64-linux-gnu/libbfd-2.31.1-system.so /usr/lib/x86_64-linux-gnu/libbfd-2.31.1-system.so
COPY --from=build /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/libdl.so.2
COPY --from=build /usr/bin/eu-strip /usr/bin/eu-strip
COPY --from=build /usr/bin/objcopy /usr/bin/objcopy
COPY --from=build /parca-agent/dist/parca-agent /bin/parca-agent

FROM scratch

COPY --chown=0:0 --from=all / /
RUN chown -R nobody:nogroup /tmp

CMD ["/bin/parca-agent"]
