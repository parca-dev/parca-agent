# Equivalent of docker.io/golang:1.17.5-bullseye on 06.01.2022
FROM docker.io/golang@sha256:90fb73aa50a20c85ecfaf619002dceeabff306ae19beec149e6be39928ee7f2d as build

# For more information about the snapshots, see: https://snapshot.debian.org/
RUN echo "\
deb http://snapshot.debian.org/archive/debian/20220106T085239Z bullseye main\n\
deb http://snapshot.debian.org/archive/debian/20220106T085239Z bullseye-updates main\n\
deb http://snapshot.debian.org/archive/debian/20220106T085239Z bullseye-backports main\n\
deb http://snapshot.debian.org/archive/debian-security/20220104T163649Z bullseye-security main\
" > /etc/apt/sources.list

# NOTICE: -o Acquire::Check-Valid-Until="false" added as a mitigation, see https://github.com/parca-dev/parca-agent/issues/10 for further details.
RUN apt-get -o Acquire::Check-Valid-Until="false" update -y && \
      apt-get install -y clang-11 make gcc coreutils elfutils binutils zlib1g-dev libelf-dev ca-certificates netbase && \
      ln -s /usr/bin/clang-11 /usr/bin/clang && \
      ln -s /usr/bin/llc-11 /usr/bin/llc
WORKDIR /parca-agent

COPY go.mod go.sum /parca-agent/
RUN go mod download -modcacherw

COPY parca-agent.bpf.c vmlinux.h Makefile /parca-agent/
COPY ./3rdparty /parca-agent/3rdparty
RUN make bpf

COPY . /parca-agent
RUN make build

# Equivalent of docker.io/debian:bullseye-slim on 06.01.2022
FROM docker.io/debian@sha256:96e65f809d753e35c54b7ba33e59d92e53acc8eb8b57bf1ccece73b99700b3b0 as all
COPY --from=build /etc/nsswitch.conf /etc/nsswitch.conf
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build /lib/x86_64-linux-gnu/libpthread.so.0 /lib/x86_64-linux-gnu/libpthread.so.0
COPY --from=build /usr/lib/x86_64-linux-gnu/libelf-0.183.so /usr/lib/x86_64-linux-gnu/libelf-0.183.so
COPY --from=build /usr/lib/x86_64-linux-gnu/libdw.so.1 /usr/lib/x86_64-linux-gnu/libdw.so.1
RUN ln -s /usr/lib/x86_64-linux-gnu/libelf-0.183.so /usr/lib/x86_64-linux-gnu/libelf.so.1
COPY --from=build /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1
COPY --from=build /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6
COPY --from=build /usr/lib/x86_64-linux-gnu/libbfd-2.35.2-system.so /usr/lib/x86_64-linux-gnu/libbfd-2.35.2-system.so
COPY --from=build /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/libdl.so.2
COPY --from=build /usr/bin/objcopy /usr/bin/objcopy
COPY --from=build /usr/bin/eu-strip /usr/bin/eu-strip
COPY --from=build /parca-agent/dist/parca-agent /bin/parca-agent

FROM scratch

COPY --chown=0:0 --from=all / /
RUN chown -R nobody:nogroup /tmp

CMD ["/bin/parca-agent"]
