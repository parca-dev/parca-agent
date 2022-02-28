#!/usr/bin/env bash
set +x

MANIFEST="$1"
ARCHS=('arm64' 'amd64')
LINUX_ARCHS=('aarch64' 'x86_64')

# podman manifest inspect docker.io/golang:1.17.7-bullseye
# SHA order is respectively arm64, amd64
DOCKER_GOLANG_SHAS=(
    'docker.io/golang@sha256:55bebd100dc82c17d2111bff177156fd4aa4f5db37a396b5834c645b19208d44'
    'docker.io/golang@sha256:1996dda6ea808b9909acf67f594e68948bf630bade0bf61b3a2025f5aadc3ada'
)

# podman manifest inspect docker.io/debian:bullseye-slim
# SHA order is respectively arm64, amd64
DOCKER_DEBIAN_SHAS=(
    'docker.io/debian@sha256:306e5b78ae40c2467397e2cfb560dc9ff8ae935c1c7b2ed8224eb6aecc76cd32'
    'docker.io/debian@sha256:7c78fedca85eec82669ff06969250175edac0750cb883628dfe7be18cb906928'
)

for i in "${!ARCHS[@]}"; do
    ARCH=${ARCHS[$i]}
    LINUX_ARCH=${LINUX_ARCHS[$i]}
    DOCKER_GOLANG_SHA=${DOCKER_GOLANG_SHAS[$i]}
    DOCKER_DEBIAN_SHA=${DOCKER_DEBIAN_SHAS[$i]}
    echo "Building manifest for $MANIFEST with arch \"$ARCH\" which is linux-arch \"$LINUX_ARCH\""
    podman build \
        --build-arg GOLANG_BASE=$DOCKER_GOLANG_SHA \
        --build-arg DEBIAN_BASE=$DOCKER_DEBIAN_SHA \
        --build-arg ARCH=$ARCH \
        --build-arg ARCH=$ARCH \
        --build-arg LINUX_ARCH=$LINUX_ARCH \
        --arch $ARCH \
        --timestamp 0 \
        --manifest $MANIFEST .; \
done
