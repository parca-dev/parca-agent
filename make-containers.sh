#!/usr/bin/env bash
set +euxo pipefail

MANIFEST="$1"
ARCHS=('arm64' 'amd64')
LINUX_ARCHS=('aarch64' 'x86_64')

# podman manifest inspect docker.io/golang:1.18.1-bullseye
# SHA order is respectively arm64, amd64
DOCKER_GOLANG_SHAS=(
    'docker.io/golang@sha256:301d39546808488f001760626a904b6aa4bb6e8f94a79bdd43776d990ad6c28e'
    'docker.io/golang@sha256:ee752bc53c628ff789bacefb714cff721701042ffa9eb736f7b2ed4e9f2bdab6'
)

# podman manifest inspect docker.io/debian:bullseye-slim
# SHA order is respectively arm64, amd64
DOCKER_DEBIAN_SHAS=(
    'docker.io/debian@sha256:fc7792ebc6819bf63f967a6039f2f35346e7fa8f3650f8dd58f596c3da1a9882'
    'docker.io/debian@sha256:fa4209bc498f3cf557c7d448f295d300aed44e7fd296fdd480a8ff5785cca305'
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
        --build-arg LINUX_ARCH=$LINUX_ARCH \
        --arch $ARCH \
        --timestamp 0 \
        --manifest $MANIFEST .; \
done
