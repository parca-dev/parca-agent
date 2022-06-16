#!/usr/bin/env bash
set -euo pipefail

MANIFEST="${1?Image name must be provided}"
ARCHS=('arm64' 'amd64')

for arch in "${ARCHS[@]}"; do
    printf 'Building manifest for %s with arch %s\n' "${MANIFEST}" "${arch}"
    podman build \
        --build-arg TARGETARCH="${arch}" \
        --arch "${arch}" \
        --timestamp 0 \
        --manifest "${MANIFEST}" .
done
