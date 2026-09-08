# syntax=docker/dockerfile:1
FROM --platform=linux/amd64 gcr.io/cloud-marketplace-tools/k8s/deployer_envsubst/onbuild

LABEL com.googleapis.cloudmarketplace.product.service.name="services/parca-agent.endpoints.polar-signals-public.cloud.goog"

# Marketplace flags this image for CVE-2026-39821 (GO_STDLIB, go1.26.5, fixed
# in go1.26.6). The finding is not ours: the only Go binary in the whole image
# is /opt/kubectl/v1.36/kubectl, which ships in Google's deployer_envsubst base.
#
# We cannot fix it by rebuilding. onbuild:latest and public-image-13.0.10 are
# the same digest (2026-08-18), so there is no newer base, and upstream's
# newest v1.36 patch (v1.36.4) is also built with go1.26.5. kubectl v1.37.0 is
# the first release built with go1.26.6, so overlay that.
#
# /usr/bin/kubectl picks a binary by server version and falls back to
# /opt/kubectl/default, a symlink to this directory, so replacing the binary in
# place keeps that logic working. The directory name stays v1.36 for the same
# reason. Note this narrows server skew support from 1.35-1.37 to 1.36-1.38.
#
# Drop this once Google rebuilds the base against go1.26.6 or later.
ADD --chmod=0755 \
    --checksum=sha256:6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f \
    https://dl.k8s.io/release/v1.37.0/bin/linux/amd64/kubectl \
    /opt/kubectl/v1.36/kubectl
