# parca-agent built with GPU metrics (build tag gpumetrics) is dynamically
# linked so it can dlopen libnvidia-ml, provided at runtime by the NVIDIA
# container toolkit / driver. Dockerfile.static packages the static build.
FROM cgr.dev/chainguard/glibc-dynamic:latest
USER root

COPY parca-agent /parca-agent

ENTRYPOINT ["/parca-agent"]
