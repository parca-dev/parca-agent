# glibc-dynamic rather than static: parca-agent is static, but the
# gpu-metrics-agent it launches is dynamically linked so it can dlopen
# libnvidia-ml (provided at runtime by the NVIDIA container toolkit / driver).
FROM cgr.dev/chainguard/glibc-dynamic:latest
USER root

COPY parca-agent /parca-agent
COPY gpu-metrics-agent /gpu-metrics-agent

ENTRYPOINT ["/parca-agent"]
