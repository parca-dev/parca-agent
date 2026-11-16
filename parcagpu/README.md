# GPU event reporting

This package consumes parcagpu events, combines them with CPU traces and reports
GPU profiles. Cubin identity and debug-file uploads use the profiler's GPU package.

When a validated original cubin file is available, instruction lookup and uploads
read it instead of retaining code bytes. Otherwise, mnemonics use a byte-bounded
LRU cache enabled by setting `--gpu-cubin-cache-size` above its default of zero.
Eviction removes only mnemonics. Queued uploads can still retain the in-memory image.

See the profiler's [GPU design notes](https://github.com/parca-dev/opentelemetry-ebpf-profiler/blob/main/interpreter/gpu/README.md)
for file validation, loading-path coverage and probe compatibility.
