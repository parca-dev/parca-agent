# GPU event reporting

This package consumes parcagpu events, combines them with CPU traces and reports
GPU profiles. Cubin identity and debug-file uploads use the profiler's GPU package.

When a validated original cubin file is available, instruction lookup and uploads
read it through the file descriptor held since validation instead of retaining code
bytes, so both survive process exit and the path being unlinked. Otherwise, mnemonics
use a byte-bounded LRU cache set by `--gpu-cubin-cache-size` (64 MiB by default, 0
disables it). Most kernels are loaded from memory rather than from a cubin file,
cuBLAS and PyTorch's included, so they depend on this cache. A sample that misses an
evicted cubin rereads it from process memory. Eviction removes only mnemonics.
Queued uploads can still retain the in-memory image.

See the profiler's [GPU design notes](https://github.com/parca-dev/opentelemetry-ebpf-profiler/blob/main/interpreter/gpu/README.md)
for file validation, loading-path coverage and probe compatibility.
