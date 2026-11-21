# GPU event reporting

This package consumes parcagpu events, combines them with CPU traces and reports
GPU profiles. Cubin identity and debug-file uploads use the profiler's GPU package.

## Profile types

| Sample type | Unit | Stack | Value |
| --- | --- | --- | --- |
| `gpu_kernel_time` | nanoseconds | CPU stack of the launch, with the kernel as the leaf frame | Kernel execution time |
| `gpu_pcsample` | count (period: nanoseconds per sample) | Launch stack, with the sampled kernel PC as the leaf frame | PC samples, one sample per stall reason (`cuda_stall_reason`) |
| `cuda_blocking_time` | nanoseconds | CPU stack of the caller of the CUDA API call | Host time blocked in the call |

With `--merge-gpu-profiles`, `gpu_kernel_time` and `gpu_pcsample` are reported
as one `gpu_time`/nanoseconds type, told apart by the `gpu_view` label.
`cuda_blocking_time` is never merged into it: it is host time, not GPU time.

`cuda_blocking_time` comes from parcagpu's `cuda_blocking_call` probe, which is
off by default. Set `PARCAGPU_BLOCKING_CALLS=1` in the workload to turn it on.
It covers calls that block the calling thread, such as synchronizes, synchronous
copies, allocation, freeing, pinning, module loading and graph instantiation.
Each sample is labeled `cuda_api` with the function (for example
`cudaStreamSynchronize` or `cuMemAlloc_v2`) and `cuda_device` when it is
known. parcagpu samples calls shorter than `PARCAGPU_BLOCKING_THRESHOLD_US`
(10 µs by default) with a weight of the threshold. Totals estimate blocked time
without bias, but the number of samples is not the number of calls.

## Cubins

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
