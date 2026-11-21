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

## Controlling parcagpu (`--gpu-pc-sampling-control`)

By default every instrumented CUDA process configures parcagpu from its own
`PARCAGPU_*` environment variables (see parcagpu's README). With
`--gpu-pc-sampling-control`, parca-agent configures them instead, at runtime,
over [procctl](https://github.com/parca-dev/procctl): it finds each process that
loaded parcagpu, writes it a configuration, and reads back the GPUs it uses and
what is in effect. The code is in [`control/`](control/); the schema is
[`control/parcagpu_ctl.h`](control/parcagpu_ctl.h), copied from parcagpu.

What the agent does with it:

- **PC sampling in turns.** CUPTI can PC sample one process per GPU at a time,
  so the agent gives each GPU to one process at a time and rotates it every
  `turn`. Only processes that ran kernels in the last 10 s take turns. A
  granted process samples in windows of `window` with `gap` between them, each
  opening on the first kernel launch after the gap: a duty cycle of
  window/(window+gap), 10% by default. This replaces parcagpu's standalone
  dice roll and `PARCAGPU_PC_SAMPLING_RATE`, which don't apply under the agent.
- **Launch probe rate limits** (`rate_limit`, `graph_rate_limit`).
- **Optional instrumentation** (`kernel_stats`, `blocking_calls`). Under the
  agent each is off unless the agent turns it on.

When parca-agent stops it releases the processes, and they go back to their
environment. If it dies without releasing them, they keep its configuration for
`--gpu-pc-sampling-lease` (10 s), then go back.

### Settings

Each setting has a flag, which sets its value at startup. The settings file and
`/gpu-control` can change any of them while the agent runs.

| Key | Flag | Default | Meaning |
|---|---|---|---|
| `pc_sampling` | `--gpu-pc-sampling-control` | `true` | Whether processes take turns at PC sampling. `false` hands every GPU back, and no process samples, whatever its environment says. |
| `factor` | `--gpu-pc-sampling-factor` | `0` | CUPTI sampling period, 2^factor GPU cycles per SM, 5-31. 0 leaves it to the process: `PARCAGPU_SAMPLING_FACTOR`, else 20. |
| `window` | `--gpu-pc-sampling-window` | `30ms` | How long a sampling window stays open, 1ms-10s. Kernels run serialized while it is open, which is most of PC sampling's cost. |
| `gap` | `--gpu-pc-sampling-gap` | `270ms` | Pause between windows on a GPU, up to 60s. |
| `turn` | `--gpu-pc-sampling-turn` | `10s` | How long one process samples a GPU before the next takes over. |
| `scope` | `--gpu-pc-sampling-scope` | `gpu` | `gpu`: the processes on each GPU take turns, so different GPUs sample at once. `node`: all processes on the node, one at a time. |
| `rate_limit` | `--gpu-control-rate-limit` | `0` | Kernel launch events per second per thread that reach the probes (as `PARCAGPU_RATE_LIMIT`), up to 1000000. 0 leaves it to the process: its environment, else 100 split across the machine's GPUs. |
| `graph_rate_limit` | `--gpu-control-graph-rate-limit` | `0` | The same for CUDA graph launches (as `PARCAGPU_GRAPH_RATE_LIMIT`). 0: the environment, else 20 split across the machine's GPUs. |
| `kernel_stats` | `--gpu-control-kernel-stats` | `false` | Exact kernel execution counts and durations (parcagpu's `kernel_stats` probe), counted before the rate limits. Without the agent's control a process counts whenever a profiler listens; under it, only when this is on, so turn it on to keep the kernel execution metrics. |
| `blocking_calls` | `--gpu-control-blocking-calls` | `false` | Host time blocked in CUDA API calls (parcagpu's `cuda_blocking_call` probe). Its callbacks run on every covered API call, stream and event query polling included, so it costs more than the others. |
| `blocking_threshold` | `--gpu-control-blocking-threshold` | `0` | Threshold T for `blocking_calls`, whole microseconds up to 1s (as `PARCAGPU_BLOCKING_THRESHOLD_US`). Calls blocked at least T are reported with their duration; shorter ones with probability duration/T, weighted T, so summed weights estimate the total without bias. 0 leaves it to the process: its environment, else 10µs. The environment's "0 = every call" has no equivalent; 1µs differs from it only for calls under 1µs. |
| `metadata_refresh` | `--gpu-control-metadata-refresh` | `0` | How often processes re-emit cubins, the stall reason map and their GPU configuration, whole milliseconds (as `PARCAGPU_METADATA_REFRESH_MS`). A profiler that attaches while another is attached gets them only at the next refresh. 0: the environment, else 30s. A lower value applies at the next kernel launch. |
| `pc_hw_buffer_mb` | `--gpu-pc-sampling-hw-buffer-mb` | `0` | CUPTI's PC sampling hardware buffer, MB, up to 4096 (as `PARCAGPU_PC_HW_BUFFER_MB`). 0: the environment, else CUPTI's 512 MB. A context takes a new size at its next setup for PC sampling. On a GB10, forcing any size has made PC sampling return no samples, so leave it at 0 unless tested. |

`--gpu-pc-sampling-rescan` (how often /proc is scanned for new processes) and
`--gpu-pc-sampling-lease` are flags only. Three parcagpu environment variables
stay with each process: `PARCAGPU_PC_SAMPLING_RATE`, which drives the dice roll
that the agent's window and gap replace, and the diagnostics `PARCAGPU_DEBUG`
and `PARCAGPU_GATE_STATS`.

### Changing settings while the agent runs

`--gpu-control-file=PATH` names a YAML (or JSON) file with any of the keys
above. The agent re-reads it every 5 s. A key the file sets replaces the flag; a
key it leaves out keeps the flag's value. A missing file leaves the flags; an
invalid one is logged and ignored, and the settings stay as they were. Mount a
ConfigMap as a directory (not with `subPath`) and edits reach the agent within
about a minute.

`--gpu-control-http` serves the settings at `/gpu-control` on `--http-address`.
`GET` shows the settings in effect, in the file format. `PUT` applies a body in
the file format over the flags, not over the previous request, and answers with
the result. The next change to the settings file replaces it again.

```sh
curl -s localhost:7071/gpu-control
curl -s -X PUT --data-binary $'gap: 970ms\nblocking_calls: true\n' localhost:7071/gpu-control
```

Every process is told at the next tick, within 250 ms.

### Settings per workload

`workloads` gives some workloads their own settings:

```yaml
gap: 970ms
workloads:
  - name: vllm             # service.name
    namespace: inference   # optional: service.namespace or pod namespace
    factor: 18
    blocking_calls: true
  - name: batch-train
    pc_sampling: false
```

A process is named by the OTel `service.name` it declares (`OTEL_SERVICE_NAME`,
`service.name` in `OTEL_RESOURCE_ATTRIBUTES`, or its process context) or, failing
that, the one OTel infers from its Kubernetes pod. An entry with a `namespace`
beats one without. Each entry can override any key but `turn` and `scope`, which
are about sharing a GPU and so only global. A process that matches no entry
gets the global settings, and one that is renamed later (an SDK publishing its
process context after start) moves to its workload's settings at the next tick.

### Metrics

| Metric | Meaning |
|---|---|
| `parca_agent_gpu_control_setting{setting, workload}` | Settings in effect, globally (`workload=""`) and per configured workload. Durations in seconds, booleans 0 or 1. |
| `parca_agent_gpu_control_workload_processes{workload}` | Processes using each workload's settings, and the global ones. |
| `parca_agent_gpu_pc_sampling_holder{gpu_uuid}` | Host pid allowed to PC sample each GPU (or `node`), 0 for none. |
| `parca_agent_gpu_pc_sampling_rotations_total` | Turns handed from one process to the next. |
| `parca_agent_gpu_pc_sampling_handover_timeouts_total` | Hand-overs abandoned because the holder didn't stop sampling within 5 s. |

### parcagpu versions

The agent controls processes whose parcagpu speaks control schema version 2 or
later (parcagpu#35, #43, #44). Older ones, including the unreleased version 1,
keep running on their environment, and the agent logs a warning for each.
`blocking_threshold`, `metadata_refresh` and `pc_hw_buffer_mb` need version 3;
a version 2 process gets everything else and keeps its environment's for those.
