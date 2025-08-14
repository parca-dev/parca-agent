[![Apache 2 License](https://img.shields.io/badge/license-Apache%202-blue.svg)](LICENSE)
![Build](https://github.com/parca-dev/parca-agent/actions/workflows/build.yml/badge.svg)
![Container](https://github.com/parca-dev/parca-agent/actions/workflows/container.yml/badge.svg)
[![parca-agent](https://snapcraft.io/parca-agent/badge.svg)](https://snapcraft.io/parca-agent)

# Parca Agent

Parca Agent is an always-on sampling profiler that uses eBPF to capture raw profiling data with very low overhead. It observes user-space and kernel-space stacktraces [19 times per second](https://www.parca.dev/docs/parca-agent-design#cpu-sampling-frequency) and builds [pprof](https://github.com/google/pprof) formatted profiles from the extracted data. Read more details in the [design documentation](https://www.parca.dev/docs/parca-agent-design).

The collected data can be viewed locally via HTTP endpoints and then be configured to be sent to a [Parca](https://github.com/parca-dev/parca) server to be queried and analyzed over time.

## Requirements

- Linux Kernel version 5.3+ with BTF

## Quickstart

See the [Kubernetes Getting Started](https://www.parca.dev/docs/kubernetes).

## Language Support

Parca Agent is continuously enhancing its support for multiple languages.
Incomplete list of languages we currently support:

- C, C++, Go (with extended support), Rust
- .NET, Deno, Erlang, Java, Julia, Node.js, Wasmtime, PHP 8 and above
- Ruby, Python

Please check [our docs](https://www.parca.dev/docs/parca-agent-language-support) for further information.

> [!NOTE]
> [Further language support](https://github.com/parca-dev/parca-agent/issues?q=is%3Aissue+is%3Aopen+label%3Afeature%2Flanguage-support) is coming in the upcoming weeks and months.

## Supported Profiles

Types of profiles that are available:

- On-CPU
- Soon: Network usage, Allocations

> [!NOTE]
> Please check [our docs](https://www.parca.dev/docs/parca-agent-language-support) if your language is supported.

The following types of profiles require explicit instrumentation:

- Runtime specific information such as Goroutines

## Debugging

### Logging

To debug potential errors, enable debug logging using `--log-level=debug`.

## Configuration

<details><summary>Flags:</summary>
<p>

[embedmd]:# (dist/help.txt)
```txt
Usage: parca-agent

Flags:
  -h, --help                       Show context-sensitive help.
      --log-level="info"           Log level.
      --log-format="logfmt"        Configure if structured logging as JSON or as
                                   logfmt
      --http-address="127.0.0.1:7071"
                                   Address to bind HTTP server to.
      --version                    Show application version.
      --environment-type=STRING    The type of environment.
      --machine-id=STRING          The machine ID.
      --include-env-var=INCLUDE-ENV-VAR,...
                                   Environment variables to include in the
                                   profile.
      --otel-tags=""               Otel tags to attach to all traces.
      --tracers="all"              Tracers to enable.
      --node="hostname"            The name of the node that the process is
                                   running on. If on Kubernetes, this must match
                                   the Kubernetes node name.
      --config-path=""             Path to config file.
      --memlock-rlimit=0           [deprecated] The value for the maximum number
                                   of bytes of memory that may be locked into
                                   RAM. It is used to ensure the agent can lock
                                   memory for eBPF maps. 0 means no limit.
      --mutex-profile-fraction=0
                                   Fraction of mutex profile samples to collect.
      --block-profile-rate=0       Sample rate for block profile.
      --profiling-duration=5s      The agent profiling duration to use. Leave
                                   this empty to use the defaults.
      --profiling-cpu-sampling-frequency=19
                                   The frequency at which profiling data is
                                   collected, e.g., 19 samples per second.
      --profiling-perf-event-buffer-poll-interval=250ms
                                   [deprecated] The interval at which the perf
                                   event buffer is polled for new events.
      --profiling-perf-event-buffer-processing-interval=100ms
                                   [deprecated] The interval at which the perf
                                   event buffer is processed.
      --profiling-perf-event-buffer-worker-count=4
                                   [deprecated] The number of workers that
                                   process the perf event buffer.
      --profiling-probabilistic-interval=1m
                                   Time interval for which probabilistic
                                   profiling will be enabled or disabled.
      --profiling-probabilistic-threshold=100
                                   If set to a value between 1 and 99
                                   will enable probabilistic profiling:
                                   every probabilistic-interval a random number
                                   between 0 and 99 is chosen. If the given
                                   probabilistic-threshold is greater than
                                   this random number, the agent will collect
                                   profiles from this system for the duration of
                                   the interval.
      --profiling-enable-error-frames
                                   Enable collection of error frames.
      --metadata-external-labels=KEY=VALUE;...
                                   Label(s) to attach to all profiles.
      --metadata-container-runtime-socket-path=STRING
                                   The filesystem path to the container runtimes
                                   socket. Leave this empty to use the defaults.
      --metadata-disable-caching
                                   [deprecated] Disable caching of metadata.
      --metadata-enable-process-cmdline
                                   [deprecated] Add /proc/[pid]/cmdline as a
                                   label, which may expose sensitive information
                                   like secrets in profiling data.
      --local-store-directory=STRING
                                   The local directory to store the profiling
                                   data.
      --remote-store-address=STRING
                                   gRPC address to send profiles and symbols to.
      --remote-store-bearer-token=STRING
                                   Bearer token to authenticate with store
                                   ($PARCA_BEARER_TOKEN).
      --remote-store-bearer-token-file=STRING
                                   File to read bearer token from to
                                   authenticate with store.
      --remote-store-insecure      Send gRPC requests via plaintext instead of
                                   TLS.
      --remote-store-insecure-skip-verify
                                   Skip TLS certificate verification.
      --remote-store-batch-write-interval=10s
                                   [deprecated] Interval between batch remote
                                   client writes. Leave this empty to use the
                                   default value of 10s.
      --remote-store-rpc-logging-enable
                                   [deprecated] Enable gRPC logging.
      --remote-store-rpc-unary-timeout=5m
                                   [deprecated] Maximum timeout window for unary
                                   gRPC requests including retries.
      --remote-store-grpc-max-call-recv-msg-size=33554432
                                   The maximum message size the client can
                                   receive.
      --remote-store-grpc-max-call-send-msg-size=33554432
                                   The maximum message size the client can send.
      --remote-store-grpc-startup-backoff-time=1m
                                   The time between failed gRPC requests during
                                   startup phase.
      --remote-store-grpc-connection-timeout=3s
                                   The timeout duration for gRPC connection
                                   establishment.
      --remote-store-grpc-max-connection-retries=5
                                   The maximum number of retries to establish a
                                   gRPC connection.
      --debuginfo-directories=/usr/lib/debug,...
                                   Ordered list of local directories to search
                                   for debuginfo files.
      --debuginfo-temp-dir="/tmp"
                                   The local directory path to store the interim
                                   debuginfo files.
      --debuginfo-strip            Only upload information needed for
                                   symbolization. If false the exact binary the
                                   agent sees will be uploaded unmodified.
      --debuginfo-compress         Compress debuginfo files' DWARF sections
                                   before uploading.
      --debuginfo-upload-disable
                                   Disable debuginfo collection and upload.
      --debuginfo-upload-max-parallel=25
                                   The maximum number of debuginfo upload
                                   requests to make in parallel.
      --debuginfo-upload-timeout-duration=2m
                                   The timeout duration to cancel upload
                                   requests.
      --debuginfo-upload-cache-duration=5m
                                   The duration to cache debuginfo upload
                                   responses for.
      --debuginfo-disable-caching
                                   Disable caching of debuginfo.
      --debuginfo-upload-queue-size=4096
                                   The maximum number of debuginfo upload
                                   requests to queue. If the queue is full,
                                   new requests will be dropped.
      --symbolizer-jit-disable     [deprecated] Disable JIT symbolization.
      --otlp-address=STRING        The endpoint to send OTLP traces to.
      --otlp-exporter="grpc"       The OTLP exporter to use.
      --object-file-pool-eviction-policy="lru"
                                   [deprecated] The eviction policy to use for
                                   the object file pool.
      --object-file-pool-size=100
                                   [deprecated] The maximum number of object
                                   files to keep in the pool. This is used to
                                   avoid re-reading object files from disk.
                                   It keeps FDs open, so it should be kept in
                                   sync with ulimits. 0 means no limit.
      --clock-sync-interval=3m     How frequently to synchronize with the
                                   realtime clock.
      --dwarf-unwinding-disable    [deprecated] Do not unwind using .eh_frame
                                   information.
      --dwarf-unwinding-mixed      [deprecated] Unwind using .eh_frame
                                   information and frame pointers.
      --python-unwinding-disable
                                   [deprecated] Disable Python unwinder.
      --ruby-unwinding-disable     [deprecated] Disable Ruby unwinder.
      --java-unwinding-disable     [deprecated] Disable Java unwinder.
      --collect-custom-labels      Attempt to collect custom labels (e.g.
                                   trace ID) from the process.
      --analytics-opt-out          Opt out of sending anonymous usage
                                   statistics.
      --telemetry-disable-panic-reporting

      --telemetry-stderr-buffer-size-kb=4096

      --bpf-verbose-logging        Enable verbose BPF logging.
      --bpf-events-buffer-size=8192
                                   Size in pages of the events buffer.
      --bpf-map-scale-factor=0     Scaling factor for eBPF map sizes. Every
                                   increase by 1 doubles the map size. Increase
                                   if you see eBPF map size errors. Default is
                                   0 corresponding to 4GB of executable address
                                   space, max is 8.
      --bpf-verifier-log-level=0
                                   Log level of the eBPF verifier output
                                   (0,1,2). Default is 0.
      --bpf-verifier-log-size=0    [deprecated] Unused.
      --offline-mode-storage-path=STRING
                                   Enables offline mode, with the data stored at
                                   the given path.
      --offline-mode-rotation-interval=10m
                                   How often to rotate and compress the offline
                                   mode log.
      --offline-mode-upload        Run the uploader for data written in offline
                                   mode.
      --off-cpu-threshold=0        The probability (0.0-1.0) of off-CPU event
                                   being recorded.
```

</p>
</details>

## Metadata Labels

Parca Agent supports [Prometheus relabeling](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config). The following labels are always attached to profiles:

* `node`: The name of the node that the process is running on as specified by the `--node` flag.
* `comm`: The command name of the process being profiled.

And optionally you can attach additional labels using the `--metadata-external-labels` flag.

Using relabeling the following labels can be attached to profiles:

* `__meta_process_pid`: The process ID of the process being profiled.
* `__meta_process_cmdline`: The command line arguments of the process being profiled.
* `__meta_env_var_*`: The value of the environment variable `*` of the process being profiled. Note that the environment variables to pick up must be specified by `--include-env-var` flag.
* `__meta_process_cgroup`: The (main) cgroup of the process being profiled.
* `__meta_process_ppid`: The parent process ID of the process being profiled.
* `__meta_process_executable_file_id`: The file ID (a hash) of the executable of the process being profiled.
* `__meta_process_executable_name`: The basename of the executable of the process being profiled.
* `__meta_process_executable_build_id`: The build ID of the executable of the process being profiled.
* `__meta_process_executable_compiler`: The compiler used to build the executable of the process being profiled.
* `__meta_process_executable_static`: Whether the executable of the process being profiled is statically linked.
* `__meta_process_executable_stripped`: Whether the executable of the process being profiled is stripped from debuginfo.
* `__meta_system_kernel_release`: The kernel release of the system.
* `__meta_system_kernel_machine`: The kernel machine of the system (typically the architecture).
* `__meta_thread_comm`: The command name of the thread being profiled.
* `__meta_thread_id`: The PID of the thread being profiled.
* `__meta_agent_revision`: The revision of the agent.
* `__meta_kubernetes_namespace`: The namespace of the pod the process is running in.
* `__meta_kubernetes_pod_name`: The name of the pod the process is running in.
* `__meta_kubernetes_pod_label_*`: The value of the label `*` of the pod the process is running in.
* `__meta_kubernetes_pod_labelpresent_*`: Whether the label `*` of the pod the process is running in is present.
* `__meta_kubernetes_pod_annotation_*`: The value of the annotation `*` of the pod the process is running in.
* `__meta_kubernetes_pod_annotationpresent_*`: Whether the annotation `*` of the pod the process is running in is present.
* `__meta_kubernetes_pod_ip`: The IP of the pod the process is running in.
* `__meta_kubernetes_pod_container_name`: The name of the container the process is running in.
* `__meta_kubernetes_pod_container_id`: The ID of the container the process is running in.
* `__meta_kubernetes_pod_container_image`: The image of the container the process is running in.
* `__meta_kubernetes_pod_container_init`: Whether the container the process is running in is an init container.
* `__meta_kubernetes_pod_ready`: Whether the pod the process is running in is ready.
* `__meta_kubernetes_pod_phase`: The phase of the pod the process is running in.
* `__meta_kubernetes_node_name`: The name of the node the process is running on.
* `__meta_kubernetes_pod_host_ip`: The host IP of the pod the process is running in.
* `__meta_kubernetes_pod_uid`: The UID of the pod the process is running in.
* `__meta_kubernetes_pod_controller_kind`: The kind of the controller of the pod the process is running in.
* `__meta_kubernetes_pod_controller_name`: The name of the controller of the pod the process is running in.
* `__meta_kubernetes_node_label_*`: The value of the label `*` of the node the process is running on.
* `__meta_kubernetes_node_labelpresent_*`: Whether the label `*` of the node the process is running on is present.
* `__meta_kubernetes_node_annotation_*`: The value of the annotation `*` of the node the process is running on.
* `__meta_kubernetes_node_annotationpresent_*`: Whether the annotation `*` of the node the process is running on is present.
* `__meta_docker_container_id`: The ID of the container the process is running in.
* `__meta_docker_container_name`: The name of the container the process is running in.
* `__meta_docker_build_kit_container_id`: The ID of the container the process is running in.
* `__meta_containerd_container_id`: The ID of the container the process is running in.
* `__meta_containerd_container_name`: The name of the container the process is running in.
* `__meta_containerd_pod_name`: The name of the pod the process is running in.
* `__meta_lxc_container_id`: The ID of the container the process is running in.
* `__meta_cpu`: The CPU the sample was taken on.

## Security

Parca Agent is required to be running as `root` user (or `CAP_SYS_ADMIN`). Various security precautions have been taken to protect users running Parca Agent. See details in [Security Considerations](https://www.parca.dev/docs/parca-agent-security).

To report a security vulnerability, see [this guide](https://www.parca.dev/docs/parca-agent-security#report-security-vulnerabilities).

## Contributing

Check out our [Contributing Guide](CONTRIBUTING.md) to get started!

## License

User-space code: Apache 2

Kernel-space code (eBPF profilers): GNU General Public License, version 2

## Credits

Thanks to:

- Kinvolk for creating [Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget); some parts of this project were inspired by parts of it.
