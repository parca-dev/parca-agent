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

Parca Agent supports specifying configuration through command-line flags or a YAML configuration file via `--config-path`. The configuration file can contain both relabel configurations and any CLI flag using hyphenated names (e.g., `log-level`, `http-address`). Command-line arguments take precedence over configuration file values, making it easy to override specific settings while maintaining a base configuration file.

### OTLP metadata

`--remote-store-format=otlp` exports resource attributes using OpenTelemetry semantic convention names without a relabel configuration. These include process and host identity, architecture and OS information, and, when discovered, Kubernetes pod/container/owner identity, container image information and cloud topology. Parent PIDs are integers; image tags and repository digests are string arrays. Service naming is unchanged: the application can declare its service identity, with the existing comm/executable fallback.

Metadata providers emit semconv keys directly in OTLP mode. There is no discovery-label promotion pass. Process, container and host metadata become resource attributes; CPU number, thread identity and custom sample labels become sample attributes. CPU and thread IDs are integers, and custom sample labels use the `process.context.label.*` prefix.

Optional relabel rules can override or remove the providers' resource attributes. When rules are configured, providers also supply the legacy `__meta_*` discovery labels for those rules; otherwise OTLP skips generating them. Command lines and arbitrary Kubernetes labels remain opt-in. [The Kubernetes relabel example](config/examples/otlp-semconv-k8s.yaml) shows additional policies such as deriving service names from pod labels. Arrow export keeps its existing labels and still uses relabel configuration.

`--metadata-external-labels=parca.agent=true` adds a string-valued resource attribute to every OTLP export: profiles, host and per-process GPU metrics, NVTX spans/logs, and the agent's diagnostic logs/traces. Repeat the flag to add more labels. Existing resource attributes take precedence, including the workload's `service.name`, discovered identity, and typed attributes. Arrow profiles keep their existing external-label behavior. Use source or cluster markers rather than pod/container/process identity for these global labels, because they also apply to node-wide metrics. The agent's own environment resource is not copied onto workload or host metric resources.

Collectors can route profiler telemetry on `resource.attributes["parca.agent"] == "true"` before Kubernetes enrichment on a shared OTLP receiver. Match the string `"true"`, not the boolean `true`. This marker does not itself perform pod association or protect node-wide metrics from connection-IP association; the collector still needs resource-based workload association and routing that preserves node telemetry. Choose a marker key that does not conflict with an existing resource attribute.

To delegate Kubernetes enrichment to a collector, set `--metadata-discovery=local`. This skips Kubernetes API clients, informers, and Docker/containerd/CRI clients and socket probing. It retains locally read container IDs, host/process/executable metadata, application-declared attributes and custom sample labels. It also reads `k8s.pod.uid` from Kubernetes cgroupfs or systemd cgroup paths, on cgroup v1 or v2. Static pod config hashes are not API pod UIDs and are not emitted as such. The setting also applies to the shared metadata used by OOM profiles, per-process GPU metrics and NVTX spans/logs. `full` remains the default discovery mode.

```console
parca-agent \
  --remote-store-format=otlp \
  --remote-store-address=otel-collector.observability.svc:4317 \
  --remote-store-insecure \
  --metadata-discovery=local \
  --debuginfo-upload-disable \
  --symbolize-go
```

This example uses plaintext transport inside the cluster. Omit `--remote-store-insecure` for TLS. It disables Parca debuginfo uploads because collectors do not implement that protocol, and enables local Go symbolization for a destination without a Go symbolizer. Symbols can instead go to a separate Parca debuginfo endpoint as described below.

The collector must support OTLP profiles and associate resources using `container.id` or `k8s.pod.uid`. Local mode needs no Kubernetes metadata RBAC or container runtime sockets, but still requires host PID/procfs access and the usual profiling privileges. Host processes without a container ID remain reportable. No `--config-path` or relabel configuration is needed for this example.

GPU metrics and NVTX spans/logs also need resource-based pod association in the collector. A discovered pod UID lets ordinary `k8s.pod.uid` association select the workload rather than the profiler pod. Configure `container.id` association for workloads whose cgroup path has no API pod UID, including static pods. The container ID must be available in the collector's pod cache.

Do not use sender connection-IP fallback for telemetry forwarded by the profiler: that connection identifies the profiler, not the workload. Node-wide GPU metrics intentionally carry only host/node identity, with no pod or container identity. The collector must bypass pod association for those resources, or use a profiler-specific pipeline with resource-only pod association and no connection fallback. Resources without a resolvable workload identity must remain unassociated; do not fill them with the profiler pod's identity. If other clients need connection-based association, keep their pipeline separate. Namespace filtering and export routing must also preserve node-wide metrics as node telemetry rather than treating them as belonging to the profiler namespace.

### Separate debuginfo endpoint

By default, profiles and debuginfo share the `--remote-store-address` connection, including its authentication and TLS settings. Set `--debuginfo-address` to upload debuginfo to a separate Parca DebuginfoService, regardless of the profile wire format:

```console
parca-agent \
  --remote-store-address=profiles.example.com:443 \
  --remote-store-bearer-token-file=/etc/parca/profile-token \
  --debuginfo-address=symbols.example.com:443 \
  --debuginfo-bearer-token-file=/etc/parca/symbol-token
```

An explicit debuginfo endpoint uses independent `--debuginfo-*` connection settings, not the `--remote-store-*` settings. These include bearer tokens, custom gRPC headers, TLS verification, mTLS client certificates, message size limits, and RPC timeouts. TLS is enabled by default; use `--debuginfo-insecure` for a plaintext endpoint. The debuginfo bearer token can also come from `PARCA_DEBUGINFO_BEARER_TOKEN`, independently of `PARCA_BEARER_TOKEN` for profiles.

The separate connection is lazy: an unavailable debuginfo service does not delay sampling startup or profile delivery. gRPC reconnects automatically. Connection startup retry flags do not apply to this lazy connection. Invalid local credentials or TLS configuration still fail startup. Upload work has a bounded queue, worker count, and retained-request cache. Each attempt has a five-minute deadline; retryable failures and `retry_required` responses defer another attempt by five minutes without occupying a worker. Recovery requires the source executable to remain accessible, and queue pressure can drop new requests until the executable is reported again.

The uploader supports both legacy single-upstream instructions and multiple upload targets. Targets transfer and complete independently, including partial-failure retries. A proxy configuration change can invalidate outstanding completions, so rotation is not seamless: drain uploads before changing destinations or credentials. Failed artifacts are renegotiated after the retry cooldown. There is no agent-side routing configuration or shared routing key.

If you already set `--debuginfo-address`, configure its credentials and TLS options with the corresponding `--debuginfo-*` flags. Without `--debuginfo-address`, debuginfo connection settings are ignored and the remote-store connection is reused. Debuginfo uploads remain disabled in offline mode or with `--debuginfo-upload-disable`.

For a trusted cluster network, the dash0-operator integration sends OTLP profiles to a same-node collector and debuginfo to a separate same-node proxy using `--debuginfo-insecure`, without agent-side backend credentials. Only the proxy holds those credentials. Disabling uploads needs no proxy. This is the Parca DebuginfoService protocol, not the built-in OpenTelemetry profiler's profile exporter.

### Go labels and symbolization

`--tracers=labels` enables Go goroutine labels and native custom labels without enabling Go symbolization. `all` also retains both label types. Tracer lists without `labels` or `all` do not implicitly enable labels. Go frames remain native for backend symbolization by default. To opt into local symbolization, select `go` or `all` and also set `--symbolize-go`. The dash0-operator integration must not set that flag, even when debuginfo uploads are disabled.

<details><summary>Flags:</summary>
<p>

[embedmd]:# (dist/help.txt)
```txt
Usage: parca-agent [flags]

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
      --profiling-label-ttl=10m    The interval at which the agent will refresh
                                   the labels of a tid.
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
      --metadata-discovery="full"
                                   Metadata discovery mode: full queries
                                   Kubernetes and container runtimes; local only
                                   reads host/process metadata and container
                                   IDs, leaving Kubernetes enrichment to the
                                   receiver.
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
      --metadata-disable-cpu-label
                                   Disable adding the cpu label to profiling
                                   data.
      --metadata-disable-thread-id-label
                                   Disable adding the thread_id label to
                                   profiling data.
      --metadata-disable-thread-comm-label
                                   Disable adding the thread_comm label to
                                   profiling data.
      --local-store-directory=STRING
                                   The local directory to store the profiling
                                   data.
      --remote-store-address=STRING
                                   gRPC address to send requests to. Sends
                                   profiles and, by default, symbols.
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
                                   Maximum timeout window for unary gRPC
                                   requests including retries.
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
      --remote-store-grpc-headers=KEY=VALUE;...
                                   Additional gRPC headers to send with each
                                   request (key=value pairs).
      --remote-store-client-cert=STRING
                                   Client certificate for mTLS
      --remote-store-client-key=STRING
                                   Client key for mTLS
      --remote-store-use-v2-schema
                                   Use v2 Arrow schema with inline stacktraces
                                   and ListView deduplication (experimental).
      --debuginfo-address=STRING
                                   gRPC address to send requests to. Uploads
                                   symbols via the Parca DebuginfoService
                                   protocol. When unset, reuses the remote-store
                                   connection and ignores debuginfo connection
                                   settings.
      --debuginfo-bearer-token=STRING
                                   Bearer token to authenticate with store
                                   ($PARCA_DEBUGINFO_BEARER_TOKEN).
      --debuginfo-bearer-token-file=STRING
                                   File to read bearer token from to
                                   authenticate with store.
      --debuginfo-insecure         Send gRPC requests via plaintext instead of
                                   TLS.
      --debuginfo-insecure-skip-verify
                                   Skip TLS certificate verification.
      --debuginfo-rpc-unary-timeout=5m
                                   Maximum timeout window for unary gRPC
                                   requests including retries.
      --debuginfo-grpc-max-call-recv-msg-size=33554432
                                   The maximum message size the client can
                                   receive.
      --debuginfo-grpc-max-call-send-msg-size=33554432
                                   The maximum message size the client can send.
      --debuginfo-grpc-startup-backoff-time=1m
                                   The time between failed gRPC requests during
                                   startup phase.
      --debuginfo-grpc-connection-timeout=3s
                                   The timeout duration for gRPC connection
                                   establishment.
      --debuginfo-grpc-max-connection-retries=5
                                   The maximum number of retries to establish a
                                   gRPC connection.
      --debuginfo-grpc-headers=KEY=VALUE;...
                                   Additional gRPC headers to send with each
                                   request (key=value pairs).
      --debuginfo-client-cert=STRING
                                   Client certificate for mTLS
      --debuginfo-client-key=STRING
                                   Client key for mTLS
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
      --instrument-cuda-launch     instrument calls to cudaLaunchKernel.
      --analytics-opt-out          Opt out of sending anonymous usage
                                   statistics.
      --telemetry-disable-panic-reporting

      --telemetry-stderr-buffer-size-kb=4096

      --bpf-verbose-logging        Enable verbose BPF logging from eBPF code to
                                   ebpf trace_pipe.
      --bpf-log-trace-pipe         Copy bpf trace_pipe to info logging.
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
                                   [deprecated] Enables offline mode, with the
                                   data stored at the given path. Offline mode
                                   will be removed in a future release; buffer
                                   data in an OpenTelemetry Collector instead.
      --offline-mode-rotation-interval=10m
                                   [deprecated] How often to rotate and compress
                                   the offline mode log.
      --offline-mode-upload        [deprecated] Run the uploader for data
                                   written in offline mode.
      --off-cpu-threshold=0        The probability (0.0-1.0) of off-CPU event
                                   being recorded.
      --enable-oom-prof            Enable OOMProf profiling integration.
      --enable-oom-prof-allocs     Enable OOMProf alloc counts.
```

</p>
</details>

## Metadata Labels

Parca Agent supports [Prometheus relabeling](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config). The following labels are always attached to profiles:

* `node`: The name of the node that the process is running on as specified by the `--node` flag.
* `comm`: The command name of the process being profiled.
* `cpu`: The CPU the sample was taken on. Can be disabled with `--metadata-disable-cpu-label`.
* `thread_id`: The thread ID of the thread being profiled. Can be disabled with `--metadata-disable-thread-id-label`.
* `thread_name`: The command name of the thread being profiled. Can be disabled with `--metadata-disable-thread-comm-label`.

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
* `__meta_docker_container_label_*`: The value of the label `*` of the container the process is running in.
* `__meta_docker_container_labelpresent_*`: Whether the label `*` of the container the process is running in is present.
* `__meta_docker_build_kit_container_id`: The ID of the container the process is running in.
* `__meta_containerd_container_id`: The ID of the container the process is running in.
* `__meta_containerd_container_name`: The name of the container the process is running in.
* `__meta_containerd_container_label_*`: The value of the label `*` of the container the process is running in.
* `__meta_containerd_container_labelpresent_*`: Whether the label `*` of the container the process is running in is present.
* `__meta_containerd_pod_name`: The name of the pod the process is running in.
* `__meta_lxc_container_id`: The ID of the container the process is running in.

### Example configurations

Two optional relabel configurations ship with the agent. Choose the one for
your export format rather than combining both vocabularies:

* [`parca-k8s-config.yaml`](parca-k8s-config.yaml) promotes Kubernetes
  metadata under parca-agent's own label names (`namespace`, `pod`,
  `container`), which is what the Parca UI and stored queries are written
  against. It mirrors the default a jsonnet deployment renders into its
  ConfigMap.
* [`config/examples/otlp-semconv-k8s.yaml`](config/examples/otlp-semconv-k8s.yaml)
  customizes OTLP resource attributes, for use with
  `--remote-store-format=otlp`. It is not required for semconv naming.

The `__meta_*` discovery labels above are available to relabel rules and are
deleted afterwards. Arrow requires rules to keep discovery metadata in its
exported labels. OTLP providers produce standard resource attributes directly;
rules can change these defaults or add attributes from discovery labels. The
OTLP example also derives `service.name` from pod labels rather than using the
comm/executable fallback. Review its command-line rule before enabling it,
because command lines can contain credentials.

Both files are examples rather than default configurations.

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
