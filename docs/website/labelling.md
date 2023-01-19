# Labelling

## Metadata labels

The agent does its best to enrich profiles with labels coming from various system facilities relative to the originating process.

### Profiler

* `__name__`: The name of the profiler (e.g. `parca_agent_cpu`).
* `pid`: The PID of the process.

### Service Discovery

#### Kubernetes

* `namespace`: The namespace of the pod object.
* `pod`: The name of the pod object.
* `container`: The name of the container.
* `containerid`: The ID of the container.

#### systemd

* `systemd_unit`: The systemd unit name as in `systemctl list-units --type=service --state=running`.

### Target

* `node`: The name of the node set by the `--node` flag on the agent.
* Any labels configured by the `--metadata-external-labels` flag on the agent.

### cgroup

* `cgroup_name`: The cgroup path as in `hierarchy-ID:controller-list:cgroup-path` from `/proc/[pid]/cgroup` (see [`cgroups(7)` man page](https://man7.org/linux/man-pages/man7/cgroups.7.html)).

### Compiler

* `compiler`: Detected compiler and its version (see [github.com/xyproto/ainur](https://pkg.go.dev/github.com/xyproto/ainur#readme-features-and-limitations) for supported compilers).
* `stripped`: `true` if the binary has been stripped of its debug and symbol info, otherwise `false`.
* `static`: `true` if the binary is compiled statically, otherwise `false`.

### Process

* `comm`: The comm of the process as in `/proc/[pid]/comm` (see [`proc(5)` man page](https://man7.org/linux/man-pages/man5/proc.5.html)).
* `executable`: The executable name of the process as in `readlink /proc/[pid]/exe` (see [`proc(5)` man page](https://man7.org/linux/man-pages/man5/proc.5.html)).

### System

* `kernel_release`: The Linux kernel release used by the node as in `uname --kernel-release`.
* `agent_revision`: The Git commit SHA Parca Agent was built from.

## Configuration

Parca Agent supports relabeling in the same fashion as Prometheus.
This can be used to add, update, or delete labels, as well as filtering the profiles sent to Parca (keep or drop).

To do so, pass a YAML configuration file to the agent with `--config-path` (default: `parca-agent.yaml`) with a list of `relabel_configs`.
Example:

```yaml
relabel_configs:
# Example: Add a profiler_pid label (e.g. provider_pid="cpu/1234")
- source_labels: [__name__, pid]
  separator: /
  target_label: profiler_pid
  regex: parca_agent_(.+)
  replacement: $1
  action: replace
```

Please see the [Prometheus `relabel_config` documentation](https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config) for more details about the fields.
