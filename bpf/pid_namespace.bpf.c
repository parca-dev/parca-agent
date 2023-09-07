//+build ignore

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

 struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 4096);
} events SEC(".maps");

SEC("uprobe/test_function")
int uprobe__test_function(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pid, sizeof(pid));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
