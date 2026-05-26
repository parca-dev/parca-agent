// SPDX-License-Identifier: Apache-2.0
//
// Generic uprobe program for parca-agent's simple-probes-v1 feature.
// One program; the spec_id of the firing probe is carried in the high
// 32 bits of the attach cookie (set userspace-side via UprobeOptions.Cookie).
// Requires kernel >= 5.15 for bpf_get_attach_cookie.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Apache-2.0";

struct probe_event {
	__u64 ktime_ns;
	__u32 pid;
	__u32 tid;
	char  comm[16];
	__u32 spec_id;
	__u32 _pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} probe_events SEC(".maps");

SEC("uprobe/probe_event")
int probe_event(struct pt_regs *ctx)
{
	struct probe_event *e =
		bpf_ringbuf_reserve(&probe_events, sizeof(*e), 0);
	if (!e)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->ktime_ns = bpf_ktime_get_ns();
	e->pid      = pid_tgid >> 32;
	e->tid      = (__u32)pid_tgid;
	e->spec_id  = (__u32)(bpf_get_attach_cookie(ctx) >> 32);
	e->_pad     = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
