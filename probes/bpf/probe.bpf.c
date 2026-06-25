// SPDX-License-Identifier: Apache-2.0
//
// Paired entry/exit uprobes for parca-agent's simple-probes-v1 feature.
//
// Two SEC programs (probe_entry, probe_exit) share a per-tid LRU hash map
// tracking the lifetime of the OUTERMOST scope only. probe_entry captures
// a timestamp when the outer scope opens (top transitions 0->1) and just
// increments a counter for nested entries. probe_exit decrements; emits a
// ringbuf event only when the outer scope closes (top transitions back to
// 0). Inner scopes roll into the outer's measured duration -- they do not
// get their own records.
//
// Cookie layout (set by user-space, same on both attach points):
//   bits 63..32 : spec_id  (uint32, 1-based)
//   bits 31..1  : min_duration_ms (31 bits)
//   bit  0      : main_thread_only flag
//
// Requires kernel >= 5.15 for bpf_get_attach_cookie.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Apache-2.0";

// bpf_get_attach_cookie is kernel helper #174 (added in 5.15). Older
// libbpf-dev packages don't declare it, AND older linux-libc-dev packages
// don't even define BPF_FUNC_get_attach_cookie in <linux/bpf.h>; the Debian
// base in goreleaser-cross has both. The helper ID itself is stable kernel
// ABI, so we hardcode 174 here rather than depending on either header. A
// private name avoids any conflict with libbpf's own declaration on newer
// systems. See the file header comment for the kernel-version requirement.
static __u64 (*probe_attach_cookie)(void *ctx) = (void *)174;

struct scope_state {
	__u64 entry_ns;  // ktime when the outermost scope opened (top went 0->1)
	__u32 top;       // current nesting depth; 0 = outside any scope
	__u32 _pad;
};

struct probe_event {
	__u64 ktime_ns;     // exit ktime (CLOCK_MONOTONIC) of the outer scope
	__u64 duration_ns;  // exit_ktime - entry_ktime of the outer scope
	__u32 pid;          // tgid
	__u32 tid;
	char  comm[16];
	__u32 spec_id;
};

// Force probe_event into BTF so bpf2go can mirror it as a Go struct. Without
// this, the type is only referenced from a local in probe_exit and clang's
// BTF emitter elides it, breaking `bpf2go -type probe_event`.
const struct probe_event *_probe_event_btf_force __attribute__((unused));

// scope_stacks: per-tid open-scope state. LRU evicts dead threads without
// requiring a sched_process_exit hook.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);                  // tid
	__type(value, struct scope_state);
	__uint(max_entries, 4096);
} scope_stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} probe_events SEC(".maps");

static __always_inline __u32 cookie_spec_id(__u64 c)
{
	return (__u32)(c >> 32);
}

static __always_inline __u32 cookie_main_only(__u64 c)
{
	return (__u32)(c & 1ULL);
}

static __always_inline __u32 cookie_min_dur_ms(__u64 c)
{
	return (__u32)((c >> 1) & 0x7fffffffULL);
}

SEC("uprobe/probe_entry")
int probe_entry(struct pt_regs *ctx)
{
	__u64 cookie = probe_attach_cookie(ctx);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid  = (__u32)pid_tgid;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	if (cookie_main_only(cookie) && tid != tgid)
		return 0;

	struct scope_state *s = bpf_map_lookup_elem(&scope_stacks, &tid);
	if (!s) {
		struct scope_state init = {};
		bpf_map_update_elem(&scope_stacks, &tid, &init, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&scope_stacks, &tid);
		if (!s)
			return 0;
	}

	// Only capture entry_ns when opening the outermost scope. Nested
	// scopes just increment top; their time rolls into the outer scope's
	// total duration.
	if (s->top == 0)
		s->entry_ns = bpf_ktime_get_ns();
	s->top++;
	return 0;
}

SEC("uprobe/probe_exit")
int probe_exit(struct pt_regs *ctx)
{
	__u64 cookie = probe_attach_cookie(ctx);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tid  = (__u32)pid_tgid;
	__u32 tgid = (__u32)(pid_tgid >> 32);

	if (cookie_main_only(cookie) && tid != tgid)
		return 0;

	struct scope_state *s = bpf_map_lookup_elem(&scope_stacks, &tid);
	if (!s || s->top == 0)
		return 0; // unmatched exit (started mid-callback) — silently drop

	s->top--;
	if (s->top != 0)
		return 0; // closing an inner scope — roll up into outer

	__u64 now = bpf_ktime_get_ns();
	__u64 duration_ns = now - s->entry_ns;

	__u32 min_dur_ms = cookie_min_dur_ms(cookie);
	if (min_dur_ms > 0 && duration_ns < (__u64)min_dur_ms * 1000000ULL)
		return 0;

	struct probe_event *e =
		bpf_ringbuf_reserve(&probe_events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ktime_ns    = now;
	e->duration_ns = duration_ns;
	e->pid         = tgid;
	e->tid         = tid;
	e->spec_id     = cookie_spec_id(cookie);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
