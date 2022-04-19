// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see
 * https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8
 * for more details
 */
#include "vmlinux.h"
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#define KBUILD_MODNAME "parca-agent"

#undef container_of
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#if defined(bpf_target_x86)
#define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif

// Max amount of different stack trace addresses to buffer in the Map
#define MAX_STACK_ADDRESSES 1024
// Max depth of each stack trace to track
#define MAX_STACK_DEPTH 127

/*================================ eBPF MAPS =================================*/

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)            \
  struct {                                                                     \
    __uint(type, _type);                                                       \
    __uint(max_entries, _max_entries);                                         \
    __type(key, _key_type);                                                    \
    __type(value, _value_type);                                                \
  } _name SEC(".maps");

// Stack Traces are slightly different
// in that the value is 1 big byte array
// of the stack addresses
typedef __u64 stack_trace_type[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries)                                   \
  BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_type, _max_entries);

#define BPF_HASH(_name, _key_type, _value_type)                                \
  BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240);

/*============================= INTERNAL STRUCTS ============================*/

typedef struct stack_count_key {
  u32 pid;
  int user_stack_id;
  int kernel_stack_id;
} stack_count_key_t;

/*================================ MAPS =====================================*/

BPF_HASH(counts, stack_count_key_t, u64);
BPF_STACK_TRACE(stack_traces, MAX_STACK_ADDRESSES);

/*=========================== HELPER FUNCTIONS ==============================*/

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
  void *val;
  long err;

  val = bpf_map_lookup_elem(map, key);
  if (val)
    return val;

  err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
  // 17 == EEXIST
  if (err && err != -17)
    return 0;

  return bpf_map_lookup_elem(map, key);
}

/*================================= HOOKS ==================================*/

// This code gets a bit complex. Probably not suitable for casual hacking.
SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u32 pid = id;

  if (pid == 0)
    return 0;

  // create map key
  stack_count_key_t key = {.pid = tgid};

  // get user stack id
  key.user_stack_id = 0;
  int stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
  if (stack_id >= 0)
    key.user_stack_id = stack_id;

  // get kernel stack id
  key.kernel_stack_id = 0;
  int kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
  if (kernel_stack_id >= 0)
    key.kernel_stack_id = kernel_stack_id;

  // TODO(kakkoyun): failed bpf_get_stackid() could indicate stack unwinding
  // issues; this could be a useful place to hook eh_frame-based stack
  // unwinding.
  // TODO(kakkoyun): Does returned error code help?
  // if (key.user_stack_id == 0 && key.kernel_stack_id == 0)
  // Both user and kernel stacks are empty.
  // However, for now, we still want to count the event, to keep track of the
  // number of the failed stack unwinding attempts.
  // return 0;

  u64 zero = 0;
  u64 *count;
  count = bpf_map_lookup_or_try_init(&counts, &key, &zero);
  if (!count)
    return 0;

  __sync_fetch_and_add(count, 1);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
