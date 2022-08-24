// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler

// TODO(kakkoyun): Remove unused macros and functions.

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see
 * https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8
 * for more details
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#define KBUILD_MODNAME "parca-agent"

#undef container_of

// TODO(kakkoyun): Split into multiple files.
#include "../common.h"
// #include "../helpers.h"
// #include "unwind.h"

#include <bpf_core_read.h> // TODO(kakkoyun): Validate if this is needed.
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h> // TODO(kakkoyun): Validate if this is needed.

// NOTICE: Please check out
// https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md for the
// features supported by Agent's minimum required kernel version.

// TODO(kakkoyun): Remove bpf_printk calls! /sys/kernel/tracing/trace_pipe
// TODO(kakkoyun): Use bpftool to debug!

volatile const char bpf_metadata_name[] SEC(".rodata") =
    "parca-agent (https://github.com/parca-dev/parca-agent)";

unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";

// TODO(kakkoyun): Is there a use case for this?
#if defined(bpf_target_x86)
#define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif

/*================================ CONSTANTS =================================*/

// Max amount of different stack trace addresses to buffer in the Map
#define MAX_STACK_ADDRESSES 1024
// Max depth of each stack trace to track
#define MAX_STACK_DEPTH 127
// TODO(kakkoyun): Explain.
#define MAX_PID_MAP_SIZE 256
// TODO(kakkoyun): Explain.
#define MAX_ENTRIES 10240
// TODO(kakkoyun): Explain. This is safe to remove after using heap!
#define MAX_BINARY_SEARCH_DEPTH 24
// TODO(kakkoyun): Explain.
#define MAX_UNWIND_TABLE_SIZE 1024 // 0xffffff

/*=========================== MACROS ==================================*/

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)            \
  struct {                                                                     \
    __uint(type, _type);                                                       \
    __uint(max_entries, _max_entries);                                         \
    __type(key, _key_type);                                                    \
    __type(value, _value_type);                                                \
  } _name SEC(".maps");
// TODO(kakkoyun): __uint(map_flags, BPF_F_NO_PREALLOC);

// Stack Traces are slightly different
// in that the value is 1 big byte array
// of the stack addresses
typedef __u64 stack_trace_type[MAX_STACK_DEPTH];

#define BPF_STACK_TRACE(_name, _max_entries)                                   \
  BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_type, _max_entries);

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                  \
  BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries);

#define BPF_ARRAY(_name, _value_type, _max_entries)                            \
  BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries);

// Supported for Linux Kernel version >= 4.12

// The value type must be u32, because it is inner map id.
#define BPF_HASH_OF_MAPS(_name, _key_type, _max_entries)                       \
  BPF_MAP(_name, BPF_MAP_TYPE_HASH_OF_MAPS, _key_type, u32, _max_entries);

// The value type must be u32, because it is inner map id.
#define BPF_ARRAY_OF_MAPS(_name, _key_type, _max_entries)                      \
  BPF_MAP(_name, BPF_MAP_TYPE_ARRAY_OF_MAPS, _key_type, u32, _max_entries);

/*=========================== FUNCTIONS ==============================*/

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

/*============================= INTERNAL STRUCTS ============================*/

typedef struct stack_count_key {
  u32 pid;
  int user_stack_id;
  int kernel_stack_id;
} stack_count_key_t;

typedef struct stack_unwind_instruction {
  u8 op;
  u64 reg;
  s64 offset;
} stack_unwind_instruction_t;

typedef __u64 program_counter_type[MAX_UNWIND_TABLE_SIZE];
typedef stack_unwind_instruction_t instructions_type[MAX_UNWIND_TABLE_SIZE];

typedef struct stack_unwind_table {
  program_counter_type PC;
  instructions_type RIP; // instruction_type
  instructions_type RSP; // instruction_type
} stack_unwind_table_t;

/*================================ eBPF MAPS =================================*/

// TODO(kakkoyun): Use service discovery mechanism to filter out process to
// profile. BPF_ARRAY(chosen, pid_t, MAX_PID_MAP_SIZE); // or MAX_ENTRIES
BPF_HASH(stack_counts, stack_count_key_t, u64, MAX_ENTRIES);
BPF_STACK_TRACE(stack_traces, MAX_STACK_ADDRESSES);
BPF_HASH(unwind_tables, pid_t, stack_unwind_table_t, MAX_PID_MAP_SIZE);
// alternative approach:
// BPF_HASH(pcs, pid_t, program_counter_type, MAX_ENTRIES);
// BPF_HASH(rips, pid_t, instruction_type, MAX_ENTRIES);
// BPF_HASH(rsps, pid_t, instruction_type, MAX_ENTRIES);

// TODO(kakkoyun): Also check BPF_MAP_TYPE_QUEUE and BPF_MAP_TYPE_STACK
// (Supported >= 4.20).

/*================================= LOGGING ==================================*/
// TODO(kakkoyun): Consider moving to the helpers.h
typedef struct log_event {
  u32 pid;
  char message[32];
  // u64 addr;
} log_event_t;

// NOTICE: perf_event (supported >= 4.20) buffer has known issues:
// - Memory overhead (per CPU) and event ordering issues
// - There's a better alternative rungbuf
// - However ringbuf is only supported for the Kernel >= 5.8.
// - https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} events SEC(".maps");

#define LOG(ctx, _pid, _msg)                                                   \
  {                                                                            \
    log_event_t e = {.pid = _pid, .message = _msg};                            \
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));     \
  }

/*============================= STACK UNWINDING ==============================*/

static __always_inline u32 *find(program_counter_type *pcs, u64 target) {
  u32 right = MAX_UNWIND_TABLE_SIZE - 1;

  u32 left = 0;
  static u32 mid;
  int i = 0;
  // #pragma clang loop unroll(full)
  while (i < MAX_BINARY_SEARCH_DEPTH && left <= right) {
    i++;

    mid = left + (right - left) / 2;

    u64 val = *pcs[mid];
    u64 guess;
    if (val > 0)
      guess = val;
    else
      guess = ULONG_MAX;

    if (guess == target)
      return &mid;
    else if (guess < target)
      left = mid + 1;
    else
      right = mid - 1;
  }
  return NULL;
}

// Where we actually read CFA and RA values.
static __always_inline u64 execute(stack_unwind_instruction_t *ins, u64 rip,
                                   u64 rsp, u64 cfa) {
  u64 addr;
  u64 unsafe_ptr = cfa + ins->offset;
  u64 res = 0;
  switch (ins->op) {
  case 1: // OpUndefined: Undefined register.
    if (bpf_probe_read(&addr, 8, &unsafe_ptr) == 0)
      res = addr;
  case 2:                    // OpCfaOffset
    res = rip + ins->offset; // Value stored at some offset from `CFA`.
  case 3:                    // OpRegister
    res = rsp + ins->offset; // Value of a machine register plus offset.
  default:
    res = 0;
  }
  return res;
}

static __always_inline bool is_zero_ins(stack_unwind_instruction_t *ins) {
  return ins->op == 0 && ins->reg == 0 && ins->offset == 0;
}

// BPF VM has a 512 byte stack size limit. This is a workaround to get around
// that limit.
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, stack_trace_type);
} heap SEC(".maps");

// TODO(kakkoyun): Remove bpf_printk!
static __always_inline int backtrace(bpf_user_pt_regs_t *regs,
                                     stack_unwind_table_t *plan_table) {
  bpf_printk("backtrace");
  long unsigned int rip = regs->ip; // current instruction pointer.
  long unsigned int rsp = regs->sp; // current stack pointer.

  int zero = 0;
  stack_trace_type *stack;
  stack = bpf_map_lookup_elem(&heap, &zero);
  if (!stack)
    return 0;

  // #pragma clang loop unroll(full)
  for (int d = 0; d < MAX_STACK_DEPTH; d++) {
    bpf_printk("backtrace, depth: %d, %u", d, rip);
    if (rip == 0)
      break;

    bpf_printk("backtrace, step 1, depth: %d, %u", d, rip);

    // Push the found return address.
    *stack[d] = (__u64)rip;

    bpf_printk("backtrace, step 2, depth: %d, %u", d, rip);
    u32 *val = find(&plan_table->PC, rip);
    if (val == NULL) {
      bpf_printk("backtrace, NOT FOUND, depth: %d, %u", d, rip);
      break;
    }

    bpf_printk("backtrace, step 3 (FOUND), depth: %d, %u", d, rip);
    u32 key = *val;
    stack_unwind_instruction_t ins = plan_table->RSP[key];
    if (is_zero_ins(&ins)) // TODO(kakkoyun): Check against zero value. Or use a nullable type?
      break;

    bpf_printk("backtrace, step 4, depth: %d, %u", d, rip);
    u64 cfa;
    cfa = execute(&ins, rip, rsp, 0);
    if (cfa == 0)
      break;

    bpf_printk("backtrace, step 5, depth: %d, %u", d, rip);
    ins = plan_table->RIP[key];
    if (is_zero_ins(&ins)) // TODO(kakkoyun): Check against zero value. Or use a nullable type?
      break;

    bpf_printk("backtrace, step 6, depth: %d, %u", d, rip);
    rip = execute(&ins, rip, rsp, cfa);
    rsp = cfa;
  }

  bpf_printk("backtrace, done, %u\n", rip);
  // TODO(kakkoyun): which appears to correspond to a 32-bit hash of the
  // instruction pointer addresses that comprise the stack for the current
  // context
  // https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/kernel/bpf/stackmap.c?_pjax=%23js-repo-pjax-container%2C%20div%5Bitemtype%3D%22http%3A%2F%2Fschema.org%2FSoftwareSourceCode%22%5D%20main%2C%20%5Bdata-pjax-container%5D#L252

  int stack_id = bpf_get_prandom_u32(); // calculate a stack_id or obtain the id
                                        // from kernel somehow.
  if (bpf_map_update_elem(&stack_traces, &stack_id, &stack, BPF_ANY) < 0) {
    bpf_printk("backtrace, failed to update stack trace\n");
    return 0;
  }

  // TODO(kakkoyun): Shall we clean the heap?
  return stack_id;
}

/*=============================== EVENT HOOKS ================================*/

// This code gets a bit complex. Probably not suitable for casual hacking.
SEC("perf_event")
int do_sample(struct bpf_perf_event_data *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u32 pid = id;

  if (pid == 0)
    return 0;

  // create map key
  stack_count_key_t key = {
      .pid = tgid,
      .user_stack_id = 0,
      .kernel_stack_id = 0,
  };

  int stack_id;

  stack_unwind_table_t *plan_table;
  plan_table = bpf_map_lookup_elem(&unwind_tables, &pid);
  if (plan_table != NULL) {
    LOG(ctx, pid, "attempt to backtrace");
    bpf_printk("do sample: %d\n", pid);
    stack_id = backtrace(&ctx->regs, plan_table);
  } else {
    // Fallback to the kernel helper function for uwinding the stack.
    stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
  }

  // get user stack id
  if (stack_id >= 0)
    key.user_stack_id = stack_id;

  // get kernel stack id
  int kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
  if (kernel_stack_id >= 0)
    key.kernel_stack_id = kernel_stack_id;

  u32 zero = 0;
  u64 *count;
  count = bpf_map_lookup_or_try_init(&stack_counts, &key, &zero);
  if (!count)
    return 0;

  __sync_fetch_and_add(count, 1);
  return 0;
}
