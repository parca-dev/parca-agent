// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler
//
// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors

#include <common.h>
#include <hash.h>
#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*================================ CONSTANTS =================================*/

// Number of frames to walk per tail call iteration.
#define MAX_STACK_DEPTH_PER_PROGRAM 11
// Number of BPF tail calls that will be attempted.
#define MAX_TAIL_CALLS 12
// Maximum number of frames.
#define MAX_STACK_DEPTH 127
_Static_assert(MAX_TAIL_CALLS *MAX_STACK_DEPTH_PER_PROGRAM >= MAX_STACK_DEPTH, "enough iterations to traverse the whole stack");
// Number of unique stacks.
#define MAX_STACK_TRACES_ENTRIES 64000
// Number of items in the stack counts aggregation map.
#define MAX_STACK_COUNTS_ENTRIES 10240
// Maximum number of processes we are willing to track.
#define MAX_PROCESSES 5000
// Binary search iterations for dwarf based stack walking.
// 2^19 can bisect ~524_288 entries.
#define MAX_BINARY_SEARCH_DEPTH 19
// Size of the unwind table.
// 250k * sizeof(stack_unwind_row_t) = 2MB
#define MAX_UNWIND_TABLE_SIZE 250 * 1000
_Static_assert(1 << MAX_BINARY_SEARCH_DEPTH >= MAX_UNWIND_TABLE_SIZE, "unwind table is big enough");

// Unwind tables bigger than can't fit in the remaining space
// of the current shard are broken up into chunks up to `MAX_UNWIND_TABLE_SIZE`.
#define MAX_UNWIND_TABLE_CHUNKS 30
// Maximum memory mappings per process.
#define MAX_MAPPINGS_PER_PROCESS 250

// Values for dwarf expressions.
#define DWARF_EXPRESSION_UNKNOWN 0
#define DWARF_EXPRESSION_PLT1 1
#define DWARF_EXPRESSION_PLT2 2

// Values for the unwind table's CFA type.
#define CFA_TYPE_RBP 1
#define CFA_TYPE_RSP 2
#define CFA_TYPE_EXPRESSION 3
// Special values.
#define CFA_TYPE_END_OF_FDE_MARKER 4

// Values for the unwind table's frame pointer type.
#define RBP_TYPE_UNCHANGED 0
#define RBP_TYPE_OFFSET 1
#define RBP_TYPE_REGISTER 2
#define RBP_TYPE_EXPRESSION 3
// Special values.
#define RBP_TYPE_UNDEFINED_RETURN_ADDRESS 4

// Binary search error codes.
#define BINARY_SEARCH_DEFAULT 0xFAFAFAFA
#define BINARY_SEARCH_NOT_FOUND 0xFABADA
#define BINARY_SEARCH_SHOULD_NEVER_HAPPEN 0xDEADBEEF
#define BINARY_SEARCH_EXHAUSTED_ITERATIONS 0xBADFAD

#define REQUEST_UNWIND_INFORMATION (1ULL << 63)
#define REQUEST_PROCESS_MAPPINGS (1ULL << 62)
#define REQUEST_REFRESH_PROCINFO (1ULL << 61)

#define ENABLE_STATS_PRINTING false

// Stack walking methods.
enum stack_walking_method {
  STACK_WALKING_METHOD_FP = 0,
  STACK_WALKING_METHOD_DWARF = 1,
};

struct unwinder_config_t {
  bool filter_processes;
  bool verbose_logging;
  bool mixed_stack_enabled;
};

struct unwinder_stats_t {
  u64 total;
  u64 success_dwarf;
  u64 error_truncated;
  u64 error_unsupported_expression;
  u64 error_unsupported_frame_pointer_action;
  u64 error_unsupported_cfa_register;
  u64 error_catchall;
  u64 error_should_never_happen;
  u64 error_pc_not_covered;
  u64 error_pc_not_covered_jit;
  u64 error_jit_unupdated_mapping;
  u64 error_jit_mixed_mode_disabled; // JIT error because mixed-mode unwinding is disabled
  u64 success_jit_frame;
  u64 success_jit_to_dwarf;
  u64 success_dwarf_to_jit;
  u64 success_dwarf_reach_bottom;
  u64 success_jit_reach_bottom;
};

const volatile struct unwinder_config_t unwinder_config = {};

/*============================== MACROS =====================================*/

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)                                                                                            \
  struct {                                                                                                                                                     \
    __uint(type, _type);                                                                                                                                       \
    __uint(max_entries, _max_entries);                                                                                                                         \
    __type(key, _key_type);                                                                                                                                    \
    __type(value, _value_type);                                                                                                                                \
  } _name SEC(".maps");

// Stack Traces are slightly different
// in that the value is 1 big byte array
// of the stack addresses
typedef u64 stack_trace_type[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries) BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_type, _max_entries);

#define BPF_HASH(_name, _key_type, _value_type, _max_entries) BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries);

// A different stack produced the same hash.
#define STACK_COLLISION(err) (err == -EEXIST)
// Tried to read a kernel stack from a non-kernel context.
#define IN_USERSPACE(err) (err == -EFAULT)

#define LOG(fmt, ...)                                                                                                                                          \
  ({                                                                                                                                                           \
    if (unwinder_config.verbose_logging) {                                                                                                                     \
      bpf_printk(fmt, ##__VA_ARGS__);                                                                                                                          \
    }                                                                                                                                                          \
  })

/*============================= INTERNAL STRUCTS ============================*/

// Unwind tables are splitted in chunks and each chunk
// maps to a range of unwind rows within a shard.
typedef struct {
  u64 low_pc;
  u64 high_pc;
  u64 shard_index;
  u64 low_index;
  u64 high_index;
} chunk_info_t;

// Unwind table shards for an executable mapping.
typedef struct {
  chunk_info_t chunks[MAX_UNWIND_TABLE_CHUNKS];
} unwind_info_chunks_t;

// The addresses of a native stack trace.
typedef struct {
  u64 len;
  u64 addresses[MAX_STACK_DEPTH];
} stack_trace_t;

typedef struct {
  int pid;
  int tid;
  int user_stack_id;
  int kernel_stack_id;
  int user_stack_id_dwarf;
} stack_count_key_t;

// Represents an executable mapping.
typedef struct {
  u64 load_address;
  u64 begin;
  u64 end;
  u64 executable_id;
  u64 type;
} mapping_t;

// Executable mappings for a process.
typedef struct {
  u64 is_jit_compiler;
  u64 len;
  mapping_t mappings[MAX_MAPPINGS_PER_PROCESS];
} process_info_t;

// State of unwinder such as the registers as well
// as internal data.
typedef struct {
  u64 ip;
  u64 sp;
  u64 bp;
  u32 tail_calls;
  stack_trace_t stack;
  bool unwinding_jit; // set to true during JITed unwinding; false unless mixed-mode unwinding is enabled
} unwind_state_t;

// A row in the stack unwinding table for x86_64.
typedef struct __attribute__((packed)) {
  u64 pc;
  u8 cfa_type;
  u8 rbp_type;
  s16 cfa_offset;
  s16 rbp_offset;
} stack_unwind_row_t;
_Static_assert(sizeof(stack_unwind_row_t) == 14, "unwind row has the expected size");

// Unwinding table representation.
typedef struct {
  stack_unwind_row_t rows[MAX_UNWIND_TABLE_SIZE];
} stack_unwind_table_t;

/*================================ MAPS =====================================*/

BPF_HASH(debug_pids, int, u8, 1); // Table size will be updated in userspace.
BPF_HASH(process_info, int, process_info_t, MAX_PROCESSES);

BPF_STACK_TRACE(stack_traces, MAX_STACK_TRACES_ENTRIES);
BPF_HASH(dwarf_stack_traces, int, stack_trace_t, MAX_STACK_TRACES_ENTRIES);
BPF_HASH(stack_counts, stack_count_key_t, u64, MAX_STACK_COUNTS_ENTRIES);

BPF_HASH(unwind_info_chunks, u64, unwind_info_chunks_t,
         5 * 1000); // Mapping of executable ID to unwind info chunks.
BPF_HASH(unwind_tables, u64, stack_unwind_table_t,
         5); // Table size will be updated in userspace.

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, unwind_state_t);
} heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct unwinder_stats_t);
} percpu_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u32);
} programs SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 8192);
} events SEC(".maps");

/*=========================== HELPER FUNCTIONS ==============================*/

#define DEFINE_COUNTER(__func__name)                                                                                                                           \
  static void bump_unwind_##__func__name() {                                                                                                                   \
    u32 zero = 0;                                                                                                                                              \
    struct unwinder_stats_t *unwinder_stats = bpf_map_lookup_elem(&percpu_stats, &zero);                                                                       \
    if (unwinder_stats != NULL) {                                                                                                                              \
      unwinder_stats->__func__name++;                                                                                                                          \
    }                                                                                                                                                          \
  }

DEFINE_COUNTER(total);
DEFINE_COUNTER(success_dwarf);
DEFINE_COUNTER(error_truncated);
DEFINE_COUNTER(error_unsupported_expression);
DEFINE_COUNTER(error_unsupported_frame_pointer_action);
DEFINE_COUNTER(error_unsupported_cfa_register);
DEFINE_COUNTER(error_catchall);
DEFINE_COUNTER(error_should_never_happen);
DEFINE_COUNTER(error_pc_not_covered);
DEFINE_COUNTER(error_pc_not_covered_jit);
DEFINE_COUNTER(error_jit_unupdated_mapping);
DEFINE_COUNTER(error_jit_mixed_mode_disabled);
DEFINE_COUNTER(success_jit_frame);
DEFINE_COUNTER(success_jit_to_dwarf);
DEFINE_COUNTER(success_dwarf_to_jit);
DEFINE_COUNTER(success_dwarf_reach_bottom);
DEFINE_COUNTER(success_jit_reach_bottom);

static void unwind_print_stats() {
  // Do not use the LOG macro, always print the stats.
  u32 zero = 0;
  struct unwinder_stats_t *unwinder_stats = bpf_map_lookup_elem(&percpu_stats, &zero);
  if (unwinder_stats == NULL) {
    return;
  }

  bpf_printk("[[ stats for cpu %d ]]", (int)bpf_get_smp_processor_id());
  bpf_printk("\tdwarf_success=%lu", unwinder_stats->success_dwarf);
  bpf_printk("\tunsup_expression=%lu", unwinder_stats->error_unsupported_expression);
  bpf_printk("\tunsup_frame=%lu", unwinder_stats->error_unsupported_frame_pointer_action);
  bpf_printk("\ttruncated=%lu", unwinder_stats->error_truncated);
  bpf_printk("\tunsup_cfa_reg=%lu", unwinder_stats->error_unsupported_cfa_register);
  bpf_printk("\tcatchall=%lu", unwinder_stats->error_catchall);
  bpf_printk("\tnever=%lu", unwinder_stats->error_should_never_happen);
  bpf_printk("\tunsup_jit=%lu", unwinder_stats->error_jit_unupdated_mapping);
  bpf_printk("\tunsup_jit_mixed_mode_disabled=%lu", unwinder_stats->error_jit_mixed_mode_disabled);
  bpf_printk("\tjit_frame=%lu", unwinder_stats->success_jit_frame);
  bpf_printk("\tjit_to_dwarf_switch=%lu", unwinder_stats->success_jit_to_dwarf);
  bpf_printk("\tdwarf_to_jit_switch=%lu", unwinder_stats->success_dwarf_to_jit);
  bpf_printk("\treached_bottom_frame_dwarf=%lu", unwinder_stats->success_dwarf_reach_bottom);
  bpf_printk("\treached_bottom_frame_jit=%lu", unwinder_stats->success_jit_reach_bottom);
  bpf_printk("\ttotal_counter=%lu", unwinder_stats->total);
  bpf_printk("\t(not_covered=%lu)", unwinder_stats->error_pc_not_covered);
  bpf_printk("\t(not_covered_jit=%lu)", unwinder_stats->error_pc_not_covered_jit);
  bpf_printk("");
}

static void bump_samples() {
  u32 zero = 0;
  struct unwinder_stats_t *unwinder_stats = bpf_map_lookup_elem(&percpu_stats, &zero);
  if (unwinder_stats == NULL) {
    return;
  }
  if (ENABLE_STATS_PRINTING && unwinder_stats->total % 50 == 0) {
    unwind_print_stats();
  }
  bump_unwind_total();
}

static __always_inline void *bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
  void *val;
  long err;

  val = bpf_map_lookup_elem(map, key);
  if (val) {
    return val;
  }

  err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
  if (err && !STACK_COLLISION(err)) {
    LOG("[error] bpf_map_lookup_or_try_init with ret: %d", err);
    return 0;
  }

  return bpf_map_lookup_elem(map, key);
}

/*================================= EVENTS ==================================*/

static __always_inline void request_unwind_information(struct bpf_perf_event_data *ctx, int user_pid) {
  char comm[20];
  bpf_get_current_comm(comm, 20);
  LOG("[debug] no fp, no unwind info for PID: %d, comm: %s ctx IP: %llx", user_pid, comm, PT_REGS_IP(&ctx->regs));

  u64 payload = REQUEST_UNWIND_INFORMATION | user_pid;
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &payload, sizeof(u64));
}

static __always_inline void request_process_mappings(struct bpf_perf_event_data *ctx, int user_pid) {
  u64 payload = REQUEST_PROCESS_MAPPINGS | user_pid;
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &payload, sizeof(u64));
}

static __always_inline void request_refresh_process_info(struct bpf_perf_event_data *ctx, int user_pid) {
  u64 payload = REQUEST_REFRESH_PROCINFO | user_pid;
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &payload, sizeof(u64));
}

// Binary search the unwind table to find the row index containing the unwind
// information for a given program counter (pc).
static u64 find_offset_for_pc(stack_unwind_table_t *table, u64 pc, u64 left, u64 right) {
  u64 found = BINARY_SEARCH_DEFAULT;

  for (int i = 0; i < MAX_BINARY_SEARCH_DEPTH; i++) {
    // TODO(javierhonduco): ensure that this condition is right as we use
    // unsigned values...
    if (left >= right) {
      LOG("\t.done");
      return found;
    }

    u32 mid = (left + right) / 2;

    // Appease the verifier.
    if (mid < 0 || mid >= MAX_UNWIND_TABLE_SIZE) {
      LOG("\t.should never happen, mid: %lu, max: %lu", mid, MAX_UNWIND_TABLE_SIZE);
      bump_unwind_error_should_never_happen();
      return BINARY_SEARCH_SHOULD_NEVER_HAPPEN;
    }

    // Debug logs.
    // LOG("\t-> fetched PC %llx, target PC %llx (iteration %d/%d, mid: %d, left:%d, right:%d)", table->rows[mid].pc, pc, i, MAX_BINARY_SEARCH_DEPTH,
    // mid, left, right);
    if (table->rows[mid].pc <= pc) {
      found = mid;
      left = mid + 1;
    } else {
      right = mid;
    }

    // Debug logs.
    // LOG("\t<- fetched PC %llx, target PC %llx (iteration %d/%d, mid:
    // --, left:%d, right:%d)", ctx->table->rows[mid].pc, ctx->pc, index,
    // MAX_BINARY_SEARCH_DEPTH, ctx->left, ctx->right);
  }
  return BINARY_SEARCH_EXHAUSTED_ITERATIONS;
}

// Finds whether a process should be unwound using the unwind
// tables.
static __always_inline bool has_unwind_information(pid_t pid) {
  process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &pid);
  if (proc_info) {
    return true;
  }
  return false;
}

static __always_inline bool is_debug_enabled_for_pid(int pid) {
  void *val = bpf_map_lookup_elem(&debug_pids, &pid);
  if (val) {
    return true;
  }
  return false;
}

enum find_unwind_table_return {
  FIND_UNWIND_SUCCESS = 1,

  FIND_UNWIND_MAPPING_SHOULD_NEVER_HAPPEN = 2,
  FIND_UNWIND_MAPPING_EXHAUSTED_SEARCH = 3,
  FIND_UNWIND_MAPPING_NOT_FOUND = 4,
  FIND_UNWIND_CHUNK_NOT_FOUND = 5,

  FIND_UNWIND_JITTED = 100,
  FIND_UNWIND_SPECIAL = 200,
};

// Finds the shard information for a given pid and program counter. Optionally,
// and offset can be passed that will be filled in with the mapping's load
// address.
static __always_inline enum find_unwind_table_return find_unwind_table(chunk_info_t **chunk_info, pid_t pid, u64 pc, u64 *offset) {
  process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &pid);
  // Appease the verifier.
  if (proc_info == NULL) {
    LOG("[error] should never happen");
    return FIND_UNWIND_MAPPING_SHOULD_NEVER_HAPPEN;
  }

  bool found = false;
  u64 executable_id = 0;
  u64 load_address = 0;
  u64 type = 0;

  // Find the mapping.
  for (int i = 0; i < MAX_MAPPINGS_PER_PROCESS; i++) {
    if (i > proc_info->len) {
      LOG("[info] mapping not found, i (%d) > proc_info->len (%d) pc: %llx", i, proc_info->len, pc);
      return FIND_UNWIND_MAPPING_EXHAUSTED_SEARCH;
    }

    // Appease the verifier.
    if (i < 0 || i > MAX_MAPPINGS_PER_PROCESS) {
      LOG("[error] should never happen, verifier");
      return FIND_UNWIND_MAPPING_SHOULD_NEVER_HAPPEN;
    }

    if (proc_info->mappings[i].begin <= pc && pc <= proc_info->mappings[i].end) {
      found = true;
      executable_id = proc_info->mappings[i].executable_id;
      load_address = proc_info->mappings[i].load_address;
      type = proc_info->mappings[i].type;
      break;
    }
  }

  if (found) {
    if (offset != NULL) {
      *offset = load_address;
    }

    // "type" here is set in userspace in our `proc_info` map to indicate JITed and special sections,
    // It is not something we get from procfs.
    if (type == 1) {
      return FIND_UNWIND_JITTED;
    }
    if (type == 2) {
      return FIND_UNWIND_SPECIAL;
    }
  } else {
    LOG("[warn] :((( no mapping for ip=%llx", pc);
    return FIND_UNWIND_MAPPING_NOT_FOUND;
  }

  LOG("~about to check shards found=%d", found);
  LOG("~checking shards now");

  // Find the chunk where this unwind table lives.
  // Each chunk maps to exactly one shard.
  unwind_info_chunks_t *chunks = bpf_map_lookup_elem(&unwind_info_chunks, &executable_id);
  if (chunks == NULL) {
    LOG("[info] chunks is null for executable %llu", executable_id);
    return FIND_UNWIND_CHUNK_NOT_FOUND;
  }

  u64 adjusted_pc = pc - load_address;
  for (int i = 0; i < MAX_UNWIND_TABLE_CHUNKS; i++) {
    // Reached last chunk.
    if (chunks->chunks[i].low_pc == 0) {
      break;
    }
    if (chunks->chunks[i].low_pc <= adjusted_pc && adjusted_pc <= chunks->chunks[i].high_pc) {
      LOG("[info] found chunk");
      *chunk_info = &chunks->chunks[i];
      return FIND_UNWIND_SUCCESS;
    }
  }

  LOG("[error] could not find chunk");
  return FIND_UNWIND_CHUNK_NOT_FOUND;
}

// Kernel addresses have the top bits set.
static __always_inline bool in_kernel(u64 ip) {
  return ip & (1UL << 63);
}

// kthreads mm's is not set.
//
// We don't check for the return value of `retrieve_task_registers`, it's
// caller due the verifier not liking that code.
static __always_inline bool is_kthread() {
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (task == NULL) {
    return false;
  }

  void *mm;
  int err = bpf_probe_read_kernel(&mm, 8, &task->mm);
  if (err) {
    LOG("[warn] bpf_probe_read_kernel failed with %d", err);
    return false;
  }

  return mm == NULL;
}

// avoid R0 invalid mem access 'scalar'
// Port of `task_pt_regs` in BPF.
static __always_inline bool retrieve_task_registers(u64 *ip, u64 *sp, u64 *bp) {
  if (ip == NULL || sp == NULL || bp == NULL) {
    return false;
  }

  int err;
  void *stack;

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  if (task == NULL) {
    return false;
  }

  if (is_kthread()) {
    return false;
  }

  err = bpf_probe_read_kernel(&stack, 8, &task->stack);
  if (err) {
    LOG("[warn] bpf_probe_read_kernel failed with %d", err);
    return false;
  }

  void *ptr = stack + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
  struct pt_regs *regs = ((struct pt_regs *)ptr) - 1;

  *ip = PT_REGS_IP_CORE(regs);
  *sp = PT_REGS_SP_CORE(regs);
  *bp = PT_REGS_FP_CORE(regs);

  return true;
}

// Find out if we can walk the stack using frame pointers.
//
// We use it because the kernel frame pointer unwinder doesn't
// return errors if it can't find the bottom frame.
// In the future, we would use our custom fp unwinder only, but
// right now using both.
static __always_inline bool has_fp(u64 current_fp) {
  u64 next_fp;
  u64 ra;
  int i;

  for (i = 0; i < MAX_STACK_DEPTH; i++) {
    int err = bpf_probe_read_user(&next_fp, 8, (void *)current_fp);
    bpf_probe_read_user(&ra, 8, (void *)current_fp + 8);
    if (err < 0) {
      // LOG("[debug] fp read failed with %d i %d", err, i);
      // We might have reached the bottom frame.
      break;
    }
    current_fp = next_fp;
  }

  // Some cpp binaries, such as testdata/out/basic-cpp
  // seem to have rbp set to 1 in the bottom frame. This
  // does not comply with the x86_64 ABI.
  //
  // Additionally, we consider that stacks with just 2
  // frames aren't valid. This is just a heuristic, as most
  // processes should at least have two frames.
  //
  // For both cases above, we prefer to unwind using the
  // DWARF-derived unwind information.
  if (next_fp == 0) {
    // LOG("[debug] fp success: %d", i > 2);
    return i > 2;
  }

  LOG("[debug] last frame pointer is not zero");
  return false;
}

// Aggregate the given stacktrace.
static __always_inline void add_stack(struct bpf_perf_event_data *ctx, u64 pid_tgid, enum stack_walking_method method, unwind_state_t *unwind_state) {
  u64 zero = 0;
  stack_count_key_t stack_key = {0};

  // The `bpf_get_current_pid_tgid` helpers returns
  // `current_task->tgid << 32 | current_task->pid`, the naming can be
  // confusing because the thread group identifier and process identifier
  // mean different things in kernel and user space.
  //
  // - What we call PIDs in userspace, are TGIDs in kernel space.
  // - What we call **thread IDs** in user space, are PIDs in kernel space.
  // In other words, the process ID in the lower 32 bits (kernel's view of the PID,
  // which in user space is usually presented as the thread ID),
  // and the thread group ID in the upper 32 bits
  // (what user space often thinks of as the PID).

  int user_pid = pid_tgid >> 32;
  int user_tgid = pid_tgid;
  stack_key.pid = user_pid;
  stack_key.tid = user_tgid;

  if (method == STACK_WALKING_METHOD_DWARF) {
    int stack_hash = MurmurHash2((u32 *)unwind_state->stack.addresses, MAX_STACK_DEPTH * sizeof(u64) / sizeof(u32), 0);
    LOG("stack hash %d", stack_hash);
    stack_key.user_stack_id_dwarf = stack_hash;

    // Insert stack.
    int err = bpf_map_update_elem(&dwarf_stack_traces, &stack_hash, &unwind_state->stack, BPF_ANY);
    if (err != 0) {
      LOG("[error] bpf_map_update_elem with ret: %d", err);
    }
  } else if (method == STACK_WALKING_METHOD_FP) {
    int stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    // `bpf_get_stackid` returns an error if two different stacks share
    // their hash, but not if stack unwinding failed due to the stack being
    // truncated due to a limit on the rbp traversals or because frame
    // pointers aren't present.
    if (stack_id < 0) {
      LOG("[warn] bpf_get_stackid user failed with %d", stack_id);
      return;
    }
    stack_key.user_stack_id = stack_id;
  }

  // Get kernel stack.
  int kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
  if (kernel_stack_id < 0 && !IN_USERSPACE(kernel_stack_id)) {
    LOG("[warn] bpf_get_stackid kernel failed with %d", kernel_stack_id);
    return;
  }
  stack_key.kernel_stack_id = kernel_stack_id;

  // Aggregate stacks.
  u64 *scount = bpf_map_lookup_or_try_init(&stack_counts, &stack_key, &zero);
  if (scount) {
    __sync_fetch_and_add(scount, 1);
  }

  request_process_mappings(ctx, user_pid);
}

// The unwinding machinery lives here.
SEC("perf_event")
int walk_user_stacktrace_impl(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int user_pid = pid_tgid;
  int err = 0;

  bool reached_bottom_of_stack = false;
  u64 zero = 0;

  bool dwarf_to_jit = false;

  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state == NULL) {
    LOG("unwind_state is NULL, should not happen");
    return 1;
  }

  for (int i = 0; i < MAX_STACK_DEPTH_PER_PROGRAM; i++) {
    LOG("[debug] Within unwinding machinery loop");
    LOG("## frame: %d", unwind_state->stack.len);

    LOG("\tcurrent pc: %llx", unwind_state->ip);
    LOG("\tcurrent sp: %llx", unwind_state->sp);
    LOG("\tcurrent bp: %llx", unwind_state->bp);

    u64 offset = 0;

    chunk_info_t *chunk_info = NULL;
    enum find_unwind_table_return unwind_table_result = find_unwind_table(&chunk_info, user_pid, unwind_state->ip, &offset);

    if (unwind_table_result == FIND_UNWIND_JITTED) {
      if (!unwinder_config.mixed_stack_enabled) {
        LOG("JIT section, stopping. Please enable mixed-mode unwinding with the --dwarf-unwinding-mixed=true to profile JITed stacks.");
        bump_unwind_error_jit_mixed_mode_disabled();
        return 1;
      }

      LOG("[debug] Unwinding JITed stacks");

      unwind_state->unwinding_jit = true;
      if (dwarf_to_jit) {
        dwarf_to_jit = false;
        bump_unwind_success_dwarf_to_jit();
      }

      u64 next_fp = 0;
      u64 ra = 0;
      u64 len = unwind_state->stack.len;

      // When we enter a JITed stack, the first JITed frame can
      // be obtained from the current value of pc(program counter)

      if (unwind_state->stack.len == 0) {
        if (len >= 0 && len < MAX_STACK_DEPTH) {
          unwind_state->stack.addresses[len] = unwind_state->ip;
          unwind_state->stack.len++;
          continue;
        }
      }

      err = bpf_probe_read_user(&next_fp, 8, (void *)unwind_state->bp);
      if (err < 0) {
        // TODO(sylfrena):
        // For some weird reason commenting out this and the next err log line results in a panic
        // Using more than 3 arguments also results in a panic in some older kernels because of
        // https://github.com/libbpf/libbpf/blob/f7eb43b90f4c8882edf6354f8585094f8f3aade0/src/bpf_helpers.h#L287-L289
        LOG("[error] rbp failed with err = %d", err);
        return 0;
      }

      // LOG("[debug]  i=%d, err = %d && rbp = %llx && ra=%llx", i, err, next_fp, ra);

      // reading return address
      err = bpf_probe_read_user(&ra, 8, (void *)unwind_state->bp + 8);
      if (err < 0) {
        // TODO(sylfrena)
        //  For some weird reason commenting out this and the next err log line results in a panic
        //  Using more than 3 arguments also results in a panic in some older kernels because of
        //  https://github.com/libbpf/libbpf/blob/f7eb43b90f4c8882edf6354f8585094f8f3aade0/src/bpf_helpers.h#L287-L289
        LOG("[error] ra failed with err = %d", err);
        return 0;
      }

      if (next_fp == 0) {
        LOG("[info] found bottom frame while walking JITed section");
        bump_unwind_success_jit_reach_bottom();
        return 1;
      }

      // Stacktraces are essentially a list of saved return addresses from function calls pushed onto a stack
      // The base pointer (`rbp` in x86_64) is a register pushed onto the stack and points to/references the beginning of the stack
      // The stack pointer(`rsp`) points to the frame at the `rbp`, updating the top of the stack to 8 bytes ahead of the `rbp`
      // When the current instruction is pushed, top of the stack moves up by 1 frame, updating `rsp` by another 8 bytes
      // Hence, we update current stack pointer by 16 bytes ahead of `rbp`
      unwind_state->sp = unwind_state->bp + 16;
      unwind_state->bp = next_fp;
      // Rewinding the program counter to get the instruction pointer for the previous function
      // would be ideal but is unreliable in `x86` due to variable width encoding. We can ensure correctness only by disassembling the `.text` section which
      // would be unfeasible. Since return addresses always point to the next instruction to be executed after returning from the function (and stack grows
      // downwards), subtracting 1 from the current `ra` gives us the current instruction pointer location, if not the exact instruction boundary
      unwind_state->ip = ra - 1;
      len = unwind_state->stack.len;

      // add ra for frame
      if (len >= 0 && len < MAX_STACK_DEPTH) {
        unwind_state->stack.addresses[len] = ra;
        unwind_state->stack.len++;
        bump_unwind_success_jit_frame();
      }

      continue;
    } else if (unwind_table_result == FIND_UNWIND_SPECIAL) {
      LOG("special section, stopping");
      return 1;
    } else if (unwind_table_result == FIND_UNWIND_MAPPING_NOT_FOUND) {
      request_refresh_process_info(ctx, user_pid);
      return 1;
    } else if (chunk_info == NULL) {
      // improve
      reached_bottom_of_stack = true;
      break;
    }

    stack_unwind_table_t *unwind_table = bpf_map_lookup_elem(&unwind_tables, &chunk_info->shard_index);
    if (unwind_table == NULL) {
      LOG("unwind table is null :( for shard %llu", chunk_info->shard_index);
      return 0;
    }

    LOG("le offset: %llx", offset);
    u64 left = chunk_info->low_index;
    u64 right = chunk_info->high_index;
    LOG("========== left %llu right %llu", left, right);

    u64 table_idx = find_offset_for_pc(unwind_table, unwind_state->ip - offset, left, right);

    if (table_idx == BINARY_SEARCH_DEFAULT || table_idx == BINARY_SEARCH_SHOULD_NEVER_HAPPEN || table_idx == BINARY_SEARCH_EXHAUSTED_ITERATIONS) {
      LOG("[error] binary search failed with %llx", table_idx);
      return 1;
    }

    LOG("\t=> table_index: %d", table_idx);
    LOG("\t=> adjusted pc: %llx", unwind_state->ip - offset);

    // Appease the verifier.
    if (table_idx < 0 || table_idx >= MAX_UNWIND_TABLE_SIZE) {
      LOG("\t[error] this should never happen");
      bump_unwind_error_should_never_happen();
      return 1;
    }

    u64 found_pc = unwind_table->rows[table_idx].pc;
    u8 found_cfa_type = unwind_table->rows[table_idx].cfa_type;
    u8 found_rbp_type = unwind_table->rows[table_idx].rbp_type;
    s16 found_cfa_offset = unwind_table->rows[table_idx].cfa_offset;
    s16 found_rbp_offset = unwind_table->rows[table_idx].rbp_offset;
    LOG("\tcfa type: %d, offset: %d (row pc: %llx)", found_cfa_type, found_cfa_offset, found_pc);

    if (found_cfa_type == CFA_TYPE_END_OF_FDE_MARKER) {
      LOG("[info] PC %llx not contained in the unwind info, found marker", unwind_state->ip);
      reached_bottom_of_stack = true;
      bump_unwind_success_dwarf_reach_bottom(); // assuming we only have unwind tables for DWARF frames, not FP or JIT frames
      break;
    }

    if (found_rbp_type == RBP_TYPE_UNDEFINED_RETURN_ADDRESS) {
      LOG("[info] null return address, end of stack", unwind_state->ip);
      reached_bottom_of_stack = true;
      bump_unwind_success_dwarf_reach_bottom();
      break;
    }

    // Add address to stack.
    u64 len = unwind_state->stack.len;
    // Appease the verifier.
    // For some reason bailing out here if the condition is not true does
    // not work?

    // This is for the case when we are NOT switching unwinding from JIT to DWARF section
    // i.e. unwind_state->unwinding_jit holds false
    if (!unwind_state->unwinding_jit) {
      if (len >= 0 && len < MAX_STACK_DEPTH) {
        unwind_state->stack.addresses[len] = unwind_state->ip;

        unwind_state->stack.len++;
      }
    }

    // Set unwind_state->unwinding_jit to false once we have checked for switch from JITed unwinding to DWARF unwinding
    if (unwind_state->unwinding_jit) {
      bump_unwind_success_jit_to_dwarf();
      LOG("[debug] Switched to mixed-mode DWARF unwinding");
    }
    unwind_state->unwinding_jit = false;

    if (found_rbp_type == RBP_TYPE_REGISTER || found_rbp_type == RBP_TYPE_EXPRESSION) {
      LOG("\t[error] frame pointer is %d (register or exp), bailing out", found_rbp_type);
      bump_unwind_error_unsupported_frame_pointer_action();
      return 1;
    }

    u64 previous_rsp = 0;
    if (found_cfa_type == CFA_TYPE_RBP) {
      previous_rsp = unwind_state->bp + found_cfa_offset;
    } else if (found_cfa_type == CFA_TYPE_RSP) {
      previous_rsp = unwind_state->sp + found_cfa_offset;
    } else if (found_cfa_type == CFA_TYPE_EXPRESSION) {
      if (found_cfa_offset == DWARF_EXPRESSION_UNKNOWN) {
        LOG("[unsup] CFA is an unsupported expression, bailing out");
        bump_unwind_error_unsupported_expression();
        return 1;
      }

      LOG("CFA expression found with id %d", found_cfa_offset);

      u64 threshold = 0;
      if (found_cfa_offset == DWARF_EXPRESSION_PLT1) {
        threshold = 11;
      } else if (found_cfa_offset == DWARF_EXPRESSION_PLT2) {
        threshold = 10;
      }

      if (threshold == 0) {
        bump_unwind_error_should_never_happen();
        return 1;
      }
      previous_rsp = unwind_state->sp + 8 + ((((unwind_state->ip & 15) >= threshold)) << 3);
    } else {
      LOG("\t[unsup] register %d not valid (expected $rbp or $rsp)", found_cfa_type);
      bump_unwind_error_unsupported_cfa_register();
      return 1;
    }

    // TODO(javierhonduco): A possible check could be to see whether this value
    // is within the stack. This check could be quite brittle though, so if we
    // add it, it would be best to add it only during development.
    if (previous_rsp == 0) {
      LOG("[error] previous_rsp should not be zero.");
      bump_unwind_error_catchall();
      return 1;
    }

    // HACK(javierhonduco): This is an architectural shortcut we can take. As we
    // only support x86_64 at the minute, we can assume that the return address
    // is *always* 8 bytes ahead of the previous stack pointer.
    u64 previous_rip_addr = previous_rsp - 8; // the saved return address is 8 bytes ahead of the previous stack pointer
    u64 previous_rip = 0;
    int err = bpf_probe_read_user(&previous_rip, 8, (void *)(previous_rip_addr));

    if (previous_rip == 0) {
      int user_pid = pid_tgid;
      process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &user_pid);
      if (proc_info == NULL) {
        LOG("[error] should never happen");
        return 1;
      }

      if (proc_info->is_jit_compiler) {
        LOG("[warn] mapping not added yet");
        request_refresh_process_info(ctx, user_pid);

        bump_unwind_error_jit_unupdated_mapping();
        return 1;
      }

      LOG("[error] previous_rip should not be zero. This can mean that the read failed, ret=%d while reading @ %llx.", err, previous_rip_addr);
      bump_unwind_error_catchall();
      return 1;
    }

    // Set rbp register.
    u64 previous_rbp = 0;
    if (found_rbp_type == RBP_TYPE_UNCHANGED) {
      previous_rbp = unwind_state->bp;
    } else {
      u64 previous_rbp_addr = previous_rsp + found_rbp_offset;
      LOG("\t(bp_offset: %d, bp value stored at %llx)", found_rbp_offset, previous_rbp_addr);
      int ret = bpf_probe_read_user(&previous_rbp, 8, (void *)(previous_rbp_addr));
      if (ret != 0) {
        LOG("[error] previous_rbp should not be zero. This can mean "
            "that the read has failed %d.",
            ret);
        bump_unwind_error_catchall();
        return 1;
      }
    }

    LOG("\tprevious ip: %llx (@ %llx)", previous_rip, previous_rip_addr);
    LOG("\tprevious sp: %llx", previous_rsp);
    // Set rsp and rip registers
    unwind_state->ip = previous_rip;
    unwind_state->sp = previous_rsp;
    // Set rbp
    LOG("\tprevious bp: %llx", previous_rbp);
    unwind_state->bp = previous_rbp;

    // Frame finished! :)
  }

  if (reached_bottom_of_stack) {
    // We've reached the bottom of the stack once we don't find an unwind
    // entry for the given program counter and the current frame pointer
    // is 0. As per the x86_64 ABI:
    //
    // From 3.4.1 Initial Stack and Register State
    // > %rbp The content of this register is unspecified at process
    // > initialization time, > but the user code should mark the deepest
    // > stack frame by setting the frame > pointer to zero.
    //
    // https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf

    if (unwind_state->bp == 0) {
      LOG("======= reached main! =======");
      add_stack(ctx, pid_tgid, STACK_WALKING_METHOD_DWARF, unwind_state);
      bump_unwind_success_dwarf();
      // success_dwarf_to_jit keeps track of transition from DWARF unwinding to JIT unwinding
      dwarf_to_jit = true;
    } else {
      int user_pid = pid_tgid;
      process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &user_pid);
      if (proc_info == NULL) {
        LOG("[error] should never happen");
        return 1;
      }

      if (proc_info->is_jit_compiler) {
        LOG("[warn] mapping not added yet to BPF maps, rbp %llx", unwind_state->bp);
        request_refresh_process_info(ctx, user_pid);
        bump_unwind_error_jit_unupdated_mapping(); // rbp != 0 and we are expecting unwind info which is absent and not expecting JITed stacks and therefore are
                                                   // not symbolising JITed stacks here but maybe it's a JIT stack
        return 1;
      }

      LOG("[error] Could not find unwind table and rbp != 0 (%llx). New mapping?", unwind_state->bp);
      request_refresh_process_info(ctx, user_pid);
      bump_unwind_error_pc_not_covered();
    }
    return 0;
  } else if (unwind_state->stack.len < MAX_STACK_DEPTH && unwind_state->tail_calls < MAX_TAIL_CALLS) {
    LOG("Continuing walking the stack in a tail call, current tail %d", unwind_state->tail_calls);
    unwind_state->tail_calls++;
    bpf_tail_call(ctx, &programs, 0);
  }

  // We couldn't get the whole stacktrace.
  bump_unwind_error_truncated();
  return 0;
}

// Set up the initial registers to start unwinding.
static __always_inline bool set_initial_state(bpf_user_pt_regs_t *regs) {
  u32 zero = 0;

  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state == NULL) {
    // This should never happen.
    return false;
  }

  // Just reset the stack size. This must be checked in userspace to ensure
  // we aren't reading garbage data.
  unwind_state->stack.len = 0;
  unwind_state->tail_calls = 0;
  unwind_state->unwinding_jit = false;

  u64 ip = 0;
  u64 sp = 0;
  u64 bp = 0;

  if (in_kernel(PT_REGS_IP(regs))) {
    if (retrieve_task_registers(&ip, &sp, &bp)) {
      // we are in kernelspace, but got the user regs
      unwind_state->ip = ip;
      unwind_state->sp = sp;
      unwind_state->bp = bp;
    } else {
      // in kernelspace, but failed, probs a kworker
      return false;
    }
  } else {
    // in userspace
    unwind_state->ip = PT_REGS_IP(regs);
    unwind_state->sp = PT_REGS_SP(regs);
    unwind_state->bp = PT_REGS_FP(regs);
  }

  return true;
}

// Note: `set_initial_state` must be called before this function.
static __always_inline int walk_user_stacktrace(struct bpf_perf_event_data *ctx) {
  LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
  LOG("traversing stack using .eh_frame information!!");
  LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

  bpf_tail_call(ctx, &programs, 0);
  return 0;
}

SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int user_pid = pid_tgid;
  int user_tgid = pid_tgid >> 32;

  if (user_pid == 0) {
    return 0;
  }

  if (is_kthread()) {
    return 0;
  }

  if (unwinder_config.filter_processes) {
    // This can be very noisy
    // LOG("debug mode enabled, make sure you specified process name");
    if (!is_debug_enabled_for_pid(user_tgid)) {
      return 0;
    }
  }

  set_initial_state(&ctx->regs);
  u32 zero = 0;
  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state == NULL) {
    // This should never happen.
    return 0;
  }

  // 1. If we have unwind information for a process, use it.
  if (has_unwind_information(user_pid)) {
    bump_samples();

    chunk_info_t *chunk_info = NULL;
    enum find_unwind_table_return unwind_table_result = find_unwind_table(&chunk_info, user_pid, unwind_state->ip, NULL);
    if (chunk_info == NULL) {
      process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &user_pid);
      if (proc_info == NULL) {
        LOG("[error] should never happen");
        return 1;
      }

      if (unwind_table_result == FIND_UNWIND_MAPPING_NOT_FOUND) {
        LOG("[warn] IP 0x%llx not covered, mapping not found.", unwind_state->ip);
        request_refresh_process_info(ctx, user_pid);
        bump_unwind_error_pc_not_covered();
        return 1;
      } else if (unwind_table_result == FIND_UNWIND_JITTED) {
        if (!unwinder_config.mixed_stack_enabled) {
          LOG("[warn] IP 0x%llx not covered, JIT (but mixed-mode unwinding disabled)!.", unwind_state->ip);
          bump_unwind_error_pc_not_covered_jit();
          bump_unwind_error_jit_mixed_mode_disabled();
          return 1;
        }
      } else if (proc_info->is_jit_compiler) {
        LOG("[warn] IP 0x%llx not covered, may be JIT!.", unwind_state->ip);
        request_refresh_process_info(ctx, user_pid);
        bump_unwind_error_pc_not_covered_jit();
        // We assume this failed because of a new JIT segment so we refresh mappings to find JIT segment in updated mappings
        bump_unwind_error_jit_unupdated_mapping();
        return 1;
      }
    }

    LOG("pid %d tgid %d", user_pid, user_tgid);
    walk_user_stacktrace(ctx);
    return 0;
  }

  // 2. We did not have unwind information, let's see if we can unwind with frame
  // pointers.
  if (has_fp(unwind_state->bp)) {
    add_stack(ctx, pid_tgid, STACK_WALKING_METHOD_FP, NULL);
    return 0;
  }

  // 3. Request unwind information.
  request_unwind_information(ctx, user_pid);
  return 0;
}

#define KBUILD_MODNAME "parca-agent"
volatile const char bpf_metadata_name[] SEC(".rodata") = "parca-agent (https://github.com/parca-dev/parca-agent)";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
