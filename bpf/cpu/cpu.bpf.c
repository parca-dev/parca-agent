// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler
//
// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors
//
// NOTICE: When modifying this code, check
// https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md for the
// features supported by which kernels.

#include "../common.h"
#include "hash.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*================================ CONSTANTS =================================*/

// Number of frames to walk per tail call iteration.
#define MAX_STACK_DEPTH_PER_PROGRAM 15
// Number of BPF tail calls that will be attempted.
#define MAX_TAIL_CALLS 10
// Maximum number of frames.
#define MAX_STACK_DEPTH 127
_Static_assert(MAX_TAIL_CALLS *MAX_STACK_DEPTH_PER_PROGRAM >= MAX_STACK_DEPTH, "Not enough iterations to traverse the whole stack");
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
_Static_assert(1 << MAX_BINARY_SEARCH_DEPTH >= MAX_UNWIND_TABLE_SIZE, "Unwind table too small");

// Useful to isolate stack unwinding issues.
#define DISABLE_BPF_HELPER_FP_UNWINDER 0

// Unwind tables bigger than can't fit in the remaining space
// of the current shard are broken up into chunks up to `MAX_UNWIND_TABLE_SIZE`.
#define MAX_UNWIND_TABLE_CHUNKS 30
// Maximum memory mappings per process.
#define MAX_MAPPINGS_PER_PROCESS 120

// Values for dwarf expressions.
#define DWARF_EXPRESSION_UNKNOWN 0
#define DWARF_EXPRESSION_PLT1 1
#define DWARF_EXPRESSION_PLT2 2

// Values for the unwind table's CFA type.
#define CFA_TYPE_RBP 1
#define CFA_TYPE_RSP 2
#define CFA_TYPE_EXPRESSION 3

// Values for the unwind table's frame pointer type.
#define RBP_TYPE_UNCHANGED 0
#define RBP_TYPE_OFFSET 1
#define RBP_TYPE_REGISTER 2
#define RBP_TYPE_EXPRESSION 3

// Binary search error codes.
#define BINARY_SEARCH_NOT_FOUND 0xFABADA
#define BINARY_SEARCH_SHOULD_NEVER_HAPPEN 0xDEADBEEF
#define BINARY_SEARCH_EXHAUSTED_ITERATIONS 0xBADFAD

// Stack walking methods.
enum stack_walking_method {
  STACK_WALKING_METHOD_FP = 0,
  STACK_WALKING_METHOD_DWARF = 1,
};

struct config_t {
  bool debug;
};

const volatile struct config_t config = {};

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
typedef __u64 stack_trace_type[MAX_STACK_DEPTH];
#define BPF_STACK_TRACE(_name, _max_entries) BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_type, _max_entries);

#define BPF_HASH(_name, _key_type, _value_type, _max_entries) BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries);

#define DEFINE_COUNTER(__func__name)                                                                                                                           \
  static void BUMP_##__func__name() {                                                                                                                          \
    u32 *c = bpf_map_lookup_elem(&percpu_stats, &__func__name);                                                                                                \
    if (c != NULL) {                                                                                                                                           \
      *c += 1;                                                                                                                                                 \
    }                                                                                                                                                          \
  }

/*============================= INTERNAL STRUCTS ============================*/

// Unwind table shard.
typedef struct shard_info {
  u64 low_pc;
  u64 high_pc;
  u64 shard_index;
  u64 low_index;
  u64 high_index;
} shard_info_t;

// Unwind table shards for an executable mapping.
typedef struct stack_unwind_table_shards {
  u64 len;
  shard_info_t shards[MAX_UNWIND_TABLE_CHUNKS];
} stack_unwind_table_shards_t;

// The addresses of a native stack trace.
typedef struct stack_trace_t {
  u64 len;
  u64 addresses[MAX_STACK_DEPTH];
} stack_trace_t;

typedef struct stack_count_key {
  int pid;
  int tgid;
  int user_stack_id;
  int kernel_stack_id;
  int user_stack_id_dwarf;
} stack_count_key_t;

// Represents an executable mapping.
typedef struct mapping {
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
typedef struct unwind_state {
  u64 ip;
  u64 sp;
  u64 bp;
  u32 tail_calls;
  stack_trace_t stack;
} unwind_state_t;

// A row in the stack unwinding table.
typedef struct stack_unwind_row {
  u64 pc;
  u16 __reserved_do_not_use;
  u8 cfa_type;
  u8 rbp_type;
  s16 cfa_offset;
  s16 rbp_offset;
} stack_unwind_row_t;

// Unwinding table representation.
typedef struct stack_unwind_table {
  stack_unwind_row_t rows[MAX_UNWIND_TABLE_SIZE];
} stack_unwind_table_t;

// Statistics.
//
// We reached main.
u32 UNWIND_SUCCESS = 1;
// Partial stack was retrieved.
u32 UNWIND_TRUNCATED = 2;
// An (unhandled) dwarf expression was found.
u32 UNWIND_UNSUPPORTED_EXPRESSION = 3;
// Any other error, such as failed memory reads.
u32 UNWIND_CATCHALL_ERROR = 4;
// Errors that should never happen.
u32 UNWIND_SHOULD_NEVER_HAPPEN_ERROR = 5;
// PC not in table (Kernel PC?).
u32 UNWIND_PC_NOT_COVERED_ERROR = 6;
// Keep track of total samples.
u32 UNWIND_SAMPLES_COUNT = 7;
u32 UNWIND_JIT_ERRORS = 8;

/*================================ MAPS =====================================*/

BPF_HASH(debug_pids, int, u8, MAX_PROCESSES);
BPF_HASH(process_info, int, process_info_t, MAX_PROCESSES);

BPF_STACK_TRACE(stack_traces, MAX_STACK_TRACES_ENTRIES);
BPF_HASH(dwarf_stack_traces, int, stack_trace_t, MAX_STACK_TRACES_ENTRIES);
BPF_HASH(stack_counts, stack_count_key_t, u64, MAX_STACK_COUNTS_ENTRIES);

// executable_chunks?
BPF_HASH(unwind_shards, u64, stack_unwind_table_shards_t,
         5 * 1000); // <executable_id, shardmap>
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
  __uint(max_entries, 10);
  __type(key, u32);
  __type(value, u32);
} percpu_stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, u32);
} programs SEC(".maps");

/*=========================== HELPER FUNCTIONS ==============================*/

DEFINE_COUNTER(UNWIND_SUCCESS);
DEFINE_COUNTER(UNWIND_TRUNCATED);
DEFINE_COUNTER(UNWIND_UNSUPPORTED_EXPRESSION);
DEFINE_COUNTER(UNWIND_SHOULD_NEVER_HAPPEN_ERROR);
DEFINE_COUNTER(UNWIND_CATCHALL_ERROR);
DEFINE_COUNTER(UNWIND_PC_NOT_COVERED_ERROR);
DEFINE_COUNTER(UNWIND_JIT_ERRORS);

static void unwind_print_stats() {
  u32 *success_counter = bpf_map_lookup_elem(&percpu_stats, &UNWIND_SUCCESS);
  if (success_counter == NULL) {
    return;
  }

  u32 *total_counter = bpf_map_lookup_elem(&percpu_stats, &UNWIND_SAMPLES_COUNT);
  if (total_counter == NULL) {
    return;
  }

  u32 *truncated_counter = bpf_map_lookup_elem(&percpu_stats, &UNWIND_TRUNCATED);
  if (truncated_counter == NULL) {
    return;
  }

  u32 *unsup_expression = bpf_map_lookup_elem(&percpu_stats, &UNWIND_UNSUPPORTED_EXPRESSION);
  if (unsup_expression == NULL) {
    return;
  }

  u32 *not_covered_count = bpf_map_lookup_elem(&percpu_stats, &UNWIND_PC_NOT_COVERED_ERROR);
  if (not_covered_count == NULL) {
    return;
  }

  u32 *catchall_count = bpf_map_lookup_elem(&percpu_stats, &UNWIND_CATCHALL_ERROR);
  if (catchall_count == NULL) {
    return;
  }

  u32 *never = bpf_map_lookup_elem(&percpu_stats, &UNWIND_SHOULD_NEVER_HAPPEN_ERROR);
  if (never == NULL) {
    return;
  }

  u32 *unknown_jit = bpf_map_lookup_elem(&percpu_stats, &UNWIND_JIT_ERRORS);
  if (unknown_jit == NULL) {
    return;
  }

  bpf_printk("[[ stats for cpu %d ]]", (int)bpf_get_smp_processor_id());
  bpf_printk("success=%lu", *success_counter);
  bpf_printk("unsup_expression=%lu", *unsup_expression);
  bpf_printk("truncated=%lu", *truncated_counter);
  bpf_printk("catchall=%lu", *catchall_count);
  bpf_printk("never=%lu", *never);
  bpf_printk("unknown_jit=%lu", *unknown_jit);

  bpf_printk("total_counter=%lu", *total_counter);
  bpf_printk("(not_covered=%lu)", *not_covered_count);
}

static void bump_samples() {
  u32 *c = bpf_map_lookup_elem(&percpu_stats, &UNWIND_SAMPLES_COUNT);
  if (c != NULL) {
    *c += 1;
    if (*c % 50 == 0) {
      unwind_print_stats();
    }
  }
}

static __always_inline void *bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
  void *val;
  long err;

  val = bpf_map_lookup_elem(map, key);
  if (val) {
    return val;
  }

  err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
  // 17 == EEXIST
  if (err && err != -17) {
    bpf_printk("[error] bpf_map_lookup_or_try_init with ret: %d", err);
    return 0;
  }

  return bpf_map_lookup_elem(map, key);
}

/*================================= HOOKS ==================================*/

// Binary search the unwind table to find the row index containing the unwind
// information for a given program counter (pc).
static u64 find_offset_for_pc(stack_unwind_table_t *table, u64 pc, u64 left, u64 right) {
  u64 found = BINARY_SEARCH_NOT_FOUND;

  for (int i = 0; i < MAX_BINARY_SEARCH_DEPTH; i++) {
    // TODO(javierhonduco): ensure that this condition is right as we use
    // unsigned values...
    if (left >= right) {
      bpf_printk("\t.done");
      return found;
    }

    u32 mid = (left + right) / 2;

    // Appease the verifier.
    if (mid < 0 || mid >= MAX_UNWIND_TABLE_SIZE) {
      bpf_printk("\t.should never happen, mid: %lu, max: %lu", mid, MAX_UNWIND_TABLE_SIZE);
      BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
      return BINARY_SEARCH_SHOULD_NEVER_HAPPEN;
    }

    // Debug logs.
    // bpf_printk("\t-> fetched PC %llx, target PC %llx (iteration %d/%d, mid:
    // %d, left:%d, right:%d)", ctx->table->rows[mid].pc, ctx->pc, index,
    // MAX_BINARY_SEARCH_DEPTH, mid, ctx->left, ctx->right);
    if (table->rows[mid].pc <= pc) {
      found = mid;
      left = mid + 1;
    } else {
      right = mid;
    }

    // Debug logs.
    // bpf_printk("\t<- fetched PC %llx, target PC %llx (iteration %d/%d, mid:
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
  FIND_UNWIND_SHARD_UNSET = 5,
  FIND_UNWIND_SHARD_EXHAUSTED_SEARCH = 6,
  FIND_UNWIND_SHARD_NOT_FOUND = 7,

  FIND_UNWIND_JITTED = 100,
  FIND_UNWIND_SPECIAL = 200,
};

// Finds the shard information for a given pid and program counter. Optionally,
// and offset can be passed that will be filled in with the mapping's load
// address.
static __always_inline enum find_unwind_table_return find_unwind_table(shard_info_t **shard_info, pid_t pid, u64 pc, u64 *offset) {
  process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &pid);
  // Appease the verifier.
  if (proc_info == NULL) {
    bpf_printk("[error] should never happen");
    return FIND_UNWIND_MAPPING_SHOULD_NEVER_HAPPEN;
  }

  bool found = false;
  u64 executable_id = 0;
  u64 load_address = 0;
  u64 type = 0;

  // Find the mapping.
  for (int i = 0; i < MAX_MAPPINGS_PER_PROCESS; i++) {
    if (i > proc_info->len) {
      bpf_printk("[info] mapping not found, i (%d) > proc_info->len (%d) pc: %llx", i, proc_info->len, pc);
      return FIND_UNWIND_MAPPING_EXHAUSTED_SEARCH;
    }

    // Appease the verifier.
    if (i < 0 || i > MAX_MAPPINGS_PER_PROCESS) {
      bpf_printk("[error] should never happen, verifier");
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
    if (type == 1) {
      return FIND_UNWIND_JITTED;
    }
    if (type == 2) {
      return FIND_UNWIND_SPECIAL;
    }
  } else {
    bpf_printk("[warn] :((( no mapping for ip=%llx", pc);
    return FIND_UNWIND_MAPPING_NOT_FOUND;
  }

  bpf_printk("~about to check shards found=%d", found);
  bpf_printk("~checking shards now");

  // Find the shard where this unwind table lives.
  stack_unwind_table_shards_t *shards = bpf_map_lookup_elem(&unwind_shards, &executable_id);
  if (shards == NULL) {
    bpf_printk("[info] shards is null for executable %llu", executable_id);
    return FIND_UNWIND_SHARD_NOT_FOUND;
  }

  for (int i = 0; i < MAX_UNWIND_TABLE_CHUNKS; i++) {
    if (i > shards->len) {
      return FIND_UNWIND_SHARD_EXHAUSTED_SEARCH;
    }

    if (shards->shards[i].low_pc <= pc - load_address && pc - load_address <= shards->shards[i].high_pc) {
      bpf_printk("[info] found shard");
      *shard_info = &shards->shards[i];
      return FIND_UNWIND_SUCCESS;
    }
  }

  bpf_printk("[error] could not find the right shard...");
  return FIND_UNWIND_SHARD_NOT_FOUND;
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
  // - What we call threads IDs in user space, are PIDs in kernel space.
  int user_pid = pid_tgid >> 32;
  int user_tgid = pid_tgid;
  stack_key.pid = user_pid;
  stack_key.tgid = user_tgid;

  // Get kernel stack.
  int kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_REUSE_STACKID);
  if (kernel_stack_id >= 0) {
    stack_key.kernel_stack_id = kernel_stack_id;
  }

  if (method == STACK_WALKING_METHOD_DWARF) {
    bpf_printk("kernel_stack_id: %d", kernel_stack_id);
    int stack_hash = MurmurHash2((u32 *)unwind_state->stack.addresses, MAX_STACK_DEPTH * sizeof(u64) / sizeof(u32), 0);
    bpf_printk("stack hash %d", stack_hash);
    stack_key.user_stack_id_dwarf = stack_hash;
    stack_key.user_stack_id = 0;

    // Insert stack.
    int err = bpf_map_update_elem(&dwarf_stack_traces, &stack_hash, &unwind_state->stack, BPF_ANY);
    if (err != 0) {
      bpf_printk("[error] bpf_map_update_elem with ret: %d", err);
    }

  } else if (method == STACK_WALKING_METHOD_FP) {
    bpf_printk("[info] fp unwinding %d", DISABLE_BPF_HELPER_FP_UNWINDER);
    if (DISABLE_BPF_HELPER_FP_UNWINDER) {
      return;
    }
    int stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    if (stack_id >= 0) {
      stack_key.user_stack_id = stack_id;
      stack_key.user_stack_id_dwarf = 0;
    } else {
      // should we fail here? sending a bogus stack does no good!
      // bump a  metric?
      return;
    }
  }

  // Aggregate stacks.
  u64 *scount = bpf_map_lookup_or_try_init(&stack_counts, &stack_key, &zero);
  if (scount) {
    __sync_fetch_and_add(scount, 1);
  }
}

// The unwinding machinery lives here.
SEC("perf_event")
int walk_user_stacktrace_impl(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int user_pid = pid_tgid;

  bool reached_bottom_of_stack = false;
  u64 zero = 0;

  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state == NULL) {
    bpf_printk("unwind_state is NULL, should not happen");
    return 1;
  }

  for (int i = 0; i < MAX_STACK_DEPTH_PER_PROGRAM; i++) {
    bpf_printk("## frame: %d", i);

    bpf_printk("\tcurrent pc: %llx", unwind_state->ip);
    bpf_printk("\tcurrent sp: %llx", unwind_state->sp);
    bpf_printk("\tcurrent bp: %llx", unwind_state->bp);

    u64 offset = 0;
    shard_info_t *shard = NULL;
    enum find_unwind_table_return unwind_table_result = find_unwind_table(&shard, user_pid, unwind_state->ip, &offset);

    if (unwind_table_result == FIND_UNWIND_JITTED) {
      bpf_printk("JIT section, stopping");
      return 1;
    } else if (unwind_table_result == FIND_UNWIND_SPECIAL) {
      bpf_printk("special section, stopping");
      return 1;
    } else if (shard == NULL) {
      // improve
      reached_bottom_of_stack = true;
      break;
    }

    stack_unwind_table_t *unwind_table = bpf_map_lookup_elem(&unwind_tables, &shard->shard_index);
    if (unwind_table == NULL) {
      bpf_printk("unwind table is null :( for shard %llu", shard->shard_index);
      return 0;
    }

    bpf_printk("le offset: %llx", offset);
    u64 left = shard->low_index;
    u64 right = shard->high_index;
    bpf_printk("========== left %llu right %llu", left, right);
    u64 table_idx = find_offset_for_pc(unwind_table, unwind_state->ip - offset, left, right);

    if (table_idx == BINARY_SEARCH_NOT_FOUND || table_idx == BINARY_SEARCH_SHOULD_NEVER_HAPPEN || table_idx == BINARY_SEARCH_EXHAUSTED_ITERATIONS) {
      bpf_printk("[error] binary search failed with %llx", table_idx);
      return 1;
    }

    bpf_printk("\t=> table_index: %d", table_idx);
    bpf_printk("\t=> adjusted pc: %llx", unwind_state->ip - offset);

    // Appease the verifier.
    if (table_idx < 0 || table_idx >= MAX_UNWIND_TABLE_SIZE) {
      bpf_printk("\t[error] this should never happen");
      BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
      return 1;
    }

    // Add address to stack.
    u64 len = unwind_state->stack.len;
    // Appease the verifier.
    // For some reason bailing out here if the condition is not true does
    // not work?
    if (len >= 0 && len < MAX_STACK_DEPTH) {
      unwind_state->stack.addresses[len] = unwind_state->ip;
    }

    u64 found_pc = unwind_table->rows[table_idx].pc;
    u8 found_cfa_type = unwind_table->rows[table_idx].cfa_type;
    u8 found_rbp_type = unwind_table->rows[table_idx].rbp_type;
    s16 found_cfa_offset = unwind_table->rows[table_idx].cfa_offset;
    s16 found_rbp_offset = unwind_table->rows[table_idx].rbp_offset;

    bpf_printk("\tcfa type: %d, offset: %d (row pc: %llx)", found_cfa_type, found_cfa_offset, found_pc);

    if (found_rbp_type == RBP_TYPE_REGISTER || found_rbp_type == RBP_TYPE_EXPRESSION) {
      bpf_printk("\t[error] frame pointer is %d (register or exp), bailing out", found_rbp_type);
      BUMP_UNWIND_CATCHALL_ERROR();
      return 1;
    }

    u64 previous_rsp = 0;
    if (found_cfa_type == CFA_TYPE_RBP) {
      previous_rsp = unwind_state->bp + found_cfa_offset;
    } else if (found_cfa_type == CFA_TYPE_RSP) {
      previous_rsp = unwind_state->sp + found_cfa_offset;
    } else if (found_cfa_type == CFA_TYPE_EXPRESSION) {
      if (found_cfa_offset == DWARF_EXPRESSION_UNKNOWN) {
        bpf_printk("[error] CFA is an unsupported expression, bailing out");
        BUMP_UNWIND_UNSUPPORTED_EXPRESSION();
        return 1;
      }

      bpf_printk("CFA expression found with id %d", found_cfa_offset);

      u64 threshold = 0;
      if (found_cfa_offset == DWARF_EXPRESSION_PLT1) {
        threshold = 11;
      } else if (found_cfa_offset == DWARF_EXPRESSION_PLT2) {
        threshold = 10;
      }

      if (threshold == 0) {
        BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
        return 1;
      }

      previous_rsp = unwind_state->sp + 8 + ((((unwind_state->ip & 15) >= threshold)) << 3);
    } else {
      bpf_printk("\t[error] register %d not valid (expected $rbp or $rsp)", found_cfa_type);
      BUMP_UNWIND_CATCHALL_ERROR();
      return 1;
    }
    // TODO(javierhonduco): A possible check could be to see whether this value
    // is within the stack. This check could be quite brittle though, so if we
    // add it, it would be best to add it only during development.
    if (previous_rsp == 0) {
      bpf_printk("[error] previous_rsp should not be zero.");
      BUMP_UNWIND_CATCHALL_ERROR();
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
        bpf_printk("[error] should never happen");
        return 1;
      }

      if (proc_info->is_jit_compiler) {
        bpf_printk("[info] rip=0, Section not added, yet");
        BUMP_UNWIND_JIT_ERRORS();
        return 1;
      }

      bpf_printk("[error] previous_rip should not be zero. This can mean that the read failed, ret=%d while reading @ %llx.", err, previous_rip_addr);
      BUMP_UNWIND_CATCHALL_ERROR();
      return 1;
    }

    // Set rbp register.
    u64 previous_rbp = 0;
    if (found_rbp_type == RBP_TYPE_UNCHANGED) {
      previous_rbp = unwind_state->bp;
    } else {
      u64 previous_rbp_addr = previous_rsp + found_rbp_offset;
      bpf_printk("\t(bp_offset: %d, bp value stored at %llx)", found_rbp_offset, previous_rbp_addr);
      int ret = bpf_probe_read_user(&previous_rbp, 8, (void *)(previous_rbp_addr));
      if (ret != 0) {
        bpf_printk("[error] previous_rbp should not be zero. This can mean "
                   "that the read has failed %d.",
                   ret);
        BUMP_UNWIND_CATCHALL_ERROR();
        return 1;
      }
    }

    bpf_printk("\tprevious ip: %llx (@ %llx)", previous_rip, previous_rip_addr);
    bpf_printk("\tprevious sp: %llx", previous_rsp);
    // Set rsp and rip registers
    unwind_state->ip = previous_rip;
    unwind_state->sp = previous_rsp;
    // Set rbp
    bpf_printk("\tprevious bp: %llx", previous_rbp);
    unwind_state->bp = previous_rbp;

    // Frame finished! :)
    unwind_state->stack.len++;
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
      bpf_printk("======= reached main! =======");
      add_stack(ctx, pid_tgid, STACK_WALKING_METHOD_DWARF, unwind_state);
      BUMP_UNWIND_SUCCESS();
    } else {
      int user_pid = pid_tgid;
      process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &user_pid);
      if (proc_info == NULL) {
        bpf_printk("[error] should never happen");
        return 1;
      }

      if (proc_info->is_jit_compiler) {
        bpf_printk("[info] Section not added, yet");
        BUMP_UNWIND_JIT_ERRORS();
        return 1;
      }

      bpf_printk("[error] Could not find unwind table and rbp != 0 (%llx) bug?", unwind_state->bp);
      BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
    }
    return 0;
  } else if (unwind_state->stack.len < MAX_STACK_DEPTH && unwind_state->tail_calls < MAX_TAIL_CALLS) {
    bpf_printk("Continuing walking the stack in a tail call, current tail %d", unwind_state->tail_calls);
    unwind_state->tail_calls++;
    bpf_tail_call(ctx, &programs, 0);
  }

  // We couldn't get the whole stacktrace.
  BUMP_UNWIND_TRUNCATED();
  return 0;
}

static __always_inline void set_initial_state(bpf_user_pt_regs_t *regs) {
  u32 zero = 0;

  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state == NULL) {
    // This should never happen.
    return;
  }

  // Just reset the stack size. This must be checked in userspace to ensure
  // we aren't reading garbage data.
  unwind_state->stack.len = 0;

  unwind_state->ip = regs->ip;
  unwind_state->sp = regs->sp;
  unwind_state->bp = regs->bp;
  unwind_state->tail_calls = 0;
}

static __always_inline int walk_user_stacktrace(struct bpf_perf_event_data *ctx) {

  bump_samples();

  bpf_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
  bpf_printk("traversing stack using .eh_frame information!!");
  bpf_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

  set_initial_state(&ctx->regs);
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

  if (config.debug) {
    // This can be very noisy
    // bpf_printk("debug mode enabled, make sure you specified process name");
    if (!is_debug_enabled_for_pid(user_tgid)) {
      return 0;
    }
  }

  bool has_unwind_info = has_unwind_information(user_pid);
  // Check if the process is eligible for the unwind table or frame pointer
  // unwinders.
  if (!has_unwind_info) {
    add_stack(ctx, pid_tgid, STACK_WALKING_METHOD_FP, NULL);
  } else {
    shard_info_t *shard = NULL;
    find_unwind_table(&shard, user_pid, ctx->regs.ip, NULL);
    if (shard == NULL) {
      bpf_printk("IP not covered. In kernel space / bug? IP %llx)", ctx->regs.ip);
      BUMP_UNWIND_PC_NOT_COVERED_ERROR();
      return 0;
    }

    bpf_printk("pid %d tgid %d", user_pid, user_tgid);
    walk_user_stacktrace(ctx);
  }

  return 0;
}

#define KBUILD_MODNAME "parca-agent"
volatile const char bpf_metadata_name[] SEC(".rodata") = "parca-agent (https://github.com/parca-dev/parca-agent)";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
