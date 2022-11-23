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
// Number of frames to walk in total.
#define MAX_STACK_DEPTH 127
// Number of stacks.
#define MAX_STACK_TRACES 1024
// Number of items in the stack counts aggregation map.
#define MAX_STACK_COUNTS_ENTRIES 10240
// Size of the `<(pid, shard_id), unwind_table>` mapping. Determines how many
// processes we can unwind.
#define MAX_PID_MAP_SIZE 100
// Binary search iterations for dwarf based stack walking.
// 2^20 can bisect ~1_048_576 entries.
#define MAX_BINARY_SEARCH_DEPTH 20
// Size of the unwind table.
#define MAX_UNWIND_TABLE_SIZE 250 * 1000

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

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                  \
  BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries);

#define DEFINE_COUNTER(__func__name)                                           \
  static void BUMP_##__func__name() {                                          \
    u32 *c = bpf_map_lookup_elem(&percpu_stats, &__func__name);                \
    if (c != NULL) {                                                           \
      *c += 1;                                                                 \
    }                                                                          \
  }

/*============================= INTERNAL STRUCTS ============================*/

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

typedef struct unwind_tables_key {
  int pid;
  int shard;
} unwind_tables_key_t;

typedef struct unwind_state {
  u64 ip;
  u64 sp;
  u64 bp;
  u32 tail_calls;
  stack_trace_t stack;
} unwind_state_t;

// A row in the stack unwinding table.
// PERF(javierhonduco): in the future, split this struct from a buffer of
// `stack_unwind_row` to multiple buffers containing each field. That way we
// would be able to not only have more entries, but we would increase
// performance as more data will be able to fit in the CPU cache.
//
// This is particularly important for the program counter => map<pid, pcs> +
// map<pid, other_data>. the second map can be split further if we decide to do
// so.
//
// This is at the cost of code readability, so should only be done if
// experiments confirm this theory.
typedef struct stack_unwind_row {
  u64 pc;
  u16 __reserved_do_not_use;
  u8 cfa_type;
  u8 rbp_type;
  s16 cfa_offset;
  s16 rbp_offset;
} stack_unwind_row_t;

// Unwinding table representation.
typedef struct stack_unwind_table_t {
  u64 low_pc;
  u64 high_pc;
  u64 table_len; // items of the table, as the max size is static.
  u64 __explicit_padding;
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
// TODO(javierhonduco): split this error into subtypes.
u32 UNWIND_CATCHALL_ERROR = 4;
// Errors that should never happen.
u32 UNWIND_SHOULD_NEVER_HAPPEN_ERROR = 5;
// PC not in table (Kernel PC?).
u32 UNWIND_PC_NOT_COVERED_ERROR = 6;
// Keep track of total samples.
u32 UNWIND_SAMPLES_COUNT = 7;

/*================================ MAPS =====================================*/

BPF_HASH(debug_pids, int, u8, 32);
BPF_HASH(stack_counts, stack_count_key_t, u64, MAX_STACK_COUNTS_ENTRIES);
BPF_STACK_TRACE(stack_traces, MAX_STACK_TRACES);
BPF_HASH(dwarf_stack_traces, int, stack_trace_t, MAX_STACK_TRACES);
BPF_HASH(unwind_tables, unwind_tables_key_t, stack_unwind_table_t,
         MAX_PID_MAP_SIZE);

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

static void unwind_print_stats() {
  u32 *success_counter = bpf_map_lookup_elem(&percpu_stats, &UNWIND_SUCCESS);
  if (success_counter == NULL) {
    return;
  }

  u32 *total_counter =
      bpf_map_lookup_elem(&percpu_stats, &UNWIND_SAMPLES_COUNT);
  if (total_counter == NULL) {
    return;
  }

  u32 *truncated_counter =
      bpf_map_lookup_elem(&percpu_stats, &UNWIND_TRUNCATED);
  if (truncated_counter == NULL) {
    return;
  }

  u32 *unsup_expression =
      bpf_map_lookup_elem(&percpu_stats, &UNWIND_UNSUPPORTED_EXPRESSION);
  if (unsup_expression == NULL) {
    return;
  }

  u32 *not_covered_count =
      bpf_map_lookup_elem(&percpu_stats, &UNWIND_PC_NOT_COVERED_ERROR);
  if (not_covered_count == NULL) {
    return;
  }

  u32 *catchall_count =
      bpf_map_lookup_elem(&percpu_stats, &UNWIND_CATCHALL_ERROR);
  if (catchall_count == NULL) {
    return;
  }

  u32 *never =
      bpf_map_lookup_elem(&percpu_stats, &UNWIND_SHOULD_NEVER_HAPPEN_ERROR);
  if (never == NULL) {
    return;
  }

  bpf_printk("[[ stats for cpu %d ]]", (int)bpf_get_smp_processor_id());
  bpf_printk("success=%lu", *success_counter);
  bpf_printk("unsup_expression=%lu", *unsup_expression);
  bpf_printk("truncated=%lu", *truncated_counter);
  bpf_printk("catchall=%lu", *catchall_count);
  bpf_printk("never=%lu", *never);

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

// Binary search the unwind table to find the row index containing the unwind
// information for a given program counter (pc).
static u64 find_offset_for_pc(stack_unwind_table_t *table, u64 pc) {
  u64 left = 0;
  u64 right = table->table_len;
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
      bpf_printk("\t.should never happen");
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

// Print an unwinding table row for debugging.
static __always_inline void show_row(stack_unwind_table_t *unwind_table,
                                     int index) {
  /*
    u64 pc = unwind_table->rows[index].pc;
    u16 cfa_type = unwind_table->rows[index].cfa_type;
    s16 cfa_offset = unwind_table->rows[index].cfa_offset;
    s16 rbp_offset = unwind_table->rows[index].rbp_offset;

    bpf_printk("~ %d entry. Loc: %llx, CFA reg: %d Offset: %d, $rbp %d", index,
               pc, cfa_type, cfa_offset, rbp_offset); */
}

// Finds whether a process should be unwound using the unwind
// tables.
static __always_inline bool has_unwind_information(pid_t pid) {
  unwind_tables_key_t key = {.pid = pid, .shard = 0};

  stack_unwind_table_t *shard1 = bpf_map_lookup_elem(&unwind_tables, &key);
  if (shard1) {
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

// Finds the unwind table for a given pid and program counter.
// Returns NULL if it can't be found, so this function can't be used to detect
// how should we unwind the native stack for a process. See
// `has_unwind_information()`.
static __always_inline stack_unwind_table_t *find_unwind_table(pid_t pid,
                                                               u64 pc) {
  unwind_tables_key_t key = {.pid = pid, .shard = 0};

  stack_unwind_table_t *shard1 = bpf_map_lookup_elem(&unwind_tables, &key);
  if (shard1) {
    if (shard1->low_pc <= pc && pc <= shard1->high_pc) {
      bpf_printk("\t Shard 1");
      return shard1;
    }
  }

  key.shard = 1;
  stack_unwind_table_t *shard2 = bpf_map_lookup_elem(&unwind_tables, &key);
  if (shard2) {
    if (shard2->low_pc <= pc && pc <= shard2->high_pc) {
      bpf_printk("\t Shard 2");
      return shard2;
    }
  }

  key.shard = 2;
  stack_unwind_table_t *shard3 = bpf_map_lookup_elem(&unwind_tables, &key);
  if (shard3) {
    if (shard3->low_pc <= pc && pc <= shard3->high_pc) {
      bpf_printk("\t Shard 3");
      return shard3;
    }
  }

  return NULL;
}

static __always_inline void add_stacks(struct bpf_perf_event_data *ctx,
                                       u64 pid_tgid,
                                       enum stack_walking_method method,
                                       unwind_state_t *unwind_state) {
  u64 zero = 0;
  stack_count_key_t stack_key = {};

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
  int kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
  if (kernel_stack_id >= 0) {
    stack_key.kernel_stack_id = kernel_stack_id;
  }

  if (method == STACK_WALKING_METHOD_DWARF) {
    int stack_hash =
        MurmurHash2((u32 *)unwind_state->stack.addresses,
                    MAX_STACK_DEPTH * sizeof(u64) / sizeof(u32), 0);
    bpf_printk("stack hash %d", stack_hash);
    stack_key.user_stack_id_dwarf = stack_hash;
    stack_key.user_stack_id = 0;

    // Insert stack.
    bpf_map_update_elem(&dwarf_stack_traces, &stack_hash, &unwind_state->stack,
                        BPF_ANY);
  } else if (method == STACK_WALKING_METHOD_FP) {
    int stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    if (stack_id >= 0) {
      stack_key.user_stack_id = stack_id;
      stack_key.user_stack_id_dwarf = 0;
    }
  }

  // Aggregate stacks.
  u64 *scount = bpf_map_lookup_or_try_init(&stack_counts, &stack_key, &zero);
  if (scount) {
    __sync_fetch_and_add(scount, 1);
  }
}

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

  // #pragma clang loop unroll(full)
  for (int i = 0; i < MAX_STACK_DEPTH_PER_PROGRAM; i++) {
    bpf_printk("## frame: %d", i);

    bpf_printk("\tcurrent pc: %llx", unwind_state->ip);
    bpf_printk("\tcurrent sp: %llx", unwind_state->sp);
    bpf_printk("\tcurrent bp: %llx", unwind_state->bp);

    stack_unwind_table_t *unwind_table =
        find_unwind_table(user_pid, unwind_state->ip);

    if (unwind_table == NULL) {
      reached_bottom_of_stack = true;
      break;
    }

    u64 table_idx = find_offset_for_pc(unwind_table, unwind_state->ip);

    if (table_idx == BINARY_SEARCH_NOT_FOUND ||
        table_idx == BINARY_SEARCH_SHOULD_NEVER_HAPPEN ||
        table_idx == BINARY_SEARCH_EXHAUSTED_ITERATIONS) {
      bpf_printk("[error] binary search failed with %llx", table_idx);
      return 1;
    }

    bpf_printk("\t=> table_index: %d", table_idx);

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

    bpf_printk("\tcfa type: %d, offset: %d (row pc: %llx)", found_cfa_type,
               found_cfa_offset, found_pc);

    if (found_rbp_type == RBP_TYPE_REGISTER ||
        found_rbp_type == RBP_TYPE_EXPRESSION) {
      bpf_printk("\t!!!! frame pointer is %d (register or exp), bailing out",
                 found_rbp_type);
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

      previous_rsp = unwind_state->sp + 8 +
                     ((((unwind_state->ip & 15) >= threshold)) << 3);
    } else {
      bpf_printk("\t[error] register %d not valid (expected $rbp or $rsp)",
                 found_cfa_type);
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
    u64 previous_rip_addr =
        previous_rsp - 8; // the saved return address is 8 bytes ahead of the
                          // previous stack pointer
    u64 previous_rip = 0;
    int err = bpf_probe_read_user(
        &previous_rip, 8,
        (void *)(previous_rip_addr)); // 8 bytes, a whole word
                                      // in a 64 bits machine

    if (previous_rip == 0) {
      bpf_printk("[error] previous_rip should not be zero. This can mean that "
                 "the read failed, ret=%d while reading @ %llx.",
                 err, previous_rip_addr);
      BUMP_UNWIND_CATCHALL_ERROR();
      return 1;
    }

    // Set rbp register.
    u64 previous_rbp = 0;
    if (found_rbp_type == RBP_TYPE_UNCHANGED) {
      previous_rbp = unwind_state->bp;
    } else {
      u64 previous_rbp_addr = previous_rsp + found_rbp_offset;
      bpf_printk("\t(bp_offset: %d, bp value stored at %llx)", found_rbp_offset,
                 previous_rbp_addr);
      int ret = bpf_probe_read_user(
          &previous_rbp, 8,
          (void *)(previous_rbp_addr)); // 8 bytes, a whole word in a 64 bits
                                        // machine

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
      add_stacks(ctx, pid_tgid, STACK_WALKING_METHOD_DWARF, unwind_state);
      BUMP_UNWIND_SUCCESS();
      bpf_printk("yesssss :)");
    } else {
      // TODO(javierhonduco): The current code doesn't have good support for
      // JIT'ed code, this is something that will be worked on in future
      // iterations.
      bpf_printk("[error] Could not find unwind table and rbp != 0 (%llx). "
                 "JIT'ed / bug?",
                 unwind_state->bp);
      BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
    }
    return 0;
  } else if (unwind_state->stack.len < MAX_STACK_DEPTH &&
             unwind_state->tail_calls < MAX_TAIL_CALLS) {
    bpf_printk("Continuing walking the stack in a tail call, current tail %d",
               unwind_state->tail_calls);
    unwind_state->tail_calls++;
    bpf_tail_call(ctx, &programs, 0);
  }

  // We couldn't walk enough frames
  bpf_printk("nooooooo :(");
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

static __always_inline int
walk_user_stacktrace(struct bpf_perf_event_data *ctx) {

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

  if (user_pid == 0)
    return 0;

  if (config.debug) {
    bpf_printk("debug mode enabled, make sure you specified process name");
    if (!is_debug_enabled_for_pid(user_tgid))
      return 0;
  }

  bool has_unwind_info = has_unwind_information(user_pid);
  // Check if the process is eligible for the unwind table or frame pointer
  // unwinders.
  if (!has_unwind_info) {
    add_stacks(ctx, pid_tgid, STACK_WALKING_METHOD_FP, NULL);
  } else {
    stack_unwind_table_t *unwind_table =
        find_unwind_table(user_pid, ctx->regs.ip);
    if (unwind_table == NULL) {
      bpf_printk("IP not covered. In kernel space / bug? IP %llx)",
                 ctx->regs.ip);
      BUMP_UNWIND_PC_NOT_COVERED_ERROR();
      return 0;
    }

    u64 last_idx = unwind_table->table_len - 1;
    // Appease the verifier.
    if (last_idx < 0 || last_idx >= MAX_UNWIND_TABLE_SIZE) {
      bpf_printk("\t[error] this should never happen");
      BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
      return 0;
    }

    // javierhonduco: Debug output to ensure that the maps are correctly
    // populated by comparing it with the data
    // we are writing. Remove later on.
    show_row(unwind_table, 0);
    show_row(unwind_table, 1);
    show_row(unwind_table, 2);
    show_row(unwind_table, last_idx);

    bpf_printk("pid %d tgid %d", user_pid, user_tgid);
    walk_user_stacktrace(ctx);
  }

  return 0;
}

#define KBUILD_MODNAME "parca-agent"
volatile const char bpf_metadata_name[] SEC(".rodata") =
    "parca-agent (https://github.com/parca-dev/parca-agent)";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
