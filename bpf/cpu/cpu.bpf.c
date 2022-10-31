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

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*================================ CONSTANTS =================================*/

#define MAX_STACK_DEPTH 127 // Max depth of each stack trace to track

#define MAX_STACK_ADDRESSES 1024 // Num of unique stack traces.
#define MAX_ENTRIES                                                            \
  10240 // Num entries for the `stack_counts` map. Unused atm.
        // TODO(javierhonduco): use this later on.
#define UNWIND_TABLES_MAX_STACK_DEPTH                                          \
  100 // Max depth of each stack trace to track. TODO(javierhonduco): just to
      // debug. Set to a larger number.
#define MAX_PID_MAP_SIZE                                                       \
  256 // Size of the `<PID, unwind_table>` mapping. Determines how many
      // processes we can unwind.
#define MAX_BINARY_SEARCH_DEPTH                                                \
  20 // Binary search iterations. 2ˆ20 can bisect ~1_048_576 entries.
#define MAX_UNWIND_TABLE_SIZE 130 * 1000 // Size of the unwind_table.

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
  u32 pid;
  int user_stack_id;
  int kernel_stack_id;
  stack_trace_t unwind_table_frames;
} stack_count_key_t;

// A row in the stack unwinding table.
// PERF(javierhonduco): in the future, split this struct from a buffer of
// `stack_unwind_row`` to multiple buffers containing each field. That way we
// would be able to not only have more entries, but we would increase
// performance as more data will be able to fit in the CPU cache.
//
// This is particularly important for the program counter => map<pid, pcs> +
// map<pid, other_data>. the second map can be split further if we decide to do
// so.
//
// This is at the cost of code readability, so should only be done if
// experiments confirm this theory.
//
// PERF(javierhonduco): Some of these types use a bigger type than we need, but
// this makes prototyping easier as no padding should be added between fields.
// Later on, we can make this more compact, which again, will allow us to pack
// more items + make a better use of the CPU caches.
typedef struct stack_unwind_row {
  u64 pc;
  u64 cfa_reg;
  s64 cfa_offset;
  s64 rbp_offset;
} stack_unwind_row_t;

// Unwinding table representation.
typedef struct stack_unwind_table_t {
  u64 table_len; // size of the table, as the max size is static.
  stack_unwind_row_t rows[MAX_UNWIND_TABLE_SIZE];
} stack_unwind_table_t;

// Context for the binary search. We mutate it on every step and at the end
// we read the resulting values.
struct callback_ctx {
  u64 pc;                      // the needle.
  stack_unwind_table_t *table; // the haystack.
  u32 found;
  u32 left;  // current left index.
  u32 right; // current right index.
};

// TODO(javierhonduco): Improve register list, this is just the two
// registers we need for x86_64.
enum registers {
  X86_64_REGISTER_RBP = 6,
  X86_64_REGISTER_RSP = 7,
};

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

BPF_HASH(stack_counts, stack_count_key_t, u64, MAX_ENTRIES);

BPF_STACK_TRACE(stack_traces, MAX_STACK_ADDRESSES);
BPF_HASH(unwind_tables, pid_t, stack_unwind_table_t, MAX_PID_MAP_SIZE);

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, stack_count_key_t);
} heap SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 10);
  __type(key, __u32);
  __type(value, __u32);
} percpu_stats SEC(".maps");

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

// This function does 1 iteration of the binary search.
// It's called via `bpf_loop` as the BPF verifier is unable
// to verify a single function that does all the steps.
//
// (See comment around the call-site.)
//
// Experimentally, I have seen that ~7 iterations could
// be completed with the approach I previously tried, but
// unfortunately, that's just ~128 (2^7) entries, which
// won't be enough for most tables.
//
// In my tests a very small binary already has 60k entries,
// so it requires ~log2(60k) ~= 16 iterations to find an entry
// in this case.
static int find_offset_for_pc(__u32 index, void *data) {
  struct callback_ctx *ctx = data;

  // TODO(javierhonduco): ensure that this condition is right as we use
  // unsigned values...
  if (ctx->left >= ctx->right) {
    bpf_printk("\t.done");
    return 1;
  }

  u32 mid = (ctx->left + ctx->right) / 2;

  // Appease the verifier.
  if (mid < 0 || mid >= MAX_UNWIND_TABLE_SIZE) {
    bpf_printk("\t.should never happen");
    BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
    return 1;
  }

  // Debug logs.
  // bpf_printk("\t-> fetched PC %llx, target PC %llx (iteration %d/%d, mid: %d,
  // left:%d, right:%d)", ctx->table->rows[mid].pc, ctx->pc, index,
  // MAX_BINARY_SEARCH_DEPTH, mid, ctx->left, ctx->right);
  if (ctx->table->rows[mid].pc <= ctx->pc) {
    ctx->found = mid;
    ctx->left = mid + 1;
  } else {
    ctx->right = mid;
  }

  // Debug logs.
  // bpf_printk("\t<- fetched PC %llx, target PC %llx (iteration %d/%d, mid: --,
  // left:%d, right:%d)", ctx->table->rows[mid].pc, ctx->pc, index,
  // MAX_BINARY_SEARCH_DEPTH, ctx->left, ctx->right);

  return 0;
}

// Print an unwinding table row for debugging.
static __always_inline void show_row(stack_unwind_table_t *unwind_table,
                                     int index) {
  u64 pc = unwind_table->rows[index].pc;
  int cfa_reg = unwind_table->rows[index].cfa_reg;
  int cfa_offset = unwind_table->rows[index].cfa_offset;
  int rbp_offset = unwind_table->rows[index].rbp_offset;

  bpf_printk("~ %d entry. Loc: %llx, CFA reg: %d Offset: %d, $rbp %d", index,
             pc, cfa_reg, cfa_offset, rbp_offset);
}
static __always_inline int
walk_user_stacktrace(bpf_user_pt_regs_t *regs,
                     stack_unwind_table_t *unwind_table, stack_trace_t *stack) {
  u64 current_rip = regs->ip;
  u64 current_rsp = regs->sp;
  u64 current_rbp = regs->bp;

  bpf_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
  bpf_printk("traversing stack using .eh_frame information!!");
  bpf_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

  u64 table_len = unwind_table->table_len;
  // Just for debugging to ensure that the data we are reading
  // matches what we wrote.
  bpf_printk("- unwind table has %d items", table_len);

  // Invariant check.
  if (table_len >= MAX_UNWIND_TABLE_SIZE) {
    bpf_printk("should never happen");
    BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
    return 1;
  }

  bump_samples();

  // #pragma clang loop unroll(full)
  for (int i = 0; i < MAX_STACK_DEPTH; i++) {
    bpf_printk("## frame: %d", i);

    bpf_printk("\tcurrent pc: %llx", current_rip);
    bpf_printk("\tcurrent sp: %llx", current_rsp);
    bpf_printk("\tcurrent bp: %llx", current_rbp);

    struct callback_ctx callback_context = {
        .pc = current_rip,
        .table = unwind_table,
        .found = 0,
        .left = 0,
        .right = table_len - 1,
    };

    // Note that we are using bpf_loop whilst prototyping. We might change the
    // approach later on to support older kernels, but so far it's very
    // convenient (not having to deal with global state, such as what rbperf has
    // to do. Avoiding having to do this is good when prototyping)
    bpf_loop(MAX_BINARY_SEARCH_DEPTH, find_offset_for_pc, &callback_context, 0);

    u64 table_idx = callback_context.found;
    bpf_printk("\t=> table_index: %d", table_idx);

    // Appease the verifier.
    if (table_idx < 0 || table_idx >= MAX_UNWIND_TABLE_SIZE) {
      bpf_printk("\t[error] this should never happen");
      BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
      return 1;
    }

    u64 last_idx = unwind_table->table_len - 1;
    // Appease the verifier.
    if (last_idx < 0 || last_idx >= MAX_UNWIND_TABLE_SIZE) {
      bpf_printk("\t[error] this should never happen");
      BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
      return 0;
    }

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
    if ((current_rip < unwind_table->rows[0].pc ||
         current_rip > unwind_table->rows[last_idx].pc) &&
        current_rbp == 0) {
      bpf_printk("======= reached main! =======");
      stack->len = i;
      BUMP_UNWIND_SUCCESS();
      return 0;
    }

    // Add address to stack.
    stack->addresses[i] = current_rip;

    u64 found_pc = unwind_table->rows[table_idx].pc;
    u64 found_cfa_reg = unwind_table->rows[table_idx].cfa_reg;
    s64 found_cfa_offset = unwind_table->rows[table_idx].cfa_offset;
    s64 found_rbp_offset = unwind_table->rows[table_idx].rbp_offset;

    bpf_printk("\tcfa reg: $%s, offset: %d (row pc: %llx)",
               found_cfa_reg == X86_64_REGISTER_RSP ? "rsp" : "rbp",
               found_cfa_offset, found_pc);

    // HACK(javierhonduco): dwarf expressions aren't supported. We set these
    // values to the register and the offset to recognise them.
    if (found_cfa_reg == 0xBEEF && found_cfa_offset == 0xBADFAD) {
      bpf_printk("\t!!!! CFA is an expression, bailing out");
      BUMP_UNWIND_UNSUPPORTED_EXPRESSION();
      return 1;
    }

    u64 previous_rsp = 0;
    if (found_cfa_reg == X86_64_REGISTER_RBP) {
      previous_rsp = current_rbp + found_cfa_offset;
    } else if (found_cfa_reg == X86_64_REGISTER_RSP) {
      previous_rsp = current_rsp + found_cfa_offset;
    } else {
      bpf_printk("\t[error] register %d not valid (expected $rbp or $rsp)",
                 found_cfa_reg);
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
    if (found_rbp_offset == 0) {
      previous_rbp = current_rbp;
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
    current_rip = previous_rip;
    current_rsp = previous_rsp;
    // Set rbp
    bpf_printk("\tprevious bp: %llx", previous_rbp);
    current_rbp = previous_rbp;

    // Frame finished! :)
  }

  // We couldn't walk enough frames
  BUMP_UNWIND_TRUNCATED();
  return 1;
}

SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u32 pid = id;

  if (pid == 0)
    return 0;

  u32 zero = 0;
  stack_count_key_t *stack = bpf_map_lookup_elem(&heap, &zero);
  if (stack == NULL) {
    // This should never happen.
    return 1;
  }

  // Reset global state.
  stack->unwind_table_frames.len = 0;
  stack->pid = tgid;
  stack->user_stack_id = 0;
  stack->kernel_stack_id = 0;

  // Get kernel stack.
  int kernel_stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
  if (kernel_stack_id >= 0) {
    stack->kernel_stack_id = kernel_stack_id;
  }

  stack_unwind_table_t *unwind_table =
      bpf_map_lookup_elem(&unwind_tables, &pid);

  // Check if the process is eligible for the unwind table or frame pointer
  // unwinders.
  if (unwind_table == NULL) {
    int stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    if (stack_id >= 0) {
      stack->user_stack_id = stack_id;
    }
    // Aggregate stacks.
    u64 zero = 0;
    u64 *scount = bpf_map_lookup_or_try_init(&stack_counts, stack, &zero);
    if (scount) {
      __sync_fetch_and_add(scount, 1);
    }
  } else {
    u64 last_idx = unwind_table->table_len - 1;
    // Appease the verifier.
    if (last_idx < 0 || last_idx >= MAX_UNWIND_TABLE_SIZE) {
      bpf_printk("\t[error] this should never happen");
      BUMP_UNWIND_SHOULD_NEVER_HAPPEN_ERROR();
      return 0;
    }

    if (ctx->regs.ip < unwind_table->rows[0].pc ||
        ctx->regs.ip > unwind_table->rows[last_idx].pc) {
      bpf_printk("IP not covered. In kernel space / bug? IP %llx",
                 ctx->regs.ip);
      BUMP_UNWIND_PC_NOT_COVERED_ERROR();
      return 0;
    }

    int ret = walk_user_stacktrace(&ctx->regs, unwind_table,
                                   &stack->unwind_table_frames);
    if (ret == 0) {
      // Aggregate stacks.
      u64 zero = 0;
      u64 *scount = bpf_map_lookup_or_try_init(&stack_counts, stack, &zero);
      if (scount) {
        __sync_fetch_and_add(scount, 1);
      }

      bpf_printk("yesssss :)");
    } else {
      bpf_printk("noooooo :(");
    }

    // javierhonduco: Debug output to ensure that the maps are correctly
    // populated by comparing it with the data
    // we are writing. Remove later on.
    show_row(unwind_table, 0);
    show_row(unwind_table, 1);
    show_row(unwind_table, 2);
    show_row(unwind_table, last_idx);
  }

  return 0;
}

#define KBUILD_MODNAME "parca-agent"
volatile const char bpf_metadata_name[] SEC(".rodata") =
    "parca-agent (https://github.com/parca-dev/parca-agent)";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
