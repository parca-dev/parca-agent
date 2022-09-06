// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler

// TODO(kakkoyun): Remove unused macros and functions.

#define KBUILD_MODNAME "parca-agent"

#undef container_of

// TODO(kakkoyun): Split into multiple files.
#include "../common.h"

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

#define MAX_STACK_ADDRESSES 1024 // Num of unique stack traces.
#define MAX_ENTRIES 10240 // Num entries for the `counts` map. Unused atm. TODO(javierhonduco): use this later on.
#define MAX_STACK_DEPTH 50 // Max depth of each stack trace to track. TODO(javierhonduco): just to debug. Set to a larger number.
#define MAX_PID_MAP_SIZE 256 // Size of the `<PID, unwind_table>` mapping. Determines how many processes we can unwind.
#define MAX_BINARY_SEARCH_DEPTH 20 // Binary search iterations. 2ˆ20 can bisect ~1_048_576 entries.
#define MAX_UNWIND_TABLE_SIZE 100 * 1000 // Size of the unwind_table. 

/*=========================== MACROS ==================================*/

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)            \
  struct {                                                                     \
    __uint(type, _type);                                                       \
    __uint(max_entries, _max_entries);                                         \
    __type(key, _key_type);                                                    \
    __type(value, _value_type);                                                \
  } _name SEC(".maps");
// TODO(kakkoyun): __uint(map_flags, BPF_F_NO_PREALLOC);

#define BPF_STACK_TRACE(_name, _max_entries)                                   \
  BPF_MAP(_name, BPF_MAP_TYPE_STACK_TRACE, u32, stack_trace_type, _max_entries);

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                  \
  BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries);

#define BPF_ARRAY(_name, _value_type, _max_entries)                            \
  BPF_MAP(_name, BPF_MAP_TYPE_ARRAY, u32, _value_type, _max_entries);

/*============================= INTERNAL TYPE DEFINITIONS ============================*/

// TODO(javierhonduco): Unused atm, use it later on.
typedef struct stack_count_key {
  u32 pid;
  int user_stack_id;
  int kernel_stack_id;
} stack_count_key_t;

// A row in the stack unwinding table.
// PERF(javierhonduco): in the future, split this struct from a buffer of `stack_unwind_row``
// to multiple buffers containing each field. That way we would be able to not only have more
// entries, but we would increase performance as more data will be able to fit in the CPU cache.
//
// This is particularly important for the program counter => map<pid, pcs> + map<pid, other_data>.
// the second map can be split further if we decide to do so.
//
// This is at the cost of code readability, so should only be done if experiments confirm this
// theory.
//
// PERF(javierhonduco): Some of these types use a bigger type than we need, but this makes
// prototyping easier as no padding should be added between fields. Later on, we can make
// this more compact, which again, will allow us to pack more items + make a better use of the CPU
// caches.
typedef struct stack_unwind_row {
  u64 pc;
  u64 cfa_reg;
  s64 cfa_offset;
  s64 rbp_offset;
} stack_unwind_row_t;

// Keeps the lowest program counter and the highest one
// for `main` to detect if we are done walking the stack.
typedef struct process_configuration_t {
  u64 main_low_pc;
  u64 main_high_pc;
} process_configuration_t;

// Unwinding table representation.
typedef struct stack_unwind_table_t { 
  process_configuration_t process_config;
  u64 table_len; // size of the table, as the max size is static.
  stack_unwind_row_t rows[MAX_UNWIND_TABLE_SIZE]; 
} stack_unwind_table_t;

// TODO(javierhonduco): Improve register list, this is just the two
// registers we need for x86_64.
enum registers {
  X86_64_REGISTER_RBP = 6,
  X86_64_REGISTER_RSP = 7,
};

// Stack Traces are slightly different
// in that the value is 1 big byte array
// of the stack addresses
typedef __u64 stack_trace_type[MAX_STACK_DEPTH];

// The addresses of a native stack trace.
typedef struct stack_trace_t { 
  u64 addresses[MAX_STACK_DEPTH]; 
} stack_trace_t;

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


// Context for the binary search. We mutate it on every step and at the end
// we read the resulting values.
struct callback_ctx {
  u64 pc; // the needle.
  stack_unwind_table_t *table; // the haystack.
  u32 found;
  u32 left; // current left index.
  u32 right; // current right index.
};

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
static int find_offset_for_pc(__u32 index, void *data)
{
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
    return 1;
  }

  // Debug logs.
  // bpf_printk("\t-> fetched PC %llx, target PC %llx (iteration %d/%d, left:%d, right:%d)", ctx->table->rows[mid].pc, ctx->pc, index, MAX_BINARY_SEARCH_DEPTH, ctx->left, ctx->right);

  if (ctx->table->rows[mid].pc <= ctx->pc) {
    ctx->found = mid;
    ctx->left = mid + 1;
  } else {
    ctx->right = mid;
  } 
  
  // Debug logs.
  // bpf_printk("\t<- fetched PC %llx, target PC %llx (iteration %d/%d, left:%d, right:%d)", ctx->table->rows[mid].pc, ctx->pc, index, MAX_BINARY_SEARCH_DEPTH, ctx->left, ctx->right);

	return 0;
}

static __always_inline int walk_user_stacktrace(bpf_user_pt_regs_t *regs,
                                     stack_unwind_table_t *unwind_table, process_configuration_t *process_config) {
  u64 current_rip = regs->ip;
  u64 current_rsp = regs->sp;
  u64 current_rbp = regs->bp;


  stack_trace_t stack = {.addresses = {}};

  bpf_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
  bpf_printk("traversing stack using .eh_frame information!!");
  bpf_printk("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

  u64 table_len = unwind_table->table_len;
  // Just for debugging to ensure that the data we are reading
  // matches what we wrote.
  bpf_printk("- unwind table has %d items", table_len);
  bpf_printk("- main pc range %llx...%llx", process_config->main_low_pc, process_config->main_high_pc);

  // Invariant check.
  if (table_len >= MAX_UNWIND_TABLE_SIZE) {
    bpf_printk("should never happen");
    return 0;
  }

  // #pragma clang loop unroll(full)
  for (int i = 0; i < MAX_STACK_DEPTH; i++) {
    bpf_printk("## frame: %d", i);

    bpf_printk("\tcurrent pc: %llx", current_rip);
    bpf_printk("\tcurrent sp: %llx", current_rsp);
    bpf_printk("\tcurrent bp: %llx", current_rbp);
    

    // Add address to stack.
    stack.addresses[i] = current_rip;

    if (process_config->main_low_pc <= current_rip && current_rip <= process_config->main_high_pc) {
      bpf_printk("======= reached main! =======");
      return 0;
    }

    struct callback_ctx callback_context = {
      .pc = current_rip,
      .table = unwind_table,
      .found = 0,
      .left = 0,
      .right = table_len - 1, 
    };

    // TODO(javierhonduco): use the return value.
    // Note that we are using bpf_loop whilst prototyping. We might change the approach later on
    // to support older kernels, but so far it's very convenient (not having to deal with global
    // state, such as what rbperf has to do. Avoiding having to do this is good when prototyping)
    bpf_loop(MAX_BINARY_SEARCH_DEPTH, find_offset_for_pc, &callback_context, 0);

    u64 table_idx = callback_context.found;
    bpf_printk("\t=> table_index: %d", table_idx);

    // TODO(javierhonduco): add proper not found checks
    if (table_idx == -1) {
      return 0;
    }

    // Appease the verifier.
    if (table_idx < 0 || table_idx >= MAX_UNWIND_TABLE_SIZE) {      
      bpf_printk("\t[error] this should never happen");
      return 0;
    }

    u64 found_pc = unwind_table->rows[table_idx].pc;
    u64 found_cfa_reg = unwind_table->rows[table_idx].cfa_reg;
    u64 found_cfa_offset = unwind_table->rows[table_idx].cfa_offset;

    u64 frame_address = 0;

    bpf_printk("\tcfa reg: %d, offset: %d (pc: %llx)", found_cfa_reg, found_cfa_offset, found_pc);
    if (found_cfa_reg == X86_64_REGISTER_RBP) { 
      frame_address = current_rbp + found_cfa_offset;
    } else if (found_cfa_reg == X86_64_REGISTER_RSP) {
      frame_address = current_rsp + found_cfa_offset;
    } else {
      bpf_printk("\t[error] register %d not valid (expected $rbp or $rsp)", found_cfa_reg);
      return 0;
    }
    
    u64 previous_rip = 0;
    bpf_probe_read_user(&previous_rip, 8, (void *)(frame_address - 8)); // 8 bytes, a whole word in a 64 bits machine
    // TODO(javierhonduco): check invariants
    // - previous_rip != 0
    // - looks like a pointer    
    bpf_printk("\tprevious ip: %llx (@ %llx)", previous_rip, frame_address - 8);

    // Set registers (rsp and rip)
    // TODO(javierhonduco): check invariants
    // - previous_rsp != 0
    // - looks like a pointer
    u64 previous_rsp = frame_address; // + 8; // call pushes the rip to the stack, the previous stack pointer is 8 Bytes before
    bpf_printk("\tprevious sp: %llx", previous_rsp);
    current_rsp = previous_rsp;
    current_rip = previous_rip;
    // Set rbp register.
    s64 rbp_offset = unwind_table->rows[table_idx].rbp_offset;
    bpf_printk("\trbp offset %d", rbp_offset);
    bpf_printk("\tprevious bp: %llx", current_rbp);
    // TODO(javierhonduco): rbp not implemented yet.
    // bpf_probe_read_user(&current_rbp, 8, (void *)(current_rsp + rbp_offset)); // 8 bytes, a whole word in a 64 bits machine

    // Frame finished! :)
  }

  return 0;
}

// Print an unwinding table row for debugging.
static __always_inline void show_row(stack_unwind_table_t *unwind_table, int index) {
  u64 pc = unwind_table->rows[index].pc;
  int cfa_reg = unwind_table->rows[index].cfa_reg;
  int cfa_offset = unwind_table->rows[index].cfa_offset;
  int rbp_offset = unwind_table->rows[index].rbp_offset;

  bpf_printk("~ %d entry. Loc: %llx, CFA reg: %d Offset: %d, $rbp %d", index, pc, cfa_reg, cfa_offset, rbp_offset);
}

SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx) {
  u64 id = bpf_get_current_pid_tgid();
  u32 pid = id;

  if (pid == 0)
    return 0;
  
  stack_unwind_table_t *unwind_table = bpf_map_lookup_elem(&unwind_tables, &pid);
  if (unwind_table != NULL) {
    // Check if we are in the kernel and do nothing.
    // TODO(javierhonduco): Improve this check.

    if(ctx->regs.ip >= 0xc0000000) {
      // bpf_printk("in kernel space");
      return 0;
    }

    walk_user_stacktrace(&ctx->regs, unwind_table, &unwind_table->process_config);

    // javierhonduco: Debug output to ensure that the maps are correctly populated by comparing it with the data
    // we are writing. Remove later on.
    show_row(unwind_table, 0);
    show_row(unwind_table, 1);
    show_row(unwind_table, 2);
    u64 last_idx = unwind_table->table_len - 1;
    // Appease the verifier.
    if (last_idx < 0 || last_idx >= MAX_UNWIND_TABLE_SIZE) {    
      bpf_printk("\t[error] this should never happen");  
      return 0;
    }
    show_row(unwind_table, last_idx);
  }

  return 0;
}
