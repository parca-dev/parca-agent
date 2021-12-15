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
// TODO(kakkoyun): Explain.
#define MAX_PID_MAP_SIZE 1024
// TODO(kakkoyun): Explain.
#define MAX_ENTRIES 10240
// TODO(kakkoyun): Explain.
#define MAX_BINARY_SEARCH_DEPTH 24

/* Maximum value an `unsigned long int' can hold.  (Minimum is 0.)  */
#if __WORDSIZE == 64
#define ULONG_MAX 18446744073709551615UL
#else
#define ULONG_MAX 4294967295UL
#endif

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)           \
  struct bpf_map_def SEC ("maps") _name = {                                   \
    .type = _type,                                                            \
    .key_size = sizeof (_key_type),                                           \
    .value_size = sizeof (_value_type),                                       \
    .max_entries = _max_entries,                                              \
  };
// __uint(map_flags, BPF_F_NO_PREALLOC);

// Stack Traces are slightly different
// in that the value is 1 big byte array
// of the stack addresses
#define BPF_STACK_TRACE(_name, _max_entries)                                  \
  struct bpf_map_def SEC ("maps") _name = {                                   \
    .type = BPF_MAP_TYPE_STACK_TRACE,                                         \
    .key_size = sizeof (u32),                                                 \
    .value_size = sizeof (size_t) * MAX_STACK_DEPTH,                          \
    .max_entries = _max_entries,                                              \
  };

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                 \
  BPF_MAP (_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries);

#define BPF_ARRAY(_name, _value_type, _max_entries)                           \
  struct bpf_map_def SEC ("maps") _name = {                                   \
    .type = BPF_MAP_TYPE_ARRAY,                                               \
    .key_size = sizeof (u32),                                                 \
    .value_size = sizeof (_value_type),                                       \
    .max_entries = _max_entries,                                              \
  };

// .map_flags = BPF_F_NO_PREALLOC

//// Value size must be u32 because it is inner map id
//#define BPF_PID_HASH_OF_MAP(_name, _max_entries) \
//  struct bpf_map_def SEC ("maps") _name = { \
//    .type = BPF_MAP_TYPE_HASH_OF_MAPS, \
//    .key_size = sizeof (u32), \
//    .value_size = sizeof (u32), \
//    .max_entries = _max_entries, \
//  };

#define LOG(_pid, _msg)                                                       \
  {                                                                           \
    log_event_t e = { .pid = _pid, .message = _msg };                         \
    bpf_ringbuf_output (&events, &e, sizeof (e), 0);                          \
  }

typedef struct log_event
{
  u32 pid;
  char message[32];
  // u64 addr;
} log_event_t;

struct bpf_map_def SEC ("maps") events = {
  .type = BPF_MAP_TYPE_RINGBUF,
  .max_entries = 1 << 24,
};

/*============================= INTERNAL STRUCTS ============================*/

typedef struct stack_count_key
{
  u32 pid;
  int user_stack_id;
  int kernel_stack_id;
} stack_count_key_t;

typedef struct stack_unwind_instruction
{
  u8 op;
  u64 reg;
  s64 offset;
} stack_unwind_instruction_t;

/*================================ MAPS =====================================*/

BPF_HASH (counts, stack_count_key_t, u64, MAX_ENTRIES);
BPF_STACK_TRACE (stack_traces, MAX_STACK_ADDRESSES);

BPF_ARRAY (chosen, u32, 2);   // TODO(kakkoyun): Remove later.
BPF_ARRAY (pcs, u64, 200000); // 0xffffff // 200_000
BPF_ARRAY (rips, stack_unwind_instruction_t, 200000);
BPF_ARRAY (rsps, stack_unwind_instruction_t, 200000);

BPF_ARRAY (unwinded_stack_traces, u64, MAX_STACK_DEPTH);

// BPF_PID_HASH_OF_MAP (pcs, MAX_PID_MAP_SIZE);
// BPF_PID_HASH_OF_MAP (rips, MAX_PID_MAP_SIZE);
// BPF_PID_HASH_OF_MAP (rsps, MAX_PID_MAP_SIZE);

/*=========================== HELPER FUNCTIONS ==============================*/

static __always_inline void *
bpf_map_lookup_or_try_init (void *map, const void *key, const void *init)
{
  void *val;
  long err;

  val = bpf_map_lookup_elem (map, key);
  if (val)
    return val;

  err = bpf_map_update_elem (map, key, init, BPF_NOEXIST);
  // 17 == EEXIST
  if (err && err != -17)
    return 0;

  return bpf_map_lookup_elem (map, key);
}

static __always_inline u32 *
find (u64 target)
{
  // TODO(kakkoyun): Is there a better way to get current size?
  u32 right = MAX_ENTRIES - 1;
  u32 one = 1; // Second element is the size of the unwind table.
  u32 *val;
  val = bpf_map_lookup_elem (&chosen, &one);
  if (val)
    right = *val;

  u32 left = 0;
  static u32 mid;
  int i = 0;
  // #pragma clang loop unroll(full)
  while (i < MAX_BINARY_SEARCH_DEPTH && left <= right)
    {
      i++;

      mid = left + (right - left) / 2;

      u64 *val;
      val = bpf_map_lookup_elem (&pcs, &mid);
      u64 guess;
      if (val)
        guess = *val;
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

static __always_inline u64
execute (stack_unwind_instruction_t *ins, u64 rip, u64 rsp, u64 cfa)
{
  u64 addr;
  u64 unsafe_ptr = cfa + ins->offset;
  u64 res = 0;
  switch (ins->op)
    {
    case 1: // OpUndefined: Undefined register.
      if (bpf_probe_read (&addr, 8, &unsafe_ptr) == 0)
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

static __always_inline void *
backtrace (bpf_user_pt_regs_t *regs, u32 stack_id)
{
  bpf_printk ("backtrace");
  long unsigned int rip = regs->ip;
  long unsigned int rsp = regs->sp;
  // TODO(kakkoyun): Bigger than 512B limit.
  // - Figure out how to use stack traces map.
  // long unsigned int stack[MAX_STACK_DEPTH];
  // #pragma clang loop unroll(full)
  for (int d = 0; d < MAX_STACK_DEPTH; d++)
    {
      bpf_printk ("backtrace, depth: %d, %u", d, rip);
      if (rip == 0)
        break;

      // bpf_printk ("backtrace, step 1, depth: %d, %u", d, rip);
      // Push the found return address.
      // stack[d] = rip;
      if (bpf_map_update_elem (&unwinded_stack_traces, &d, &rip, BPF_ANY) < 0)
        {
          bpf_printk ("backtrace, failed to update stack trace\n");
          break;
        }

      // bpf_printk ("backtrace, step 2, depth: %d, %u", d, rip);
      u32 *val = find (rip);
      if (val == NULL)
        {
          // bpf_printk ("backtrace, NOT FOUND, depth: %d, %u", d, rip);
          break;
        }

      bpf_printk ("backtrace, FOUND, depth: %d, %u", d, rip);
      // bpf_printk ("backtrace, step 3, depth: %d, %u", d, rip);
      u32 key = *val;
      stack_unwind_instruction_t *ins;
      ins = bpf_map_lookup_elem (&rsps, &key);
      if (ins == NULL)
        break;

      // bpf_printk ("backtrace, step 4, depth: %d, %u", d, rip);
      u64 cfa;
      cfa = execute (ins, rip, rsp, 0);
      if (cfa == 0)
        break;

      // bpf_printk ("backtrace, step 5, depth: %d, %u", d, rip);
      ins = bpf_map_lookup_elem (&rips, &key);
      if (ins == NULL)
        break;

      // bpf_printk ("backtrace, step 6, depth: %d, %u", d, rip);
      rip = execute (ins, rip, rsp, cfa);
      rsp = cfa;
    }

  bpf_printk ("backtrace, done, %u\n", rip);
  // if (bpf_map_update_elem (&stack_traces, &stack_id, &stack, BPF_ANY) < 0)
  //   {
  //     bpf_printk ("backtrace, failed to update stack trace\n");
  //     return NULL;
  //   }
  return 0;
}

/*=========================== BPF FUNCTIONS ==============================*/

SEC ("perf_event")
int
do_sample (struct bpf_perf_event_data *ctx)
{
  u64 id = bpf_get_current_pid_tgid ();
  u32 tgid = id >> 32;
  u32 pid = id;

  if (pid == 0)
    return 0;

  // create map key
  stack_count_key_t key = { .pid = tgid };

  // get user stack
  key.user_stack_id = 0;
  int stack_id = bpf_get_stackid (ctx, &stack_traces, BPF_F_USER_STACK);
  if (stack_id >= 0)
    key.user_stack_id = stack_id;

  // First element is the PID to lookup.
  u32 zero = 0;
  u32 *val;
  val = bpf_map_lookup_elem (&chosen, &zero);
  // // TODO(kakkoyun): Test if we can unwind the stack using frame pointers.
  if (val && pid == *val)
    {
      // TODO(kakkoyun): which appears to correspond to a 32-bit hash of the
      // instruction pointer addresses that comprise the stack for the current
      // context
      // https://github.com/torvalds/linux/blob/5bfc75d92efd494db37f5c4c173d3639d4772966/kernel/bpf/stackmap.c?_pjax=%23js-repo-pjax-container%2C%20div%5Bitemtype%3D%22http%3A%2F%2Fschema.org%2FSoftwareSourceCode%22%5D%20main%2C%20%5Bdata-pjax-container%5D#L252
      // stack_id = bpf_get_prandom_u32 ();
      LOG (pid, "attempt to backtrace");
      bpf_printk ("do sample: %d\n", pid);
      backtrace (&ctx->regs, stack_id);
    }

  // get kernel stack
  key.kernel_stack_id = bpf_get_stackid (ctx, &stack_traces, 0);

  // u64 zero = 0;
  u64 *count;
  count = bpf_map_lookup_or_try_init (&counts, &key, &zero);
  if (!count)
    return 0;

  __sync_fetch_and_add (count, 1);
  return 0;
}

char LICENSE[] SEC ("license") = "GPL";
