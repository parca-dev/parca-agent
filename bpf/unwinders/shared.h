#ifndef PARCA_AGENT_SHARED_H
#define PARCA_AGENT_SHARED_H
#include "common.h"
#include "vmlinux.h"
#include "basic_types.h"
#include <bpf/bpf_helpers.h>
#include "vmlinux.h"

// This file contains shared structures, BPF maps, and other helpers
// that every unwinder uses.

// Number of items in the stack counts aggregation map.
#define MAX_STACK_COUNTS_ENTRIES 10240
// A different stack produced the same hash.
#define STACK_COLLISION(err) (err == -EEXIST)

typedef struct {
    int pid;
    int tgid;
    u64 user_stack_id;
    u64 kernel_stack_id;
    u64 interpreter_stack_id;
    u64 custom_labels_id;
} stack_count_key_t;

typedef struct {
    u64 ip;
    u64 sp;
    u64 bp;
#if __TARGET_ARCH_arm64
    u64 leaf_lr;
    u64 x28; // value of register 28, meaningful to the Go runtime
#endif
    u32 tail_calls;
    stack_trace_t stack;
    bool unwinding_jit;
    bool use_fp;

    u64 unwinder_type;
    stack_count_key_t stack_key;

    u64 vdso_pc;
    u64 vdso_sp;
} unwind_state_t;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, unwind_state_t);
} heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_STACK_COUNTS_ENTRIES);
    __type(key, stack_count_key_t);
    __type(value, u64);
} stack_counts SEC(".maps");

#define MAX_CUSTOM_LABELS_ENTRIES 1000

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CUSTOM_LABELS_ENTRIES);
    __type(key, u64);
    __type(value, custom_labels_array_t);
} custom_labels SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_STACK_COUNTS_ENTRIES);
    __type(key, u64);
    __type(value, stack_trace_t);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1);  // Set in the user-space.
    __type(key, symbol_t);
    __type(value, u32);
} symbol_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} symbol_index_storage SEC(".maps");

const volatile int num_cpus = 200;  // Hard-limit of 200 CPUs.

static inline __attribute__((__always_inline__)) u32 get_symbol_id(symbol_t *sym) {
    int *found_id = bpf_map_lookup_elem(&symbol_table, sym);
    if (found_id) {
        return *found_id;
    }

    u32 zero = 0;
    u32 *sym_idx = bpf_map_lookup_elem(&symbol_index_storage, &zero);
    if (sym_idx == NULL) {
        // Appease the verifier, this will never fail.
        return 0;
    }

    // u32 idx = __sync_fetch_and_add(sym_idx, 1);
    // The previous __sync_fetch_and_add does not seem to work in 5.4 and 5.10
    //  > libbpf: prog 'walk_ruby_stack': -- BEGIN PROG LOAD LOG --\nBPF_STX uses reserved fields
    //
    // Checking for the version does not work as these branches are not pruned
    // in older kernels, so we shard the id generation per CPU.
    u32 idx = *sym_idx * num_cpus + bpf_get_smp_processor_id();
    *sym_idx += 1;

    int err;
    err = bpf_map_update_elem(&symbol_table, sym, &idx, BPF_ANY);
    if (err) {
        return 0;
    }
    return idx;
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
        bpf_printk("[error] bpf_map_lookup_or_try_init with ret: %d", err);
        return 0;
    }

    return bpf_map_lookup_elem(map, key);
}

// To be called once we are completely done walking stacks and we are ready to
// aggregate them in the 'counts' map and end the execution of the BPF program(s).
#define aggregate_stacks()                                                                            \
    ({                                                                                                \
        u64 zero = 0;                                                                                 \
        unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);                             \
        if (unwind_state != NULL) {                                                                   \
            u64 *scount = bpf_map_lookup_or_try_init(&stack_counts, &unwind_state->stack_key, &zero); \
            if (scount) {                                                                             \
                __sync_fetch_and_add(scount, 1);                                                      \
            }                                                                                         \
        }                                                                                             \
    })

// HACK: On failure, bpf_perf_prog_read_value() zeroes the buffer. We ensure that this always
// fail with a compile time assert that ensures that the struct size is different to the size
// of the expected structure.
#define bpf_large_memzero(_d, _l)                                                                                        \
    ({                                                                                                                   \
        _Static_assert(_l != sizeof(struct bpf_perf_event_value), "stack size must be different to the valid argument"); \
        bpf_perf_prog_read_value(ctx, _d, _l);                                                                           \
    })

// Hack to thwart the verifier's detection of variable bounds.
//
// In recent kernels (6.8 and above) the verifier has gotten smarter
// in its tracking of variable bounds. For example, after an if statement like
// `if (v1 < v2)`,
// if it already had computed bounds for v2, it can infer bounds
// for v1 in each side of the branch (and vice versa). This means it can verify more
// programs successfully, which doesn't matter to us because our program was
// verified successfully before. Unfortunately it has a downside which
// _does_ matter to us: it increases the number of unique verifier states,
// which can cause the same instructions to be explored many times, especially
// in cases where a value is carried through a loop and possibly has
// multiple sets of different bounds on each iteration of the loop, leading to
// a combinatorial explosion. This causes us to blow out the kernel's budget of
// maximum number of instructions verified on program load (currently 1M).
//
// `opaquify32` is a no-op; thus `opaquify32(x, anything)` has the same value as `x`.
// However, the verifier is fortunately not smart enough to realize this,
// and will not realize the result has the same bounds as `x`, subverting the feature
// described above.
//
// For further discussion, see:
// https://lore.kernel.org/bpf/874jci5l3f.fsf@taipei.mail-host-address-is-not-set/
//
// if the verifier knows `val` is constant, you must set `seed`
// to something the verifier has no information about
// (if you don't have something handy, you can use `bpf_get_prandom_u32`).
// Otherwise, if the verifier knows bounds on `val` but not its exact value,
// it's fine to just use -1.
static __always_inline u32 opaquify32(u32 val, u32 seed) {
    // We use inline asm to make sure clang doesn't optimize it out
    asm volatile(
        "%0 ^= %1\n"
        "%0 ^= %1\n"
        : "+&r"(val)
        : "r"(seed)
    );
    return val;
}

// like opaquify32, but for u64.
static __always_inline u64 opaquify64(u64 val, u64 seed) {
    asm volatile(
        "%0 ^= %1\n"
        "%0 ^= %1\n"
        : "+&r"(val)
        : "r"(seed)
    );
    return val;
}
#endif
