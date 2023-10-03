
#include "common.h"

// This file contains shared structures, BPF maps, and other helpers
// that every unwinder uses.

// Number of items in the stack counts aggregation map.
#define MAX_STACK_COUNTS_ENTRIES 10240
// A different stack produced the same hash.
#define STACK_COLLISION(err) (err == -EEXIST)

typedef struct {
    int pid;
    int tgid;
    int user_stack_id;
    int kernel_stack_id;
    int user_stack_id_dwarf_id;
    int interpreter_stack_id;
} stack_count_key_t;

typedef struct {
    u64 ip;
    u64 sp;
    u64 bp;
    u32 tail_calls;
    stack_trace_t stack;
    bool unwinding_jit; // set to true during JITed unwinding; false unless mixed-mode unwinding is enabled

    u64 interpreter_type;
    stack_count_key_t stack_key;
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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_STACK_COUNTS_ENTRIES);
    __type(key, int);
    __type(value, stack_trace_t);
} interpreter_stack_traces SEC(".maps"); // TODO think about this.

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1); // Set in the user-space.
    __type(key, symbol_t);
    __type(value, u32);
} symbol_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} symbol_index_storage SEC(".maps");

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
#define aggregate_stacks()                                                                                                                                     \
    ({                                                                                                                                                         \
        u64 zero = 0;                                                                                                                                          \
        unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);                                                                                      \
        if (unwind_state != NULL) {                                                                                                                            \
            u64 *scount = bpf_map_lookup_or_try_init(&stack_counts, &unwind_state->stack_key, &zero);                                                          \
            if (scount) {                                                                                                                                      \
                __sync_fetch_and_add(scount, 1);                                                                                                               \
            }                                                                                                                                                  \
        }                                                                                                                                                      \
    })
