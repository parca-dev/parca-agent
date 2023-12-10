
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
    u64 user_stack_id;
    u64 kernel_stack_id;
    u64 interpreter_stack_id;
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
    __type(key, u64);
    __type(value, stack_trace_t);
} stack_traces SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1); // Set in the user-space.
    __type(key, symbol_t);
    __type(value, u32);
} symbol_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} symbol_index_storage SEC(".maps");

const volatile int num_cpus = 200; // Hard-limit of 200 CPUs.

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
