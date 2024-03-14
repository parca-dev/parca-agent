
#include "common.h"

// This file contains shared structures, BPF maps, and other helpers
// that every unwinder uses.

// Number of items in the stack counts aggregation map.
#define MAX_STACK_COUNTS_ENTRIES 10240
// A different stack produced the same hash.
#define STACK_COLLISION(err) (err == -EEXIST)

// Maximum memory mappings per process.
#define MAX_MAPPINGS_PER_PROCESS 400
#define MAX_MAPPINGS_BINARY_SEARCH_DEPTH 10
_Static_assert(1 << MAX_MAPPINGS_BINARY_SEARCH_DEPTH >= MAX_MAPPINGS_PER_PROCESS, "mappings array is big enough");

// Programs.

// TODO(kakkoyun): Merge with below.
#define NATIVE_UNWINDER_PROGRAM_ID 0
#define RUBY_UNWINDER_PROGRAM_ID 1
#define PYTHON_UNWINDER_PROGRAM_ID 2
#define JAVA_UNWINDER_PROGRAM_ID 3

enum runtime_unwinder_type {
    RUNTIME_UNWINDER_TYPE_UNDEFINED = 0,  // TODO(kakkoyun): Native by default?
    RUNTIME_UNWINDER_TYPE_RUBY = 1,
    RUNTIME_UNWINDER_TYPE_PYTHON = 2,
    RUNTIME_UNWINDER_TYPE_JAVA = 3,
};

// "type" here is set in userspace in our `proc_info` map to indicate JITed and special sections,
// It is not something we get from procfs.
enum mapping_type {
    MAPPING_TYPE_NORMAL = 0,
    MAPPING_TYPE_JIT = 1,
    MAPPING_TYPE_SPECIAL = 2,
};
typedef struct {
    int pid;
    int tgid;
    u64 user_stack_id;
    u64 kernel_stack_id;
    u64 interpreter_stack_id;
    unsigned char trace_id[16];
} stack_count_key_t;

// Represents an executable mapping.
typedef struct {
    u64 load_address;
    u64 begin;
    u64 end;
    u64 executable_id;
    enum mapping_type type;
    bool has_frame_pointers;
} mapping_t;

typedef struct {
    bool has_jit_compiler;
    enum runtime_unwinder_type runtime_unwinder;
    u64 len;
    // Executable mappings for a process.
    mapping_t mappings[MAX_MAPPINGS_PER_PROCESS];
} process_info_t;

typedef struct {
    pid_t per_process_id;
    pid_t per_thread_id;
    process_info_t *proc_info;

    u64 ip;
    u64 sp;
    u64 bp;

    bool reached_bottom_of_stack;
    u32 tail_calls;

    stack_trace_t stack;
    stack_count_key_t stack_key;

    // TODO(kakkoyun): Current? Previous? Next? Unwinders.
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
