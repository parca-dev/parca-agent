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
#include "shared.h"

/*================================ CONSTANTS =================================*/

#if __TARGET_ARCH_x86
// Number of frames to walk per tail call iteration.
#define MAX_STACK_DEPTH_PER_PROGRAM 7
// Number of BPF tail calls that will be attempted.
#define MAX_TAIL_CALLS 19
#endif

#if __TARGET_ARCH_arm64
// Number of frames to walk per tail call iteration.
#define MAX_STACK_DEPTH_PER_PROGRAM 5
// Number of BPF tail calls that will be attempted.
#define MAX_TAIL_CALLS 26
#endif

// Maximum number of frames.
_Static_assert(MAX_TAIL_CALLS *MAX_STACK_DEPTH_PER_PROGRAM >= MAX_STACK_DEPTH, "enough iterations to traverse the whole stack");
// Number of unique stacks.
#define MAX_STACK_TRACES_ENTRIES 64000
// Maximum number of processes we are willing to track.
#define MAX_PROCESSES 5000
// Binary search iterations for dwarf based stack walking.
// 2^19 can bisect ~524_288 entries.
#define MAX_UNWIND_INFO_BINARY_SEARCH_DEPTH 19
// Size of the unwind table.
// 250k * sizeof(stack_unwind_row_t) = 2MB
#define MAX_UNWIND_TABLE_SIZE 250 * 1000
_Static_assert(1 << MAX_UNWIND_INFO_BINARY_SEARCH_DEPTH >= MAX_UNWIND_TABLE_SIZE, "unwind table is big enough");

// Unwind tables bigger than can't fit in the remaining space
// of the current shard are broken up into chunks up to `MAX_UNWIND_TABLE_SIZE`.
#define MAX_UNWIND_TABLE_CHUNKS 30
// Maximum memory mappings per process.
#define MAX_MAPPINGS_PER_PROCESS 2000
#define MAX_MAPPINGS_BINARY_SEARCH_DEPTH 12
_Static_assert(1 << MAX_MAPPINGS_BINARY_SEARCH_DEPTH >= MAX_MAPPINGS_PER_PROCESS, "mappings array is big enough");

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
#define BINARY_SEARCH_DEFAULT 0xFABADAFABADAULL
#define BINARY_SEARCH_SHOULD_NEVER_HAPPEN 0xDEADBEEFDEADBEEFULL
#define BINARY_SEARCH_EXHAUSTED_ITERATIONS 0xBADFADBADFADBADULL

#define BINARY_SEARCH_NOT_FOUND(var) (var == BINARY_SEARCH_DEFAULT)
#define BINARY_SEARCH_FAILED(var) (var == BINARY_SEARCH_SHOULD_NEVER_HAPPEN || var == BINARY_SEARCH_EXHAUSTED_ITERATIONS)

#define REQUEST_UNWIND_INFORMATION 0
#define REQUEST_PROCESS_MAPPINGS 1
#define REQUEST_REFRESH_PROCINFO 2
#define REQUEST_READ 3

#define ENABLE_STATS_PRINTING false

enum runtime_unwinder_type {
    RUNTIME_UNWINDER_TYPE_UNDEFINED = 0,
    RUNTIME_UNWINDER_TYPE_RUBY = 1,
    RUNTIME_UNWINDER_TYPE_PYTHON = 2,
    RUNTIME_UNWINDER_TYPE_JAVA = 3,
    RUNTIME_UNWINDER_TYPE_GO = 4,
};

enum find_unwind_table_return {
    FIND_UNWIND_SUCCESS = 1,

    FIND_UNWIND_MAPPING_SHOULD_NEVER_HAPPEN = 2,
    FIND_UNWIND_MAPPING_EXHAUSTED_SEARCH = 3,
    FIND_UNWIND_MAPPING_NOT_FOUND = 4,
    // This means we didn't have unwind tables for the mapping.
    FIND_UNWIND_CHUNK_NOT_FOUND = 5,
    // This means we have unwind tables for the mapping but the PC wasn't covered by them.
    FIND_UNWIND_CHUNK_NOT_FOUND_FOR_PC = 6,

    FIND_UNWIND_JITTED = 100,
    FIND_UNWIND_SPECIAL = 200,
};

struct unwinder_config_t {
    bool filter_processes;
    bool verbose_logging;
    bool mixed_stack_enabled;
    bool python_enabled;
    bool ruby_enabled;
    bool java_enabled;
    bool collect_custom_labels;
    /* 1 byte of padding */
    bool _padding;
    u32 rate_limit_unwind_info;
    u32 rate_limit_process_mappings;
    u32 rate_limit_refresh_process_info;
    u32 rate_limit_reads;
};

struct unwinder_stats_t {
    u64 total_entries;
    u64 total_runs;
    u64 total_samples;
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
    u64 error_jit_mixed_mode_disabled;  // JIT error because mixed-mode unwinding is disabled
    u64 success_jit_frame;
    u64 success_jit_to_dwarf;
    u64 success_dwarf_to_jit;
    u64 success_dwarf_reach_bottom;
    u64 success_jit_reach_bottom;
    u64 success_dwarf_missing_pc_bottom;

    u64 event_request_unwind_information;
    u64 event_request_process_mappings;
    u64 event_request_refresh_process_info;
    u64 event_request_read;

    u64 total_zero_pids;
    u64 total_kthreads;
    u64 total_filter_misses;
};

const volatile struct unwinder_config_t unwinder_config = {};

/*============================== MACROS =====================================*/

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries) \
    struct {                                                        \
        __uint(type, _type);                                        \
        __uint(max_entries, _max_entries);                          \
        __type(key, _key_type);                                     \
        __type(value, _value_type);                                 \
    } _name SEC(".maps");

#define BPF_HASH(_name, _key_type, _value_type, _max_entries) BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries);

#define LOG(fmt, ...)                                  \
    ({                                                 \
        if (unwinder_config.verbose_logging) {         \
            bpf_printk("native: " fmt, ##__VA_ARGS__); \
        }                                              \
    })

#include "go_runtime.h"

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
    u64 should_use_fp_by_default;
    u64 is_jit_compiler;
    u64 unwinder_type;
    u64 len;
    mapping_t mappings[MAX_MAPPINGS_PER_PROCESS];
} process_info_t;

// A row in the stack unwinding table for Arm64.
typedef struct __attribute__((packed)) {
    u64 pc;
#if __TARGET_ARCH_arm64
    s16 lr_offset;
#endif
    u8 cfa_type;
    u8 rbp_type;
    s16 cfa_offset;
    s16 rbp_offset;
} stack_unwind_row_t;
#if __TARGET_ARCH_arm64
_Static_assert(sizeof(stack_unwind_row_t) == 16, "unwind row has the expected size");
#endif
#if __TARGET_ARCH_x86
_Static_assert(sizeof(stack_unwind_row_t) == 14, "unwind row has the expected size");
#endif

// Unwinding table representation.
typedef struct {
    stack_unwind_row_t rows[MAX_UNWIND_TABLE_SIZE];
} stack_unwind_table_t;

#define RUNTIME_INFO_TAG_GO 0

typedef struct {
    union {
        struct go_runtime_offsets go;
    } inner;
    u8 tag;
} runtime_info_t;

typedef struct {
    u32 pc_not_covered;
    u32 no_unwind_info;
    u32 missed_filter;
    u32 mapping_not_found;
    u32 chunk_not_found;
    u32 null_unwind_table;
    u32 table_not_found;
    u32 rbp_failed;
    u32 ra_failed;
    u32 unsupported_fp_action;
    u32 unsupported_cfa;
    u32 previous_rsp_zero;
    u32 previous_rip_zero;
    u32 previous_rbp_zero;
    u32 internal_error;
} unwind_failed_reasons_t;

/*================================ MAPS =====================================*/

BPF_HASH(debug_threads_ids, int, u8, 1);  // Table size will be updated in userspace.
BPF_HASH(process_info, int, process_info_t, MAX_PROCESSES);

BPF_HASH(unwind_info_chunks, u64, unwind_info_chunks_t,
         5 * 1000);  // Mapping of executable ID to unwind info chunks.
BPF_HASH(unwind_tables, u64, stack_unwind_table_t,
         5);  // Table size will be updated in userspace.

BPF_HASH(pid_to_runtime_info, int, runtime_info_t, MAX_PROCESSES);

typedef struct {
    u8 type;
    int pid;
} pid_event_t;
_Static_assert(sizeof(pid_event_t) == 8, "event payload expected to be 64 bits");

BPF_HASH(events_count, pid_event_t, u32, MAX_PROCESSES);

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct unwinder_stats_t);
} percpu_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 4);
    __type(key, u32);
    __type(value, u32);
} programs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 8192);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(custom_labels_array_t));
    __uint(max_entries, 1);
} custom_labels_storage_map SEC(".maps");

BPF_HASH(unwind_failed_reasons, pid_t, unwind_failed_reasons_t, MAX_PROCESSES)

#define BUMP_UNWIND_FAILED_COUNT(_pid, _reason)                                                                      \
    ({                                                                                                               \
        pid_t pid = _pid;                                                                                            \
        unwind_failed_reasons_t zero = {0};                                                                          \
        unwind_failed_reasons_t *p_failed_reasons = bpf_map_lookup_or_try_init(&unwind_failed_reasons, &pid, &zero); \
        if (p_failed_reasons) {                                                                                      \
            __sync_fetch_and_add(&p_failed_reasons->_reason, 1);                                                     \
        }                                                                                                            \
    })

/*=========================== HELPER FUNCTIONS ==============================*/

#define DEFINE_COUNTER(__func__name)                                                         \
    static void bump_unwind_##__func__name() {                                               \
        u32 zero = 0;                                                                        \
        struct unwinder_stats_t *unwinder_stats = bpf_map_lookup_elem(&percpu_stats, &zero); \
        if (unwinder_stats != NULL) {                                                        \
            unwinder_stats->__func__name++;                                                  \
        }                                                                                    \
    }

DEFINE_COUNTER(total_entries);
DEFINE_COUNTER(total_runs);
DEFINE_COUNTER(total_samples);
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
// DEFINE_COUNTER(success_jit_reach_bottom);
DEFINE_COUNTER(success_dwarf_missing_pc_bottom);

DEFINE_COUNTER(event_request_unwind_information);
DEFINE_COUNTER(event_request_process_mappings);
DEFINE_COUNTER(event_request_refresh_process_info);
DEFINE_COUNTER(event_request_read)

DEFINE_COUNTER(total_zero_pids);
DEFINE_COUNTER(total_kthreads);
DEFINE_COUNTER(total_filter_misses);

// For ERROR_SAMPLE.
static const int BPF_PROGRAM = NATIVE_UNWINDER_PROGRAM_ID;

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
    bpf_printk("\treached_bottom_dwarf_missing_pc_bottom=%lu", unwinder_stats->success_dwarf_missing_pc_bottom);
    bpf_printk("\ttotal_entries_counter=%lu", unwinder_stats->total_entries);
    bpf_printk("\ttotal_runs_counter=%lu", unwinder_stats->total_runs);
    bpf_printk("\ttotal_samples_counter=%lu", unwinder_stats->total_samples);
    bpf_printk("\t(not_covered=%lu)", unwinder_stats->error_pc_not_covered);
    bpf_printk("\t(not_covered_jit=%lu)", unwinder_stats->error_pc_not_covered_jit);
    bpf_printk("\t(total_zero_pids=%lu)", unwinder_stats->total_zero_pids);
    bpf_printk("\t(total_kthreads=%lu)", unwinder_stats->total_kthreads);
    bpf_printk("\t(total_filter_misses=%lu)", unwinder_stats->total_filter_misses);

    bpf_printk("");
}

static void bump_samples() {
    u32 zero = 0;
    struct unwinder_stats_t *unwinder_stats = bpf_map_lookup_elem(&percpu_stats, &zero);
    if (unwinder_stats == NULL) {
        return;
    }
    if (ENABLE_STATS_PRINTING && unwinder_stats->total_samples % 50 == 0) {
        unwind_print_stats();
    }
    bump_unwind_total_samples();
}

/*================================= EVENTS ==================================*/

static __always_inline bool event_rate_limited(pid_event_t event_id, int rate) {
    u32 zero = 0;
    u32 *val = bpf_map_lookup_or_try_init(&events_count, &event_id, &zero);
    if (val) {
        if (*val >= rate) {
            return true;
        }
        __sync_fetch_and_add(val, 1);
    }

    // Even if we got here because the map is full, let's not rate-limit this event.
    return false;
}

static __always_inline void request_unwind_information(struct bpf_perf_event_data *ctx, int user_pid) {
    char comm[20];
    bpf_get_current_comm(comm, 20);
    LOG("[debug] requesting unwind info for PID: %d, comm: %s ctx IP: %llx", user_pid, comm, PT_REGS_IP(&ctx->regs));

    pid_event_t payload = {REQUEST_UNWIND_INFORMATION, user_pid};
    if (event_rate_limited(payload, unwinder_config.rate_limit_unwind_info)) {
        return;
    }

    bump_unwind_event_request_unwind_information();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &payload, sizeof(u64));
}

static __always_inline void request_process_mappings(struct bpf_perf_event_data *ctx, int user_pid) {
    pid_event_t payload = {REQUEST_PROCESS_MAPPINGS, user_pid};
    if (event_rate_limited(payload, unwinder_config.rate_limit_process_mappings)) {
        return;
    }
    bump_unwind_event_request_process_mappings();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &payload, sizeof(u64));
}

static __always_inline void request_refresh_process_info(struct bpf_perf_event_data *ctx, int user_pid) {
    pid_event_t payload = {REQUEST_REFRESH_PROCINFO, user_pid};
    if (event_rate_limited(payload, unwinder_config.rate_limit_process_mappings)) {
        return;
    }
    bump_unwind_event_request_refresh_process_info();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &payload, sizeof(u64));
}

static __always_inline void request_read(struct bpf_perf_event_data *ctx, int user_pid, u64 addr) {
    typedef struct {
        u8 type;
        u32 pid;
        u64 addr;
    } payload_t;
    _Static_assert(sizeof(payload_t) == 16, "request_read_addr payload expected to be 128 bits");
    // `event_rate_limited` can fail open in case the map is already full.
    // We want to have `rate_limit_reads == 0` act as a kill switch where we can be sure
    // to NEVER try to read process memory from the agent, so let's just bail early in that case.
    if (!unwinder_config.rate_limit_reads) {
        return;
    }
    payload_t payload = {REQUEST_READ, user_pid, addr};
    pid_event_t payload_for_rate_limiting = {REQUEST_READ, user_pid};
    if (event_rate_limited(payload_for_rate_limiting, unwinder_config.rate_limit_reads)) {
        return;
    }
    bump_unwind_event_request_read();
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &payload, sizeof(payload));
}

// Binary search the executable mappings to find the one that covers a given pc.
static u64 find_mapping(process_info_t *proc_info, u64 pc) {
    u64 left = 0;
    u64 right = proc_info->len;
    u64 found = BINARY_SEARCH_DEFAULT;

    // Find the mapping.
    for (int i = 0; i < MAX_MAPPINGS_BINARY_SEARCH_DEPTH; i++) {
        u32 mid = (left + right) / 2;
        if (left >= right) {
            return found;
        }

        mid = opaquify32(mid, -1);
        left = opaquify64(left, -1);
        right = opaquify64(right, -1);
        if (mid < 0 || mid >= MAX_MAPPINGS_PER_PROCESS) {
            LOG("\t.should never happen");
            return BINARY_SEARCH_SHOULD_NEVER_HAPPEN;
        }

        if (proc_info->mappings[mid].begin <= pc) {
            found = mid;
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return BINARY_SEARCH_EXHAUSTED_ITERATIONS;
}

// Binary search the unwind table to find the row index containing the unwind
// information for a given program counter (pc).
static u64 find_offset_for_pc(stack_unwind_table_t *table, u64 pc, u64 left, u64 right) {
    u64 found = BINARY_SEARCH_DEFAULT;

    for (int i = 0; i < MAX_UNWIND_INFO_BINARY_SEARCH_DEPTH; i++) {
        // TODO(javierhonduco): ensure that this condition is right as we use
        // unsigned values...
        if (left >= right) {
            LOG("\t.done");
            return found;
        }

        u32 mid = (left + right) / 2;

        mid = opaquify32(mid, -1);
        left = opaquify32(left, -1);
        right = opaquify32(right, -1);
        // Appease the verifier.
        if (mid < 0 || mid >= MAX_UNWIND_TABLE_SIZE) {
            LOG("\t.should never happen, mid: %lu, max: %lu", mid, MAX_UNWIND_TABLE_SIZE);
            bump_unwind_error_should_never_happen();
            return BINARY_SEARCH_SHOULD_NEVER_HAPPEN;
        }

        // Debug logs.
        // LOG("\t-> fetched PC %llx, target PC %llx (iteration %d/%d, mid: %d, left:%d, right:%d)", table->rows[mid].pc, pc, i,
        // MAX_UNWIND_INFO_BINARY_SEARCH_DEPTH, mid, left, right);
        if (table->rows[mid].pc <= pc) {
            found = mid;
            left = mid + 1;
        } else {
            right = mid;
        }

        // Debug logs.
        // LOG("\t<- fetched PC %llx, target PC %llx (iteration %d/%d, mid:
        // --, left:%d, right:%d)", ctx->table->rows[mid].pc, ctx->pc, index,
        // MAX_UNWIND_INFO_BINARY_SEARCH_DEPTH, ctx->left, ctx->right);
    }
    return BINARY_SEARCH_EXHAUSTED_ITERATIONS;
}

// Finds whether a process should be unwound using the unwind
// tables.
static __always_inline bool has_unwind_information(pid_t per_process_id) {
    process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &per_process_id);
    if (proc_info) {
        return true;
    }
    return false;
}

static __always_inline bool is_debug_enabled_for_thread(int per_thread_id) {
    void *val = bpf_map_lookup_elem(&debug_threads_ids, &per_thread_id);
    if (val) {
        return true;
    }
    return false;
}

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

    u64 executable_id = 0;
    u64 load_address = 0;
    u64 type = 0;

    u64 index = find_mapping(proc_info, pc);

    barrier_var(index);  // necessary for verification on some kernel versions
    if (index == BINARY_SEARCH_DEFAULT) {
        return FIND_UNWIND_MAPPING_NOT_FOUND;
    }
    if (index < 0 || index >= MAX_MAPPINGS_PER_PROCESS) {
        return -1;
    }

    bool found = proc_info->mappings[index].begin <= pc && pc <= proc_info->mappings[index].end;
    if (!found) {
        LOG("[warn] :((( no mapping for ip=%llx", pc);
        return FIND_UNWIND_MAPPING_NOT_FOUND;
    }

    // "type" here is set in userspace in our `proc_info` map to indicate JITed and special sections,
    // It is not something we get from procfs.
    executable_id = proc_info->mappings[index].executable_id;
    load_address = proc_info->mappings[index].load_address;
    type = proc_info->mappings[index].type;
    if (offset != NULL) {
        *offset = load_address;
    }

    if (type == 1) {
        return FIND_UNWIND_JITTED;
    }
    if (type == 2) {
        return FIND_UNWIND_SPECIAL;
    }

    LOG("~about to check shards found=%d", found);

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

    LOG("[error] could not find chunk for adjusted ip=0x%llx", adjusted_pc);
    return FIND_UNWIND_CHUNK_NOT_FOUND_FOR_PC;
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
#if __TARGET_ARCH_arm64
static __always_inline bool retrieve_task_registers(u64 *ip, u64 *sp, u64 *bp, u64 *lr, u64 *x28) {
    if (ip == NULL || sp == NULL || bp == NULL || lr == NULL) {
        return false;
    }
#elif __TARGET_ARCH_x86
static __always_inline bool retrieve_task_registers(u64 *ip, u64 *sp, u64 *bp) {
    if (ip == NULL || sp == NULL || bp == NULL) {
        return false;
    }
#else
#error "Unsupported platform"
#endif

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
#if __TARGET_ARCH_arm64
    *lr = PT_REGS_RET_CORE(regs);
    *x28 = BPF_CORE_READ(__PT_REGS_CAST(regs), regs[28]);
#endif

    return true;
}

static __always_inline void unwind_using_kernel_provided_unwinder(struct bpf_perf_event_data *ctx, unwind_state_t *unwind_state, int user_or_kernel) {
    long ret = bpf_get_stack(ctx, unwind_state->stack.addresses, MAX_STACK_DEPTH * sizeof(u64), user_or_kernel);
    if (ret < 0) {
        LOG("[error] bpf_get_stack (%d) failed: %d", ret, user_or_kernel);
        return;
    }
    unwind_state->stack.len = ret / sizeof(u64);
    unwind_state->stack.truncated = false;
}

static __always_inline void unwind_kernel_stack(struct bpf_perf_event_data *ctx, unwind_state_t *unwind_state) {
    unwind_using_kernel_provided_unwinder(ctx, unwind_state, 0);
}

// Aggregate the given stacktrace.
static __always_inline void add_stack(struct bpf_perf_event_data *ctx, u64 pid_tgid, unwind_state_t *unwind_state) {
    stack_count_key_t *stack_key = &unwind_state->stack_key;

    int per_process_id = pid_tgid >> 32;
    int per_thread_id = pid_tgid;

    stack_key->pid = per_process_id;
    stack_key->tgid = per_thread_id;
    stack_key->custom_labels_id = 0;

    if (unwinder_config.collect_custom_labels) {
        runtime_info_t *runtime_info = bpf_map_lookup_elem(&pid_to_runtime_info, &per_process_id);
        if (runtime_info && runtime_info->tag == RUNTIME_INFO_TAG_GO) {
            u32 map_id = 0;
            custom_labels_array_t *lbls = bpf_map_lookup_elem(&custom_labels_storage_map, &map_id);
            if (lbls) {
                int success = get_custom_labels(ctx, unwind_state, &runtime_info->inner.go, lbls);
                if (success) {
                    LOG("[info] got %d custom labels", lbls->len);
                    u64 hash;
                    success = hash_custom_labels(lbls, 0, &hash);
                    if (success) {
                        int err = bpf_map_update_elem(&custom_labels, &hash, lbls, BPF_ANY);
                        if (err)
                            LOG("[error] failed to update custom labels with %d", err);
                        else
                            stack_key->custom_labels_id = hash;
                    } else
                        LOG("[error] failed to compute hash for custom labels");
                } else {
                    LOG("[error] failed to get custom labels");
                }
            }
        }
    }

    // Hash and add user stack.
    u64 user_stack_id = hash_stack(&unwind_state->stack, 0);
    stack_key->user_stack_id = user_stack_id;

    int err = bpf_map_update_elem(&stack_traces, &user_stack_id, &unwind_state->stack, BPF_ANY);
    if (err != 0) {
        LOG("[error] failed to update user stack with %d", err);
    }

    // Hash and add kernel stack.
    unwind_kernel_stack(ctx, unwind_state);

    u64 kernel_stack_id = hash_stack(&unwind_state->stack, 0);
    stack_key->kernel_stack_id = kernel_stack_id;
    err = bpf_map_update_elem(&stack_traces, &kernel_stack_id, &unwind_state->stack, BPF_ANY);
    if (err != 0) {
        LOG("[error] failed to update kernel stack with %d", err);
    }

    request_process_mappings(ctx, per_process_id);

    // Continue unwinding runtimes, if any.
    switch (unwind_state->unwinder_type) {
        case RUNTIME_UNWINDER_TYPE_UNDEFINED:
        case RUNTIME_UNWINDER_TYPE_GO:
            // Most programs aren't "runtimes", this can be rather verbose.
            // LOG("[debug] per_process_id: %d not a runtime", per_process_id);
            aggregate_stacks();
            break;
        case RUNTIME_UNWINDER_TYPE_RUBY:
            if (!unwinder_config.ruby_enabled) {
                LOG("[debug] Ruby unwinder (rbperf) is disabled");
                aggregate_stacks();
                break;
            }
            LOG("[debug] tail-call to Ruby unwinder (rbperf)");
            bpf_tail_call(ctx, &programs, RUBY_UNWINDER_PROGRAM_ID);
            break;
        case RUNTIME_UNWINDER_TYPE_PYTHON:
            if (!unwinder_config.python_enabled) {
                LOG("[debug] Python unwinder (pyperf) is disabled");
                aggregate_stacks();
                break;
            }
            LOG("[debug] tail-call to Python unwinder (pyperf)");
            bpf_tail_call(ctx, &programs, PYTHON_UNWINDER_PROGRAM_ID);
            break;
        case RUNTIME_UNWINDER_TYPE_JAVA:
            if (!unwinder_config.java_enabled) {
                LOG("[debug] Java unwinder (jvm) is disabled");
                aggregate_stacks();
                break;
            }
            LOG("[debug] tail-call to Java unwinder (jvm)");
            bpf_tail_call(ctx, &programs, JAVA_UNWINDER_PROGRAM_ID);
            break;
        default:
            LOG("[error] bad runtime unwinder type value: %d", unwind_state->unwinder_type);
            break;
    }
}

static __always_inline void add_frame(unwind_state_t *unwind_state, u64 frame) {
    u64 len = unwind_state->stack.len;
    if (len >= 0 && len < MAX_STACK_DEPTH) {
        unwind_state->stack.addresses[len] = frame;
        unwind_state->stack.len++;
    }
}

static __always_inline u64 canonicalize_addr(u64 addr) {
#if __TARGET_ARCH_arm64
    // aarch64 has a 48-bit address space; one bit (in position 56)
    // indicates whether it points into kernel or user space.
    // the remaining 15 bits of pointers can be used for
    // various other purposes. Before reading from an address, it needs
    // to be canonicalized by setting the higher-order bits to 1 or 0
    // for kernel and user space, respectively.
    return (addr & (1ull << 55)) ? (addr | 0xFFFF000000000000) : (addr & 0x0000FFFFFFFFFFFF);
#else
    return addr;
#endif
}

SEC("perf_event")
int native_unwind(struct bpf_perf_event_data *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int per_process_id = pid_tgid >> 32;

    int err = 0;
    bool reached_bottom_of_stack = false;
    u32 zero = 0;

    bool dwarf_to_jit = false;

    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state == NULL) {
        LOG("unwind_state is NULL, should not happen");
        return 1;
    }

    process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &per_process_id);
    if (proc_info == NULL) {
        LOG("[error] should never happen");
        return 1;
    }

    for (int i = 0; i < MAX_STACK_DEPTH_PER_PROGRAM; i++) {
        LOG("## frame: %d", unwind_state->stack.len);

        LOG("\tcurrent pc: %llx", unwind_state->ip);
        LOG("\tcurrent sp: %llx", unwind_state->sp);
        LOG("\tcurrent bp: %llx", unwind_state->bp);

        u64 offset = 0;

        chunk_info_t *chunk_info = NULL;
        enum find_unwind_table_return unwind_table_result = find_unwind_table(&chunk_info, per_process_id, unwind_state->ip, &offset);

        if (unwind_table_result == FIND_UNWIND_JITTED) {
            LOG("[debug] Unwinding JITed stacks");

            unwind_state->unwinding_jit = true;
            if (dwarf_to_jit) {
                dwarf_to_jit = false;
                bump_unwind_success_dwarf_to_jit();
            }

            bump_unwind_success_jit_frame();
            unwind_state->use_fp = true;
            goto unwind_with_frame_pointers;

        } else if (unwind_table_result == FIND_UNWIND_SPECIAL) {
            LOG("vDSO mapping, trying with frame pointers");
            runtime_info_t *runtime_info = bpf_map_lookup_elem(&pid_to_runtime_info, &per_process_id);
            if (runtime_info && runtime_info->tag == RUNTIME_INFO_TAG_GO) {
                u64 sp = 0;
                u64 pc = 0;
                bool success = get_go_vdso_state(ctx, unwind_state, &runtime_info->inner.go, &sp, &pc);
                if (!success) {
                    LOG("[error] failed to read Go vdso state");
                } else if (sp && pc) {
                    LOG("[info] got vdso state: sp=0x%lx, pc=0x%lx", sp, pc);
                    unwind_state->vdso_sp = sp;
                    unwind_state->vdso_pc = pc;
                }
            }
            unwind_state->use_fp = true;
            goto unwind_with_frame_pointers;
        } else if (unwind_table_result == FIND_UNWIND_MAPPING_NOT_FOUND) {
            LOG("[warn] mapping not found");
            request_refresh_process_info(ctx, per_process_id);
            BUMP_UNWIND_FAILED_COUNT(per_process_id, mapping_not_found);
            ERROR_SAMPLE(unwind_state, "mapping not found");
            return 1;
        } else if (unwind_table_result == FIND_UNWIND_CHUNK_NOT_FOUND || unwind_table_result == FIND_UNWIND_CHUNK_NOT_FOUND_FOR_PC) {
            if (proc_info->should_use_fp_by_default) {
                LOG("[info] chunk not found, trying with frame pointers");
                unwind_state->use_fp = true;
                goto unwind_with_frame_pointers;
            }
            // If dwarf is our only option and we have dwarf info but this PC isn't covered.
            // we've reached the bottom of the stack. This covers cases like __start and
            // functions above main not having symbols.
            if (unwind_table_result == FIND_UNWIND_CHUNK_NOT_FOUND_FOR_PC) {
                unwind_state->bp = 0;
                reached_bottom_of_stack = true;
                bump_unwind_success_dwarf_missing_pc_bottom();
                break;
            }
            LOG("[info] chunk not found but fp unwinding not allowed");
            BUMP_UNWIND_FAILED_COUNT(per_process_id, chunk_not_found);
            ERROR_SAMPLE(unwind_state, "chunk not found");
            return 1;
        } else if (chunk_info == NULL) {
            LOG("[debug] chunks is null");
            reached_bottom_of_stack = true;
            break;
        }

        stack_unwind_table_t *unwind_table = bpf_map_lookup_elem(&unwind_tables, &chunk_info->shard_index);
        if (unwind_table == NULL) {
            LOG("unwind table is null :( for shard %llu", chunk_info->shard_index);
            BUMP_UNWIND_FAILED_COUNT(per_process_id, null_unwind_table);
            ERROR_SAMPLE(unwind_state, "unwind table null");
            return 0;
        }

        LOG("le offset: %llx", offset);
        u64 left = chunk_info->low_index;
        u64 right = chunk_info->high_index;
        LOG("========== left %llu right %llu", left, right);

        u64 table_idx = find_offset_for_pc(unwind_table, unwind_state->ip - offset, left, right);

        if (BINARY_SEARCH_NOT_FOUND(table_idx) || BINARY_SEARCH_FAILED(table_idx)) {
            LOG("[error] binary search failed with %llx", table_idx);
            BUMP_UNWIND_FAILED_COUNT(per_process_id, table_not_found);
            return 1;
        }

        LOG("\t=> table_index: %d", table_idx);
        LOG("\t=> adjusted pc: %llx", unwind_state->ip - offset);

        // Appease the verifier.
        if (table_idx < 0 || table_idx >= MAX_UNWIND_TABLE_SIZE) {
            LOG("\t[error] this should never happen table_idx");
            bump_unwind_error_should_never_happen();
            BUMP_UNWIND_FAILED_COUNT(per_process_id, internal_error);
            return 1;
        }

// lr offset is only fetched from userspace and used as a field in unwind table for Arm64
#if __TARGET_ARCH_arm64
        s16 found_lr_offset = unwind_table->rows[table_idx].lr_offset;
#endif
        u64 found_pc = unwind_table->rows[table_idx].pc;
        u8 found_cfa_type = unwind_table->rows[table_idx].cfa_type;
        u8 found_rbp_type = unwind_table->rows[table_idx].rbp_type;
        s16 found_cfa_offset = unwind_table->rows[table_idx].cfa_offset;
        s16 found_rbp_offset = unwind_table->rows[table_idx].rbp_offset;
        LOG("\tcfa type: %d, offset: %d (row pc: %llx)", found_cfa_type, found_cfa_offset, found_pc);
        LOG("\trbp type: %d, offset: %d", found_rbp_type, found_rbp_offset);
#if __TARGET_ARCH_arm64
        LOG(" lr offset:%d", found_lr_offset);
#endif

        if (found_cfa_type == CFA_TYPE_END_OF_FDE_MARKER) {
            // If we are past the marker, this means that we don't have unwind info.
            if (unwind_state->ip - offset > found_pc && proc_info->should_use_fp_by_default) {
                LOG("[info]  no unwind info for PC %llx, using frame pointers", unwind_state->ip);
                unwind_state->use_fp = true;
                goto unwind_with_frame_pointers;
            }

            LOG("[info] PC %llx not contained in the unwind info, found marker", unwind_state->ip);
            unwind_state->bp = 0;
            reached_bottom_of_stack = true;
            bump_unwind_success_dwarf_reach_bottom();  // assuming we only have unwind tables for DWARF frames, not FP or JIT frames
            break;
        }

    unwind_with_frame_pointers:
        if (unwind_state->use_fp) {
            unwind_state->use_fp = false;
            LOG("[debug] using FP");

            u64 next_fp = 0;
            u64 ra = 0;

            err = bpf_probe_read_user(&next_fp, 8, (void *)unwind_state->bp);
            if (err < 0) {
                if (unwind_state->bp == 0) {
                    LOG("[debug] fp unwinding found end condition");
                    reached_bottom_of_stack = true;
                    break;
                }
                LOG("[error] rbp failed with err = %d, previous rbp %d", err, unwind_state->bp);
                BUMP_UNWIND_FAILED_COUNT(per_process_id, rbp_failed);
                ERROR_SAMPLE(unwind_state, "fp unwinding failed");
                return 0;
            }

            err = bpf_probe_read_user(&ra, 8, (void *)unwind_state->bp + 8);
            ra = canonicalize_addr(ra);

            if (err < 0) {
                LOG("[error] ra failed with err = %d", err);
                BUMP_UNWIND_FAILED_COUNT(per_process_id, ra_failed);
                return 0;
            }

            u64 previous_rsp = unwind_state->bp + 16;
            if (unwind_state->vdso_sp && unwind_state->vdso_pc) {
                ra = unwind_state->vdso_pc;
                previous_rsp = unwind_state->vdso_sp;
                unwind_state->vdso_sp = 0;
                unwind_state->vdso_pc = 0;
            }

            u64 previous_rip = ra - 1;
            u64 previous_rbp = next_fp;

            add_frame(unwind_state, previous_rip);

            LOG("\tprevious ip: %llx, %llx (computed)", ra, previous_rip);
            LOG("\tprevious sp: %llx", previous_rsp);
            LOG("\tprevious bp: %llx", previous_rbp);

            unwind_state->ip = previous_rip;
            unwind_state->sp = previous_rsp;
            unwind_state->bp = previous_rbp;

            continue;
        }

        if (found_rbp_type == RBP_TYPE_UNDEFINED_RETURN_ADDRESS) {
            LOG("[info] dwarf null return address, end of stack", unwind_state->ip);
            unwind_state->bp = 0;
            reached_bottom_of_stack = true;
            bump_unwind_success_dwarf_reach_bottom();
            break;
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
            BUMP_UNWIND_FAILED_COUNT(per_process_id, unsupported_fp_action);
            ERROR_SAMPLE(unwind_state, "unsupported fp action");
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
                BUMP_UNWIND_FAILED_COUNT(per_process_id, unsupported_cfa);
                ERROR_SAMPLE(unwind_state, "unsupported cfa");
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
                BUMP_UNWIND_FAILED_COUNT(per_process_id, internal_error);
                ERROR_SAMPLE(unwind_state, "threshold 0");
                return 1;
            }
            previous_rsp = unwind_state->sp + 8 + ((((unwind_state->ip & 15) >= threshold)) << 3);

        } else {
            LOG("\t[unsup] register %d not valid (expected $rbp or $rsp)", found_cfa_type);
            bump_unwind_error_unsupported_cfa_register();
            BUMP_UNWIND_FAILED_COUNT(per_process_id, unsupported_cfa);
            ERROR_SAMPLE(unwind_state, "unsupported cfa reg");
            return 1;
        }

        // TODO(javierhonduco): A possible check could be to see whether this value
        // is within the stack. This check could be quite brittle though, so if we
        // add it, it would be best to add it only during development.
        if (previous_rsp == 0) {
            LOG("[error] previous_rsp should not be zero.");
            bump_unwind_error_catchall();
            BUMP_UNWIND_FAILED_COUNT(per_process_id, previous_rsp_zero);
            ERROR_SAMPLE(unwind_state, "previous_rsp 0");
            return 1;
        }

        u64 previous_rip = 0;
        u64 previous_rip_addr;

// HACK(javierhonduco): This is an architectural shortcut we can take. As we
// only support x86_64 at the minute, we can assume that the return address
// is *always* 8 bytes ahead of the previous stack pointer.
#if __TARGET_ARCH_x86
        previous_rip_addr = previous_rsp - 8;
        int err = bpf_probe_read_user(&previous_rip, 8, (void *)(previous_rip_addr));
        if (err < 0) {
            LOG("\t[error] Failed to read previous rip with error: %d", err);
        }
        LOG("\tprevious ip: %llx (@ %llx)", previous_rip, previous_rip_addr);
#endif

#if __TARGET_ARCH_arm64
        // For the leaf frame, the saved pc/ip is always be stored in the link register itself
        if (found_lr_offset == 0) {
            u64 orig = unwind_state->leaf_lr;
            if (!orig) {
                orig = PT_REGS_RET(&ctx->regs);
            }
            previous_rip = canonicalize_addr(orig);
            LOG("\tfound_lr_offset 0, previous_rip from x30: %llx (pre-canonical %llx)", previous_rip, orig);
            previous_rip_addr = 0;
        } else {
            previous_rip_addr = previous_rsp + found_lr_offset;
            int err = bpf_probe_read_user(&previous_rip, 8, (void *)(previous_rip_addr));
            previous_rip = canonicalize_addr(previous_rip);
            if (err < 0) {
                LOG("\t[error] Failed to read previous rip with error: %d", err);
            }
            LOG("\tprevious ip: %llx (@ %llx)", previous_rip, previous_rip_addr);
        }
        // We only want to respect this for leaf frames
        unwind_state->leaf_lr = 0;
#endif

        if (previous_rip == 0) {
            if (!err) {
                LOG("[info] Read succeeded, and previous IP is 0. Assuming we have reached the end of the stack.");
                unwind_state->bp = 0;
                reached_bottom_of_stack = true;
                break;
            }
            int user_pid = pid_tgid;

            if (proc_info->is_jit_compiler) {
                LOG("[warn] mapping not added yet");
                request_refresh_process_info(ctx, user_pid);

                BUMP_UNWIND_FAILED_COUNT(per_process_id, mapping_not_found);
                bump_unwind_error_jit_unupdated_mapping();
                ERROR_SAMPLE(unwind_state, "mapping not added yet");
                return 1;
            }

            LOG("[warn] previous_rip should not be zero. This can mean that the read failed, ret=%d while reading previous_rip_addr", err);
            if (err == -EFAULT && previous_rip_addr) {
                LOG("[info] requesting that the user-space process attempt to fault in the memory at 0x%lx", previous_rip_addr);
                request_read(ctx, user_pid, previous_rip_addr);
            }
            bump_unwind_error_catchall();
            BUMP_UNWIND_FAILED_COUNT(per_process_id, previous_rip_zero);
            ERROR_SAMPLE(unwind_state, "previous rip 0");
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
                BUMP_UNWIND_FAILED_COUNT(per_process_id, previous_rbp_zero);
                ERROR_SAMPLE(unwind_state, "previous rbp 0");
                return 1;
            }
        }

        LOG("\tprevious sp: %llx", previous_rsp);
        LOG("\tprevious bp: %llx", previous_rbp);

        // Set previous registers.
        unwind_state->ip = previous_rip - 1;
        unwind_state->sp = previous_rsp;
        unwind_state->bp = previous_rbp;

        // Frame finished! :)
        add_frame(unwind_state, unwind_state->ip);
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
            bump_unwind_success_dwarf();
            add_stack(ctx, pid_tgid, unwind_state);
        } else {
            process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &per_process_id);
            if (proc_info == NULL) {
                LOG("[error] should never happen");
                return 1;
            }

            int user_pid = pid_tgid;

            BUMP_UNWIND_FAILED_COUNT(per_process_id, pc_not_covered);
            ERROR_SAMPLE(unwind_state, "pc not covered");
            if (proc_info->is_jit_compiler) {
                LOG("[warn] mapping not added yet to BPF maps, rbp %llx", unwind_state->bp);
                request_refresh_process_info(ctx, user_pid);
                bump_unwind_error_jit_unupdated_mapping();  // rbp != 0 and we are expecting unwind info which is absent and not expecting JITed stacks and
                                                            // therefore are not symbolising JITed stacks here but maybe it's a JIT stack
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
        bpf_tail_call(ctx, &programs, NATIVE_UNWINDER_PROGRAM_ID);
    }

    // We couldn't get the whole stacktrace.
    LOG("[warn] stack too deep; truncating.");
    unwind_state->stack.truncated = true;
    add_stack(ctx, pid_tgid, unwind_state);

    bump_unwind_error_truncated();
    return 0;
}

// Set up the initial registers to start unwinding.
static __always_inline bool set_initial_state(struct bpf_perf_event_data *ctx) {
    u32 zero = 0;
    bpf_user_pt_regs_t *regs = &ctx->regs;

    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state == NULL) {
        // This should never happen.
        return false;
    }

    // By zeroing the stack we will ensure that stack aggregates work more effectively as otherwise
    // previous values past the stack length will hash the stack to a different value in the map.
    bpf_large_memzero((void *)unwind_state, sizeof(unwind_state_t));

    u64 ip = 0;
    u64 sp = 0;
    u64 bp = 0;
#if __TARGET_ARCH_arm64
    u64 lr = 0;
    u64 x28 = 0;
#endif

    if (in_kernel(PT_REGS_IP(regs))) {
        int ret =
#if __TARGET_ARCH_arm64
            retrieve_task_registers(&ip, &sp, &bp, &lr, &x28)
#else
            retrieve_task_registers(&ip, &sp, &bp)
#endif
            ;
        if (ret) {
            // we are in kernelspace, but got the user regs
            LOG("in kernel, ip=%llx", ip);
            unwind_state->ip = ip;
            unwind_state->sp = sp;
            unwind_state->bp = bp;
#if __TARGET_ARCH_arm64
            unwind_state->leaf_lr = lr;
            unwind_state->x28 = x28;
#endif
        } else {
            // in kernelspace, but failed, probs a kworker
            return false;
        }
    } else {
        // in userspace
        unwind_state->ip = PT_REGS_IP(regs);
        unwind_state->sp = PT_REGS_SP(regs);
        unwind_state->bp = PT_REGS_FP(regs);
#if __TARGET_ARCH_arm64
        unwind_state->leaf_lr = PT_REGS_RET(regs);
        unwind_state->x28 = regs->regs[28];
#endif
    }

    // Leaf frame.
    add_frame(unwind_state, unwind_state->ip);

    return true;
}

// Note: `set_initial_state` must be called before this function.
static __always_inline int unwind_wrapper(struct bpf_perf_event_data *ctx) {
    LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
    LOG("traversing native stack");
    LOG("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");

    bpf_tail_call(ctx, &programs, NATIVE_UNWINDER_PROGRAM_ID);
    return 0;
}

SEC("perf_event")
int entrypoint(struct bpf_perf_event_data *ctx) {
    // This should equal runs+early exit counts but just to be safe...
    bump_unwind_total_entries();

    // What a pid and tgid mean differs in user and kernel space, see the
    // notes in https://man7.org/linux/man-pages/man2/getpid.2.html.
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int per_process_id = pid_tgid >> 32;
    int per_thread_id = pid_tgid;

    if (per_process_id == 0) {
        bump_unwind_total_zero_pids();
        return 0;
    }

    if (is_kthread()) {
        bump_unwind_total_kthreads();
        return 0;
    }

    if (unwinder_config.filter_processes) {
        if (!is_debug_enabled_for_thread(per_process_id)) {
            bump_unwind_total_filter_misses();
            BUMP_UNWIND_FAILED_COUNT(per_process_id, missed_filter);
            // LOG("[debug] pid %u didn't match filter, ignoring.", per_process_id);
            return 0;
        } else {
            LOG("[debug] pid %u matched filter.", per_process_id);
        }
    }

    bump_unwind_total_runs();

    set_initial_state(ctx);
    u32 zero = 0;
    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state == NULL) {
        // This should never happen.
        LOG("[error] no unwind state");
        return 0;
    }

    // Set these early for ERROR_SAMPLE.
    unwind_state->stack_key.pid = per_process_id;
    unwind_state->stack_key.tgid = per_thread_id;

    // We know about this process.
    if (has_unwind_information(per_process_id)) {
        bump_samples();

        process_info_t *proc_info = bpf_map_lookup_elem(&process_info, &per_process_id);
        if (proc_info == NULL) {
            LOG("[error] should never happen");
            return 1;
        }

        // Set the runtime unwinder type before we start unwinding.
        LOG("[debug] setting runtime unwinder type to %d", proc_info->unwinder_type);
        unwind_state->unwinder_type = proc_info->unwinder_type;

        chunk_info_t *chunk_info = NULL;
        enum find_unwind_table_return unwind_table_result = find_unwind_table(&chunk_info, per_process_id, unwind_state->ip, NULL);
        if (chunk_info == NULL) {
            if (unwind_table_result == FIND_UNWIND_MAPPING_NOT_FOUND) {
                LOG("[warn] IP 0x%llx not covered, mapping not found.", unwind_state->ip);
                request_refresh_process_info(ctx, per_process_id);
                bump_unwind_error_pc_not_covered();
                BUMP_UNWIND_FAILED_COUNT(per_process_id, pc_not_covered);
                ERROR_SAMPLE(unwind_state, "pc not covered");
                return 1;
            } else if (unwind_table_result == FIND_UNWIND_JITTED) {
                if (!unwinder_config.mixed_stack_enabled) {
                    LOG("[warn] IP 0x%llx not covered, JIT (but mixed-mode unwinding disabled)!.", unwind_state->ip);
                    bump_unwind_error_pc_not_covered_jit();
                    bump_unwind_error_jit_mixed_mode_disabled();
                    BUMP_UNWIND_FAILED_COUNT(per_process_id, pc_not_covered);
                    ERROR_SAMPLE(unwind_state, "pc not covered");
                    return 1;
                }
            } else if (proc_info->is_jit_compiler) {
                LOG("[warn] IP 0x%llx not covered, may be JIT!.", unwind_state->ip);
                request_refresh_process_info(ctx, per_process_id);
                bump_unwind_error_pc_not_covered_jit();
                // We assume this failed because of a new JIT segment so we refresh mappings to find JIT segment in updated mappings
                bump_unwind_error_jit_unupdated_mapping();
                BUMP_UNWIND_FAILED_COUNT(per_process_id, pc_not_covered);
                ERROR_SAMPLE(unwind_state, "pc not covered jit");
                return 1;
            }
        }

        LOG("[info] per_process_id %d per_thread_id %d", per_process_id, per_thread_id);
        unwind_wrapper(ctx);
        return 0;
    }

    BUMP_UNWIND_FAILED_COUNT(per_process_id, no_unwind_info);
    request_unwind_information(ctx, per_process_id);
    return 0;
}

#define KBUILD_MODNAME "parca-agent"
volatile const char bpf_metadata_name[] SEC(".rodata") = "parca-agent (https://github.com/parca-dev/parca-agent)";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
