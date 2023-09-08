// Copyright (c) Facebook, Inc. and its affiliates.
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
//
// Copyright (c) 2022 The rbperf authors

// clang-format off
#include "rbperf.h"

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "hash.h"
#include "shared.h"

/* struct {
    // This map's type is a placeholder, it's dynamically set
    // in rbperf.rs to either perf/ring buffer depending on
    // the configuration.
    __uint(type, BPF_MAP_TYPE_RINGBUF);
} events SEC(".maps"); */

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);
    __type(key, u32);
    __type(value, u32);
} programs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, ProcessData);
} pid_to_rb_thread SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 12);
    __type(key, u32);
    __type(value, RubyVersionOffsets);
} version_specific_offsets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, SampleState);
} global_state SEC(".maps");

const volatile bool verbose = false;
const volatile int num_cpus = 200; // Hard-limit of 200 CPUs.
const volatile bool use_ringbuf = false;
const volatile bool enable_pid_race_detector = false;
const volatile enum rbperf_event_type event_type = RBPERF_EVENT_UNKNOWN;

#define LOG(fmt, ...)                                                                                                                                          \
    ({                                                                                                                                                         \
        if (verbose) {                                                                                                                                         \
            bpf_printk("rbperf: " fmt, ##__VA_ARGS__);                                                                                                         \
        }                                                                                                                                                      \
    })

static inline_method int read_syscall_id(void *ctx, int *syscall_id) {
    return bpf_probe_read_kernel(syscall_id, SYSCALL_NR_SIZE, ctx + SYSCALL_NR_OFFSET);
}

static inline_method u32 find_or_insert_frame(symbol_t *frame) {
    u32 *found_id = bpf_map_lookup_elem(&symbol_table, frame);
    if (found_id != NULL) {
        return *found_id;
    }

    u32 zero = 0;
    u64 *frame_index = bpf_map_lookup_elem(&symbol_index_storage, &zero);
    // Appease the verifier, this will never fail.
    if (frame_index == NULL) {
        return 0;
    }

    // The previous __sync_fetch_and_add does not seem to work in 5.4 and 5.10
    //  > libbpf: prog 'walk_ruby_stack': -- BEGIN PROG LOAD LOG --\nBPF_STX uses reserved fields
    //
    // Checking for the version does not work as these branches are not pruned
    // in older kernels, so we shard the id generation per CPU.
    u64 idx = *frame_index * num_cpus + bpf_get_smp_processor_id();
    *frame_index += 1;

    int err;
    err = bpf_map_update_elem(&symbol_table, frame, &idx, BPF_ANY);
    if (err) {
        LOG("[error] symbol_table failed with %d", err);
    }
    return idx;
}

static inline_method void read_ruby_string(RubyVersionOffsets *version_offsets, u64 label, char *buffer, int buffer_len) {
    u64 flags;
    u64 char_ptr;

    rbperf_read(&flags, 8, (void *)(label + 0 /* .basic */ + 0 /* .flags */));

    if (STRING_ON_HEAP(flags)) {
        rbperf_read(&char_ptr, 8, (void *)(label + as_offset + 8 /* .long len */));
        int err = rbperf_read_str(buffer, buffer_len, (void *)(char_ptr));
        if (err < 0) {
            LOG("[warn] string @ 0x%llx [heap] failed with err=%d", char_ptr, err);
        }
    } else {
        u64 c_string_address = label + as_offset;
        if (version_offsets->major_version == 3 && version_offsets->minor_version >= 2) {
            // Account for Variable Width Allocation https://bugs.ruby-lang.org/issues/18239.
            c_string_address += sizeof(long);
        }
        int err = rbperf_read_str(buffer, buffer_len, (void *)(c_string_address));
        if (err < 0) {
            LOG("[warn] string @ 0x%llx [stack] failed with err=%d", c_string_address, err);
        }
    }
}

static inline_method int read_ruby_lineno(u64 pc, u64 body, RubyVersionOffsets *version_offsets) {
    // This will only give accurate line number for Ruby 2.4

    u64 pos_addr;
    u64 pos;
    u64 info_table;
    u32 line_info_size;
    u32 lineno;

    // Native functions have 0 as pc
    if (pc == 0) {
        return 0;
    }

    rbperf_read(&pos_addr, 8, (void *)(pc - body + iseq_encoded_offset));
    rbperf_read(&pos, 8, (void *)pos_addr);
    rbperf_read(&info_table, 8, (void *)(body + version_offsets->line_info_table_offset));

    if (pos != 0) {
        pos -= rb_value_sizeof;
    }

    rbperf_read(&line_info_size, 4, (void *)(body + version_offsets->line_info_size_offset));
    if (line_info_size == 0) {
        return 0;
    } else if (line_info_size == 1) {
        rbperf_read(&lineno, 4, (void *)(info_table + (0) * 0x8 + version_offsets->lineno_offset));
        return lineno;
    } else {
        // Note: this is not fully correct as we don't implement get_insn_info_linear_search or
        // get_insn_info_succinct_bitvector. Line numbers might be biased.
        // See https://github.com/ruby/ruby/blob/7b2306a3ab2a7d33c5c5c8ac248447349874b258/.gdbinit#L1015
        rbperf_read(&lineno, 4, (void *)(info_table + (line_info_size - 1) * 0x8 + version_offsets->lineno_offset));
        return lineno;
    }
}

static inline_method void read_frame(u64 pc, u64 body, symbol_t *current_frame, RubyVersionOffsets *version_offsets) {
    u64 path_addr;
    u64 path;
    u64 label;
    u64 flags;
    int label_offset = version_offsets->label_offset;

    LOG("[debug] reading stack");
    __builtin_memset((void *)current_frame, 0, sizeof(symbol_t));

    rbperf_read(&path_addr, 8, (void *)(body + ruby_location_offset + path_offset));
    rbperf_read(&flags, 8, (void *)path_addr);
    if ((flags & RUBY_T_MASK) == RUBY_T_STRING) {
        path = path_addr;
    } else if ((flags & RUBY_T_MASK) == RUBY_T_ARRAY) {
        if (version_offsets->path_flavour == 1) {
            // sizeof(struct RBasic)
            path_addr = path_addr + 0x10 /* offset(..., as) */ + PATH_TYPE_OFFSET;
            rbperf_read(&path, 8, (void *)path_addr);
        } else {
            path = path_addr;
        }

    } else {
        LOG("[error] read_frame, wrong type");
        // Skip as we don't have the data types we were looking for
        return;
    }

    rbperf_read(&label, 8, (void *)(body + ruby_location_offset + label_offset));

    read_ruby_string(version_offsets, path, current_frame->path, sizeof(current_frame->path));
    current_frame->lineno = read_ruby_lineno(pc, body, version_offsets);
    read_ruby_string(version_offsets, label, current_frame->method_name, sizeof(current_frame->method_name));

    LOG("[debug] method name=%s", current_frame->method_name);
}

SEC("perf_event")
int walk_ruby_stack(struct bpf_perf_event_data *ctx) {
    u64 iseq_addr;
    u64 pc;
    u64 pc_addr;
    u64 body;

    int zero = 0;
    SampleState *state = bpf_map_lookup_elem(&global_state, &zero);
    if (state == NULL) {
        return 0; // this should never happen
    }

    RubyVersionOffsets *version_offsets = bpf_map_lookup_elem(&version_specific_offsets, &state->rb_version);
    if (version_offsets == NULL) {
        return 0; // this should not happen
    }

    symbol_t current_frame = {};
    u64 base_stack = state->base_stack;
    u64 cfp = state->cfp;
    state->ruby_stack_program_count += 1;
    u64 control_frame_t_sizeof = version_offsets->control_frame_t_sizeof;

#pragma unroll
    for (int i = 0; i < MAX_STACKS_PER_PROGRAM; i++) {
        rbperf_read(&iseq_addr, 8, (void *)(cfp + iseq_offset));
        rbperf_read(&pc_addr, 8, (void *)(cfp + 0));
        rbperf_read(&pc, 8, (void *)pc_addr);

        if (cfp > state->base_stack) {
            LOG("[debug] done reading stack");
            break;
        }

        if ((void *)iseq_addr == NULL) {
            // this could be a native frame, it's missing the check though
            // https://github.com/ruby/ruby/blob/4ff3f20/.gdbinit#L1155
            // TODO(javierhonduco): Fetch path for native stacks
            bpf_probe_read_kernel_str(current_frame.method_name, sizeof(NATIVE_METHOD_NAME), NATIVE_METHOD_NAME);
            bpf_probe_read_kernel_str(current_frame.path, sizeof(NATIVE_METHOD_PATH), NATIVE_METHOD_PATH);
        } else {
            rbperf_read(&body, 8, (void *)(iseq_addr + body_offset));
            read_frame(pc, body, &current_frame, version_offsets);
        }

        long long int actual_index = state->stack.frames.len;
        if (actual_index >= 0 && actual_index < MAX_STACK_DEPTH) {
            state->stack.frames.addresses[actual_index] = find_or_insert_frame(&current_frame);
            state->stack.frames.len += 1;
        }

        cfp += control_frame_t_sizeof;
    }

    state->cfp = cfp;
    state->base_stack = base_stack;

    if (cfp <= base_stack && state->ruby_stack_program_count < BPF_PROGRAMS_COUNT) {
        LOG("[debug] traversing next chunk of the stack in a tail call");
        bpf_tail_call(ctx, &programs, RBPERF_STACK_READING_PROGRAM_IDX);
    }

    state->stack.stack_status = cfp > state->base_stack ? STACK_COMPLETE : STACK_INCOMPLETE;

    if (state->stack.frames.len != state->stack.expected_size) {
        LOG("[error] stack size %d, expected %d", state->stack.frames.len, state->stack.expected_size);
    }

    // Hash stack.
    int ruby_stack_hash = MurmurHash2((u32 *)state->stack.frames.addresses, MAX_STACK * sizeof(u64) / sizeof(u32), 0);
    LOG("[debug] ruby stack hash: %d", ruby_stack_hash);

    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state != NULL) {
        unwind_state->stack_key.interpreter_stack_id = ruby_stack_hash;
    }

    // Insert stack.
    int err = bpf_map_update_elem(&interpreter_stack_traces, &ruby_stack_hash, &state->stack.frames, BPF_ANY);
    if (err != 0) {
        LOG("[error] bpf_map_update_elem with ret: %d", err);
    }

    // We are done.
    aggregate_stacks();
    return 0;
}

SEC("perf_event")
int unwind_ruby_stack(struct bpf_perf_event_data *ctx) {
    u64 zero = 0;
    unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
    if (unwind_state == NULL) {
        bpf_printk("[rbperf] unwind_state is NULL, should not happen");
        return 1;
    }
    // bpf_printk("[rbperf] unwind_state->len = %d", unwind_state->stack.len);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    // There's no point in checking for the swapper process.
    if (pid == 0) {
        return 0;
    }

    ProcessData *process_data = bpf_map_lookup_elem(&pid_to_rb_thread, &pid);

    if (process_data != NULL && process_data->rb_frame_addr != 0) {
        struct task_struct *task = (void *)bpf_get_current_task();
        if (task == NULL) {
            LOG("[error] task_struct was NULL");
            return 0;
        }

        // PIDs in Linux are reused. To ensure that the process we are
        // profiling is the one we expect, we check the pid + start_time
        // of the process.
        //
        // When we start profiling, the start_time will be zero, so we set
        // it to the actual start time. Otherwise, we check that the start_time
        // of the process matches what we expect. If it's not the case, bail out
        // early, to avoid profiling the wrong process.
        if (enable_pid_race_detector) {
            u64 process_start_time;
            bpf_core_read(&process_start_time, 8, &task->start_time);

            if (process_data->start_time == 0) {
                // First time seeing this process
                process_data->start_time = process_start_time;
            } else {
                // Let's check that the start time matches what we saw before
                if (process_data->start_time != process_start_time) {
                    LOG("[error] the process has probably changed...");
                    return 0;
                }
            }
        }

        u64 ruby_current_thread_addr;
        u64 main_thread_addr;
        u64 ec_addr;
        u64 thread_stack_content;
        u64 thread_stack_size;
        u64 cfp;
        int control_frame_t_sizeof;
        RubyVersionOffsets *version_offsets = bpf_map_lookup_elem(&version_specific_offsets, &process_data->rb_version);

        if (version_offsets == NULL) {
            LOG("[error] can't find offsets for version");
            return 0;
        }

        rbperf_read(&ruby_current_thread_addr, 8, (void *)process_data->rb_frame_addr);

        LOG("process_data->rb_frame_addr 0x%llx", process_data->rb_frame_addr);
        LOG("ruby_current_thread_addr 0x%llx", ruby_current_thread_addr);

        // Find the main thread and the ec
        rbperf_read(&main_thread_addr, 8, (void *)ruby_current_thread_addr + version_offsets->main_thread_offset);
        rbperf_read(&ec_addr, 8, (void *)main_thread_addr + version_offsets->ec_offset);

        control_frame_t_sizeof = version_offsets->control_frame_t_sizeof;

        rbperf_read(&thread_stack_content, 8, (void *)(ec_addr + version_offsets->vm_offset));
        rbperf_read(&thread_stack_size, 8, (void *)(ec_addr + version_offsets->vm_size_offset));

        u64 base_stack = thread_stack_content + rb_value_sizeof * thread_stack_size - 2 * control_frame_t_sizeof /* skip dummy frames */;
        rbperf_read(&cfp, 8, (void *)(ec_addr + version_offsets->cfp_offset));
        int zero = 0;
        SampleState *state = bpf_map_lookup_elem(&global_state, &zero);
        if (state == NULL) {
            return 0; // this should never happen
        }

        // Set the global state, shared across bpf tail calls
        state->stack.timestamp = bpf_ktime_get_ns();
        state->stack.pid = pid;
        state->stack.cpu = bpf_get_smp_processor_id();
        if (event_type == RBPERF_EVENT_SYSCALL) {
            read_syscall_id(ctx, &state->stack.syscall_id);
        } else {
            state->stack.syscall_id = 0;
        }
        state->stack.frames.len = 0;
        state->stack.expected_size = (base_stack - cfp) / control_frame_t_sizeof;
        bpf_get_current_comm(state->stack.comm, sizeof(state->stack.comm));
        state->stack.stack_status = STACK_COMPLETE;

        state->base_stack = base_stack;
        state->cfp = cfp + version_offsets->control_frame_t_sizeof;
        state->ruby_stack_program_count = 0;
        state->rb_version = process_data->rb_version;

        bpf_tail_call(ctx, &programs, RBPERF_STACK_READING_PROGRAM_IDX);
        // This will never be executed
        LOG("[error] after bpf_tail_call, this should not be reached");
        return 0;
    } else {
        bpf_printk("[error] not a ruby proc");
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
// clang-format on
