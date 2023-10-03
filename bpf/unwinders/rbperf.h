// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.
//
// Copyright (c) 2022 The rbperf authors

#include "basic_types.h"
#include "common.h"

#define COMM_MAXLEN 25

#define MAX_STACKS_PER_PROGRAM 30
#define BPF_PROGRAMS_COUNT 25
#define MAX_STACK (MAX_STACKS_PER_PROGRAM * BPF_PROGRAMS_COUNT)

#define RBPERF_STACK_READING_PROGRAM_IDX 0

#define rbperf_read bpf_probe_read_user
#define rbperf_read_str bpf_probe_read_user_str

#ifdef USE_ABSOLUTE_PATH
// TODO(javierhonduco): Add test for this
#define PATH_TYPE_OFFSET 0x8 // ABSOLUTE_PATH_OFFSET
#else
#define PATH_TYPE_OFFSET 0x0 // RELATIVE_PATH_OFFSET
#endif

#define rb_value_sizeof 0x8 // sizeof(VALUE)

#define iseq_offset 0x10          // offsetof(rb_control_frame_t, iseq)
#define body_offset 0x10          // offsetof(struct rb_iseq_struct, body)
#define ruby_location_offset 0x40 // offsetof(struct rb_iseq_constant_body, location)
#define path_offset 0x0           // offsetof(struct rb_iseq_location_struct, path)
#define iseq_encoded_offset 0x8   // offsetof(struct rb_iseq_constant_body, iseq_encoded)

#define as_offset 0x10

#define STRING_ON_HEAP(flags) flags &(1 << 13)
#define inline_method inline __attribute__((__always_inline__))

// CRuby constants, from
// https://github.com/ruby/ruby/blob/4ff3f20/include/ruby/3/value_type.h
#define RUBY_T_MASK 0x1f
#define RUBY_T_STRING 0x05
#define RUBY_T_ARRAY 0x07

// Offset and size for the the syscall number field in x86 [1]. Would be
// best to fetch this offset from the machine where rbperf runs, but should
// be the same offset for all the syscalls even across architectures.
//
// - [1] /sys/kernel/debug/tracing/events/syscalls/*/format
#define SYSCALL_NR_OFFSET 8
#define SYSCALL_NR_SIZE 4

static char NATIVE_METHOD_NAME[] = "<native code>";
static char NATIVE_METHOD_PATH[] = "<unknown>";

enum ruby_stack_status {
    STACK_COMPLETE = 0,
    STACK_INCOMPLETE = 1,
};

enum rbperf_event_type {
    RBPERF_EVENT_UNKNOWN = 0,
    RBPERF_EVENT_ON_CPU_SAMPLING = 1,
    RBPERF_EVENT_SYSCALL = 2,
};

typedef struct {
    u64 timestamp;
    stack_trace_t frames;

    u32 pid;
    u32 cpu;
    // Only set when tracing syscalls.
    int syscall_id;
    // long long int size;
    long long int expected_size;
    char comm[COMM_MAXLEN];
    enum ruby_stack_status stack_status;
} RubyStack;

typedef struct {
    RubyStack stack;
    u64 base_stack;
    u64 cfp;
    int ruby_stack_program_count;
    int rb_version;
} SampleState;

typedef struct {
    u64 rb_frame_addr;
    u32 rb_version;
    u64 start_time;
} ProcessData;

typedef struct {
    int major_version;
    int minor_version;
    int patch_version;
    int vm_offset;
    int vm_size_offset;
    int control_frame_t_sizeof;
    int cfp_offset;
    int label_offset;
    int path_flavour;
    int line_info_size_offset;
    int line_info_table_offset;
    int lineno_offset;
    int main_thread_offset;
    int ec_offset;
} RubyVersionOffsets;
