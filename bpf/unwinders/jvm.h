// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors

#include "basic_types.h"
#include "common.h"

#define JAVA_STACK_FRAMES_PER_PROG 16
#define JAVA_STACK_PROG_CNT 5
#define MAX_STACK (JAVA_STACK_FRAMES_PER_PROG * JAVA_STACK_PROG_CNT)

#define JVM_STACK_WALKING_PROGRAM_IDX 0

typedef struct {
    // u64 start_time;
    u64 code_cache_low_addr;
    u64 code_cache_high_addr;
    u32 java_version_index;
} VMInfo;

enum java_stack_status {
    STACK_COMPLETE = 0,
    STACK_TRUNCATED = 1,
    STACK_ERROR = 2,
};

typedef struct {
    u32 pid;
    u32 tid;
    enum java_stack_status stack_status;

    stack_trace_t stack;
} Sample;

typedef struct {
    VMInfo vm_info;

    int stack_walker_prog_call_count;

    Sample sample;
} State;

typedef struct {
    s64 code_blob_start;
} JavaOffsets;
