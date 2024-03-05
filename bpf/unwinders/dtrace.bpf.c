// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors

#include "dtrace.h"

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "hash.h"
#include "shared.h"

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ Constants and Configuration                                             ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//
const volatile bool verbose = false;

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║  BPF Maps                                                               ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//

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
  __type(value, VMInfo);
} pid_to_vm_info SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 10); // We have plenty of head room.
  __type(key, u32);
  __type(value, JavaOffsets);
} version_specific_offsets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, State);
} global_state SEC(".maps");

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ Generic Helpers and Macros                                              ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//

#define GET_STATE()                                                                                                                                            \
  State *state = bpf_map_lookup_elem(&global_state, &zero);                                                                                                    \
  if (state == NULL) {                                                                                                                                         \
    return 0;                                                                                                                                                  \
  }

#define GET_OFFSETS()                                                                                                                                          \
  JavaOffsets *offsets = bpf_map_lookup_elem(&version_specific_offsets, &state->vm_info.java_version_index);                                                   \
  if (offsets == NULL) {                                                                                                                                       \
    return 0;                                                                                                                                                  \
  }

#define LOG(fmt, ...)                                                                                                                                          \
  ({                                                                                                                                                           \
    if (verbose) {                                                                                                                                             \
      bpf_printk("dtrace: " fmt, ##__VA_ARGS__);                                                                                                               \
    }                                                                                                                                                          \
  })

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ BPF Programs                                                            ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//
SEC("perf_event")
int unwind_java_stack(struct bpf_perf_event_data *ctx) {
  LOG("[call] unwind_java_stack");

  u64 zero = 0;
  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state == NULL) {
    LOG("[error] unwind_state is NULL, should not happen");
    return 1;
  }

  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;
  pid_t tid = pid_tgid;
  if (pid == 0) {
    return 0;
  }

  VMInfo *vm_info = bpf_map_lookup_elem(&pid_to_vm_info, &pid);
  if (!vm_info) {
    LOG("[error] vm_info is NULL, not a Java process or unknown Java version");
    return 1;
  }

  LOG("[start] unwind_java_stack");
  LOG("[event] pid=%d tid=%d", pid, tid);

  GET_STATE();

  // Reset state.
  state->vm_info = (VMInfo){0};
  state->vm_info = *vm_info;

  state->stack_walker_prog_call_count = 0;

  state->sample.tid = tid;
  state->sample.pid = pid;
  state->sample.stack_status = STACK_COMPLETE;
  state->sample.stack = (stack_trace_t){0};
  state->sample.stack.len = 0;
  __builtin_memset((void *)state->sample.stack.addresses, 0, sizeof(state->sample.stack.addresses));

  if (vm_info->code_cache_addr == 0) {
    goto submit_without_unwinding;
  }

  //   GET_OFFSETS();
  LOG("[debug] vm_info.code_cache_addr: %d", vm_info->code_cache_addr);

  bpf_tail_call(ctx, &programs, DTRACE_STACK_WALKING_PROGRAM_IDX);

submit_without_unwinding:
  aggregate_stacks();
  LOG("[stop] submit_without_unwinding");
  return 0;
}

SEC("perf_event")
int walk_java_stack(struct bpf_perf_event_data *ctx) {
  u64 zero = 0;
  GET_STATE();
  GET_OFFSETS();

  LOG("=====================================================\n");
  LOG("[start] walk_java_stack");
  state->stack_walker_prog_call_count++;
  Sample *sample = &state->sample;

#pragma unroll
  for (int i = 0; i < JAVA_STACK_FRAMES_PER_PROG; i++) {
    LOG("[debug] i=%d", i);
    if (sample->stack.len >= MAX_STACK_DEPTH) {
      LOG("[error] stack.len >= MAX_STACK_DEPTH");
      goto complete;
    }
  }

complete:
  LOG("[complete] walk_java_stack, stack_len=%d", sample->stack.len);
  state->sample.stack_status = STACK_COMPLETE;
  // submit:
  LOG("[stop] walk_java_stack");

  // Hash stack.
  u64 stack_hash = hash_stack(&state->sample.stack, 0);
  LOG("[debug] stack hash: %d", stack_hash);

  // Insert stack.
  int err = bpf_map_update_elem(&stack_traces, &stack_hash, &state->sample.stack, BPF_ANY);
  if (err != 0) {
    LOG("[error] failed to insert stack_traces with %d", err);
  }

  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state != NULL) {
    unwind_state->stack_key.interpreter_stack_id = stack_hash;
  }

  // We are done.
  aggregate_stacks();
  LOG("[stop] submit");
  return 0;
}

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ Metadata                                                                ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//
#define KBUILD_MODNAME "dtrace"
volatile const char bpf_metadata_name[] SEC(".rodata") = "dtrace";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
