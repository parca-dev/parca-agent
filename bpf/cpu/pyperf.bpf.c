// Copyright (c) Facebook, Inc. and its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
//
// Copyright 2023 The Parca Authors

#include "pyperf.h"

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
  __type(key, pid_t);
  __type(value, ProcessInfo);
} pid_to_process_info SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10);
  __type(key, u32);
  __type(value, PythonVersionOffsets);
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
  PythonVersionOffsets *offsets = bpf_map_lookup_elem(&version_specific_offsets, &state->process_info.py_version);                                             \
  if (offsets == NULL) {                                                                                                                                       \
    return 0;                                                                                                                                                  \
  }

#define LOG(fmt, ...)                                                                                                                                          \
  ({                                                                                                                                                           \
    if (verbose) {                                                                                                                                             \
      bpf_printk("pyperf: " fmt, ##__VA_ARGS__);                                                                                                               \
    }                                                                                                                                                          \
  })

// static inline __attribute__((__always_inline__)) void print_python_version_offsets(PythonVersionOffsets *pvo) {
//   bpf_printk("Python Version Offsets:\n");
//   bpf_printk("  major_version: %u\n", pvo->major_version);
//   bpf_printk("  minor_version: %u\n", pvo->minor_version);
//   bpf_printk("  patch_version: %u\n", pvo->patch_version);
//   bpf_printk("  py_object:\n");
//   bpf_printk("    ob_type: %lld\n", pvo->py_object.ob_type);
//   bpf_printk("  py_string:\n");
//   bpf_printk("    data: %lld\n", pvo->py_string.data);
//   bpf_printk("    size: %lld\n", pvo->py_string.size);
//   bpf_printk("  py_type_object:\n");
//   bpf_printk("    tp_name: %lld\n", pvo->py_type_object.tp_name);
//   bpf_printk("  py_thread_state:\n");
//   bpf_printk("    next: %lld\n", pvo->py_thread_state.next);
//   bpf_printk("    interp: %lld\n", pvo->py_thread_state.interp);
//   bpf_printk("    frame: %lld\n", pvo->py_thread_state.frame);
//   bpf_printk("    thread: %lld\n", pvo->py_thread_state.thread);
//   bpf_printk("    cframe: %lld\n", pvo->py_thread_state.cframe);
//   bpf_printk("  py_cframe:\n");
//   bpf_printk("    current_frame: %lld\n", pvo->py_cframe.current_frame);
//   bpf_printk("  py_interpreter_state:\n");
//   bpf_printk("    tstate_head: %lld\n", pvo->py_interpreter_state.tstate_head);
//   bpf_printk("  py_runtime_state:\n");
//   bpf_printk("    interp_main: %lld\n", pvo->py_runtime_state.interp_main);
//   bpf_printk("  py_frame_object:\n");
//   bpf_printk("    f_back: %lld\n", pvo->py_frame_object.f_back);
//   bpf_printk("    f_code: %lld\n", pvo->py_frame_object.f_code);
//   bpf_printk("    f_lineno: %lld\n", pvo->py_frame_object.f_lineno);
//   bpf_printk("    f_localsplus: %lld\n", pvo->py_frame_object.f_localsplus);
//   bpf_printk("  py_code_object:\n");
//   bpf_printk("    co_filename: %lld\n", pvo->py_code_object.co_filename);
//   bpf_printk("    co_name: %lld\n", pvo->py_code_object.co_name);
//   bpf_printk("    co_varnames: %lld\n", pvo->py_code_object.co_varnames);
//   bpf_printk("    co_firstlineno: %lld\n", pvo->py_code_object.co_firstlineno);
//   bpf_printk("  py_tuple_object:\n");
//   bpf_printk("    ob_item: %lld\n", pvo->py_tuple_object.ob_item);
// }

static __always_inline long unsigned int read_tls_base(struct task_struct *task) {
  long unsigned int tls_base;
  // This changes depending on arch and kernel version.
  // task->thread.fs, task->thread.tp_value, etc.
  // #if __x86_64__
  tls_base = BPF_CORE_READ(task, thread.fsbase);
  // #elif __aarch64__
  //   tls_base = BPF_CORE_READ(task, thread.tp_value);
  // #else
  // #error "Unsupported platform"
  // #endif
  return tls_base;
}

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ BPF Programs                                                            ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//
SEC("perf_event")
int unwind_python_stack(struct bpf_perf_event_data *ctx) {
  u64 zero = 0;
  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state == NULL) {
    bpf_printk("pyperf: [error] unwind_state is NULL, should not happen");
    return 1;
  }
  // bpf_printk("[pyperf] unwind_state->len = %d", unwind_state->stack.len);

  // @norelease: DRY
  u64 pid_tgid = bpf_get_current_pid_tgid();
  pid_t pid = pid_tgid >> 32;
  pid_t tid = pid_tgid;
  if (pid == 0) {
    return 0;
  }

  ProcessInfo *process_info = bpf_map_lookup_elem(&pid_to_process_info, &pid);
  if (!process_info) {
    bpf_printk("pyperf: [error] process_info is NULL, not a Python process or unknown Python version");
    return 0;
  }

  if (process_info->thread_state_addr == 0) {
    LOG("[error] process_info.thread_state_addr was NULL");
    return 0;
  }

  LOG("[start]");
  LOG("[event] pid=%d tid=%d", pid, tid);

  GET_STATE();

  // Reset state.
  state->process_info = (ProcessInfo){0};
  state->process_info = *process_info;
  // state->interpreter = 0;
  // state->thread_state = 0;
  // state->py_version = process_info->py_version;

  // state->base_stack = base_stack;
  // state->cfp = cfp + version_offsets->control_frame_t_sizeof;
  state->frame_ptr = 0;
  state->stack_walker_prog_call_count = 0;

  // state->sample = (Sample){0};
  state->sample.timestamp = bpf_ktime_get_ns();
  state->sample.tid = tid;
  state->sample.pid = pid;
  state->sample.cpu = bpf_get_smp_processor_id();
  state->sample.stack_status = STACK_COMPLETE;
  // TODO(kakkoyun): Add error codes.
  // state->sample.error_code = ERROR_NONE;

  state->sample.stack = (stack_trace_t){0};
  state->sample.stack.len = 0;
  // TODO(kakkoyun): Implement Stack bound checks.
  // state->stack.expected_size = (base_stack - cfp) / control_frame_t_sizeof;
  __builtin_memset((void *)state->sample.stack.addresses, 0, sizeof(state->sample.stack.addresses));

  // Fetch interpreter head.

  // LOG("process_info->interpreter_addr 0x%llx", process_info->interpreter_addr);
  // bpf_probe_read_user(&state->interpreter,
  //                     sizeof(state->interpreter),
  //                     (void *)(long)process_info->interpreter_addr);
  // LOG("interpreter 0x%llx", state->interpreter);

  // Fetch thread state.

  // GDB: ((PyThreadState *)_PyRuntime.gilstate.tstate_current)
  LOG("process_info->thread_state_addr 0x%llx", process_info->thread_state_addr);
  int err = bpf_probe_read_user(&state->thread_state, sizeof(state->thread_state), (void *)(long)process_info->thread_state_addr);
  if (err != 0) {
    LOG("[error] bpf_probe_read_user failed with %d", err);
    goto submit_event;
  }
  if (state->thread_state == 0) {
    LOG("[error] thread_state was NULL");
    goto submit_event;
  }
  LOG("thread_state 0x%llx", state->thread_state);

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  long unsigned int tls_base = read_tls_base(task);
  LOG("tls_base 0x%llx", (void *)tls_base);

  GET_OFFSETS();
  // print_python_version_offsets(offsets);

  // Fetch the thread id.

  // Python 3.11+ uses native_thread_id.
  if (offsets->py_thread_state.native_thread_id > 0) {
    u64 thread_id = 0;
    LOG("offsets->py_thread_state.native_thread_id %d", offsets->py_thread_state.native_thread_id);
    bpf_probe_read_user(&thread_id, sizeof(thread_id), state->thread_state + offsets->py_thread_state.native_thread_id);
    LOG("thread_id %d", thread_id);
    if (thread_id != tid) {
      LOG("[error] thread_id %d != tid %d", thread_id, tid);
      goto submit_event;
    }
  } else {
    LOG("offsets->py_thread_state.thread_id %d", offsets->py_thread_state.thread_id);
    s64 pthread_id;
    bpf_probe_read_user(&pthread_id, sizeof(pthread_id), state->thread_state + offsets->py_thread_state.thread_id);
    LOG("pthread_id %d", pthread_id);
    // 0x10 = offsetof(tcbhead_t, self) for glibc.
    s64 current_pthread_id;
    bpf_probe_read_user(&current_pthread_id, sizeof(current_pthread_id), (void *)(tls_base + 0x10));
    LOG("current_pthread_id %d", current_pthread_id);
    if (pthread_id != current_pthread_id) {
      LOG("[error] pthread_id %d != current_pthread_id %d", pthread_id, current_pthread_id);
      goto submit_event;
    }
  }

  // Get pointer to top frame from PyThreadState.

  // TODO(kakkoyun): Move this to the user-space and Better to check version.
  if (offsets->py_thread_state.frame > -1) {
    LOG("offsets->py_thread_state.frame %d", offsets->py_thread_state.frame);
    bpf_probe_read_user(&state->frame_ptr, sizeof(void *), state->thread_state + offsets->py_thread_state.frame);
  } else {
    LOG("offsets->py_thread_state.cframe %d", offsets->py_thread_state.cframe);
    void *cframe;
    bpf_probe_read_user(&cframe, sizeof(cframe), (void *)(state->thread_state + offsets->py_thread_state.cframe));
    if (cframe == 0) {
      LOG("[error] cframe was NULL");
      goto submit_event;
    }
    LOG("cframe 0x%llx", cframe);

    LOG("offsets->py_cframe.current_frame %d", offsets->py_cframe.current_frame);
    bpf_probe_read_user(&state->frame_ptr, sizeof(state->frame_ptr), (void *)(cframe + offsets->py_cframe.current_frame));
  }
  if (state->frame_ptr == 0) {
    LOG("[error] frame_ptr was NULL");
    goto submit_event;
  }
  LOG("frame_ptr 0x%llx", state->frame_ptr);

  bpf_tail_call(ctx, &programs, PYPERF_STACK_WALKING_PROGRAM_IDX);
  // bpf_tail_call(ctx, &programs, PYPERF_THREAD_STATE_PROGRAM_IDX);
  // This will never be executed.

submit_event:
  aggregate_stacks();
  return 0;
}

static inline __attribute__((__always_inline__)) u64 get_symbol_id(symbol_t *sym) {
  int *symbol_id_ptr = bpf_map_lookup_elem(&symbol_table, sym);
  if (symbol_id_ptr) {
    return *symbol_id_ptr;
  }

  u32 zero = 0;
  u64 *sym_idx = bpf_map_lookup_elem(&symbol_index_storage, &zero);
  if (sym_idx == NULL) {
    // Appease the verifier, this will never fail.
    return 0;
  }

  u64 idx = __sync_fetch_and_add(sym_idx, 1);
  int err;
  err = bpf_map_update_elem(&symbol_table, sym, &idx, BPF_ANY);
  if (err) {
    LOG("[error] symbols failed with %d", err);
  }
  return idx;
}

static inline __attribute__((__always_inline__)) void read_symbol(PythonVersionOffsets *offsets, void *cur_frame, void *code_ptr, symbol_t *symbol) {
  // Figure out if we want to parse class name, basically checking the name of
  // the first argument.
  // If it's 'self', we get the type and it's name, if it's cls, we just get
  // the name. This is not perfect but there is no better way to figure this
  // out from the code object.
  // Everything we do in this function is best effort, we don't want to fail
  // the program if we can't read something.

  // GDB: ((PyTupleObject*)$frame->f_code->co_varnames)->ob_item[0]
  void *args_ptr;
  bpf_probe_read_user(&args_ptr, sizeof(void *), code_ptr + offsets->py_code_object.co_varnames);
  bpf_probe_read_user(&args_ptr, sizeof(void *), args_ptr + offsets->py_tuple_object.ob_item);
  bpf_probe_read_user_str(&symbol->method_name, sizeof(symbol->method_name), args_ptr + offsets->py_string.data);

  // Compare strings as ints to save instructions.
  char self_str[4] = {'s', 'e', 'l', 'f'};
  char cls_str[4] = {'c', 'l', 's', '\0'};
  bool first_self = *(s32 *)symbol->method_name == *(s32 *)self_str;
  bool first_cls = *(s32 *)symbol->method_name == *(s32 *)cls_str;

  // GDB: $frame->f_localsplus[0]->ob_type->tp_name.
  if (first_self || first_cls) {
    void *ptr;
    bpf_probe_read_user(&ptr, sizeof(void *), cur_frame + offsets->py_frame_object.f_localsplus);
    if (first_self) {
      // We are working with an instance, first we need to get type.
      bpf_probe_read_user(&ptr, sizeof(void *), ptr + offsets->py_object.ob_type);
    }
    bpf_probe_read_user(&ptr, sizeof(void *), ptr + offsets->py_type_object.tp_name);
    bpf_probe_read_user_str(&symbol->class_name, sizeof(symbol->class_name), ptr);
  }

  void *pystr_ptr;

  // GDB: $frame->f_code->co_filename
  bpf_probe_read_user(&pystr_ptr, sizeof(void *), code_ptr + offsets->py_code_object.co_filename);
  bpf_probe_read_user_str(&symbol->path, sizeof(symbol->path), pystr_ptr + offsets->py_string.data);

  // GDB: $frame->f_code->co_name
  bpf_probe_read_user(&pystr_ptr, sizeof(void *), code_ptr + offsets->py_code_object.co_name);
  bpf_probe_read_user_str(&symbol->method_name, sizeof(symbol->method_name), pystr_ptr + offsets->py_string.data);

  // GDB: $frame->f_code->co_firstlineno
  bpf_probe_read_user(&symbol->lineno, sizeof(symbol->lineno), code_ptr + offsets->py_code_object.co_firstlineno);
}

static inline __attribute__((__always_inline__)) void reset_symbol(symbol_t *sym) {
  __builtin_memset((void *)sym, 0, sizeof(symbol_t));

  // We re-use the same symbol_t instance across loop iterations, which means
  // we will have left-over data in the struct. Although this won't affect
  // correctness of the result because we have '\0' at end of the strings read,
  // it would affect effectiveness of the deduplication.
  // Helper bpf_perf_prog_read_value clears the buffer on error, so here we
  // (ab)use this behavior to clear the memory. It requires the size of symbol_t
  // to be different from struct bpf_perf_event_value, which we check at
  // compilation time using the FAIL_COMPILATION_IF macro.
  // bpf_perf_prog_read_value(ctx, (struct bpf_perf_event_value *)sym, sizeof(symbol_t));

  sym->class_name[0] = '\0';
  sym->method_name[0] = '\0';
  sym->path[0] = '\0';
  sym->lineno = 0;
}

SEC("perf_event")
int walk_python_stack(struct bpf_perf_event_data *ctx) {
  u64 zero = 0;
  GET_STATE();
  GET_OFFSETS();

  LOG("=====================================================\n");
  LOG("[start] walk_python_stack");
  state->stack_walker_prog_call_count++;
  Sample *sample = &state->sample;

  int frame_count = 0;
#pragma unroll
  for (int i = 0; i < PYTHON_STACK_FRAMES_PER_PROG; i++) {
    void *cur_frame = state->frame_ptr;
    if (!cur_frame) {
      break;
    }

    // Read the code pointer. PyFrameObject.f_code
    void *cur_code_ptr;
    bpf_probe_read_user(&cur_code_ptr, sizeof(cur_code_ptr), state->frame_ptr + offsets->py_frame_object.f_code);
    if (!cur_code_ptr) {
      LOG("[error] bpf_probe_read_user failed");
      break;
    }


    LOG("## frame %d", frame_count);
    LOG("\tcur_frame_ptr 0x%llx", cur_frame);
    LOG("\tcur_code_ptr 0x%llx", cur_code_ptr);

    symbol_t sym = (symbol_t){0};
    reset_symbol(&sym);

    // Read symbol information from the code object if possible.
    read_symbol(offsets, cur_frame, cur_code_ptr, &sym);


    LOG("\tsym.path %s", sym.path);
    LOG("\tsym.class_name %s", sym.class_name);
    LOG("\tsym.method_name %s", sym.method_name);
    LOG("\tsym.lineno %d", sym.lineno);

    u64 symbol_id = get_symbol_id(&sym);
    u64 cur_len = sample->stack.len;
    if (cur_len >= 0 && cur_len < MAX_STACK_DEPTH) {
      LOG("\tstack->frames[%llu] = %llu", cur_len, symbol_id);
      sample->stack.addresses[cur_len] = symbol_id;
      sample->stack.len++;
    }
    frame_count++;

    bpf_probe_read_user(&state->frame_ptr, sizeof(state->frame_ptr), cur_frame + offsets->py_frame_object.f_back);
    if (!state->frame_ptr) {
      // There aren't any frames to read. We are done.
      goto complete;
    }
  }
  LOG("[iteration] frame_count %d", frame_count);

  LOG("state->stack_walker_prog_call_count %d", state->stack_walker_prog_call_count);
  if (state->stack_walker_prog_call_count < PYTHON_STACK_PROG_CNT) {
    LOG("[continue] walk_python_stack");
    bpf_tail_call(ctx, &programs, PYPERF_STACK_WALKING_PROGRAM_IDX);
    // state->sample.error_code = ERROR_CALL_FAILED;
    goto submit;
  }

  // TODO(kakkoyun): Stack bound checks.
  // state->stack.stack_status = cfp > state->base_stack ? STACK_COMPLETE : STACK_INCOMPLETE;
  // if (state->stack.frames.len != state->stack.expected_size) {
  //     LOG("[error] stack size %d, expected %d", state->stack.frames.len, state->stack.expected_size);
  // }

  LOG("[error] walk_python_stack TRUNCATED");
  LOG("[truncated] walk_python_stack, stack_len=%d", sample->stack.len);
  // state->sample.error_code = ERROR_NONE;
  state->sample.stack_status = STACK_TRUNCATED;
  goto submit;

complete:
  LOG("[complete] walk_python_stack, stack_len=%d", sample->stack.len);
  // state->sample.error_code = ERROR_NONE;
  state->sample.stack_status = STACK_COMPLETE;
submit:
  LOG("[stop] walk_python_stack");

  // Hash stack.
  int stack_hash = MurmurHash2((u32 *)state->sample.stack.addresses, MAX_STACK * sizeof(u64) / sizeof(u32), 0);
  LOG("[debug] stack hash: %d", stack_hash);

  // Insert stack.
  int err = bpf_map_update_elem(&interpreter_stack_traces, &stack_hash, &state->sample.stack, BPF_ANY);
  if (err != 0) {
    LOG("[error] bpf_map_update_elem with ret: %d", err);
  }

  unwind_state_t *unwind_state = bpf_map_lookup_elem(&heap, &zero);
  if (unwind_state != NULL) {
    unwind_state->stack_key.interpreter_stack_id = stack_hash;
  }

  // We are done.
  aggregate_stacks();
  return 0;
}

//
//   ╔═════════════════════════════════════════════════════════════════════════╗
//   ║ Metadata                                                                ║
//   ╚═════════════════════════════════════════════════════════════════════════╝
//
#define KBUILD_MODNAME "py-perf"
volatile const char bpf_metadata_name[] SEC(".rodata") = "py-perf";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "Dual MIT/GPL";
