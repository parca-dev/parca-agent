// Copyright (c) Facebook, Inc. and its affiliates.
// Licensed under the Apache License, Version 2.0 (the "License")
//
// Copyright 2023-2024 The Parca Authors

#include "basic_types.h"
#include "common.h"

#define PYTHON_STACK_FRAMES_PER_PROG 16
#define PYTHON_STACK_PROG_CNT 5
#define MAX_STACK (PYTHON_STACK_FRAMES_PER_PROG * PYTHON_STACK_PROG_CNT)

#define PYPERF_STACK_WALKING_PROGRAM_IDX 0

enum libc_implementation {
  LIBC_IMPLEMENTATION_GLIBC = 0,
  LIBC_IMPLEMENTATION_MUSL = 1,
};

typedef struct {
  // u64 start_time;
  u64 interpreter_addr;
  u64 thread_state_addr;
  u64 tls_key;
  u32 py_version_offset_index;
  u32 libc_offset_index;
  enum libc_implementation libc_implementation;

  _Bool use_tls;
  // TODO(kakkoyun): bool use_runtime_debug_offsets;
} InterpreterInfo;

enum python_stack_status {
  STACK_COMPLETE = 0,
  STACK_TRUNCATED = 1,
  STACK_ERROR = 2,
};

typedef struct {
  u32 pid;
  u32 tid;
  enum python_stack_status stack_status;

  stack_trace_t stack;
} Sample;

typedef unsigned long int pthread_t;

typedef struct {
  InterpreterInfo interpreter_info;

  void *thread_state;
  pthread_t current_pthread;

  // TODO: Unify naming with Ruby and CPU unwinders.
  // u64 base_stack;
  void *frame_ptr;
  int stack_walker_prog_call_count;

  Sample sample;
} State;

// Offsets of structures across different Python versions:
//
// For the most part, these fields are named after their corresponding structures in Python.
// They are depicted as structures with x86_64 offset fields named after the fields in the original structure.
// However, there are some deviations:
// 1. PyString - The offsets target the Python string object structure.
//     - Owing to the varying representation of strings across versions, which depends on encoding and interning,
//     the field names don't match those of a specific structure. Here, `data` is the offset pointing to the string's
//     first character, while `size` indicates the offset to the 32-bit integer that denotes the string's byte length
//     (not the character count).
// 2. PyRuntimeState.interp_main - This aligns with the offset of (_PyRuntimeState, interpreters.main).

typedef struct {
  s64 ob_type;
} PyObject;

typedef struct {
  s64 data;
  s64 size;
} PyString;

typedef struct {
  s64 tp_name;
} PyTypeObject;

typedef struct {
  s64 next;
  s64 interp;
  s64 frame;
  s64 thread_id;
  s64 native_thread_id;

  s64 cframe;
} PyThreadState;

typedef struct {
  // since Python 3.11 this structure holds pointer to target FrameObject.
  s64 current_frame;
} PyCFrame;

typedef struct {
  s64 tstate_head;
} PyInterpreterState;

typedef struct {
  s64 interp_main;
} PyRuntimeState;

typedef struct {
  s64 f_back;
  s64 f_code;
  s64 f_lineno;
  s64 f_localsplus;
} PyFrameObject;

typedef struct {
  s64 co_filename;
  s64 co_name;
  s64 co_varnames;
  s64 co_firstlineno;
} PyCodeObject;

typedef struct {
  s64 ob_item;
} PyTupleObject;

typedef struct {
  // TODO(kakkoyun): Change with _Py_DebugOffsets eventually.
  PyCFrame py_cframe;
  PyCodeObject py_code_object;
  PyFrameObject py_frame_object;
  PyInterpreterState py_interpreter_state;
  PyObject py_object;
  PyRuntimeState py_runtime_state;
  PyString py_string;
  PyThreadState py_thread_state;
  PyTupleObject py_tuple_object;
  PyTypeObject py_type_object;
} PythonVersionOffsets;

typedef struct {
  s64 pthread_size;
  s64 pthread_block;
  s64 pthread_key_data;
  s64 pthread_key_data_size;
} LibcOffsets;

// cpythob/Include/internal/pycore_runtime.h
typedef struct _Py_DebugOffsets {
  char cookie[8];
  uint64_t version;
  // Runtime state offset;
  struct _runtime_state {
    off_t finalizing;
    off_t interpreters_head;
  } runtime_state;

  // Interpreter state offset;
  struct _interpreter_state {
    off_t next;
    off_t threads_head;
    off_t gc;
    off_t imports_modules;
    off_t sysdict;
    off_t builtins;
    off_t ceval_gil;
    off_t gil_runtime_state_locked;
    off_t gil_runtime_state_holder;
  } interpreter_state;

  // Thread state offset;
  struct _thread_state {
    off_t prev;
    off_t next;
    off_t interp;
    off_t current_frame;
    off_t thread_id;
    off_t native_thread_id;
  } thread_state;

  // InterpreterFrame offset;
  struct _interpreter_frame {
    off_t previous;
    off_t executable;
    off_t instr_ptr;
    off_t localsplus;
    off_t owner;
  } interpreter_frame;

  // CFrame offset;
  struct _cframe {
    off_t current_frame;
    off_t previous;
  } cframe;

  // Code object offset;
  struct _code_object {
    off_t filename;
    off_t name;
    off_t linetable;
    off_t firstlineno;
    off_t argcount;
    off_t localsplusnames;
    off_t localspluskinds;
    off_t co_code_adaptive;
  } code_object;

  // PyObject offset;
  struct _pyobject {
    off_t ob_type;
  } pyobject;

  // PyTypeObject object offset;
  struct _type_object {
    off_t tp_name;
  } type_object;

  // PyTuple object offset;
  struct _tuple_object {
    off_t ob_item;
  } tuple_object;
} _Py_DebugOffsets;
