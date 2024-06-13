// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler
//
// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 The Parca Authors

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>

static inline __attribute__((__always_inline__)) long unsigned int read_tls_base(struct task_struct *task) {
    long unsigned int tls_base;
// This changes depending on arch and kernel version.
// task->thread.fs, task->thread.uw.tp_value, etc.
#if __TARGET_ARCH_x86
    tls_base = BPF_CORE_READ(task, thread.fsbase);
#elif __TARGET_ARCH_arm64
    tls_base = BPF_CORE_READ(task, thread.uw.tp_value);
#else
#error "Unsupported platform"
#endif
    return tls_base;
}
