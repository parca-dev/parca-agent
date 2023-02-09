// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler
//
// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors
//
#include "../common.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// TODO(kakkoyun): Actually write a function to read current task's comm and pid using BTF macros.
SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int pid = pid_tgid;
  int tgid = pid_tgid >> 32;

  if (pid == 0) {
    return 0;
  }

  // bpf_get_current_task_btf();
  // bpf_get_current_task();

  struct task_struct *task = (void *)bpf_get_current_task();

  // struct task_struct *parent_task;
  // int err;

  // err = bpf_core_read(&parent_task, sizeof(void *), &task->parent);
  // if (err) {
  // 	/* handle error */
  // }

  const char *name;
  name = BPF_CORE_READ(task, mm, exe_file, fpath.dentry, d_name.name);

  // const char *name;
  // int err;
  // err = BPF_CORE_READ_INTO(&name, t, mm, binfmt, executable, fpath.dentry, d_name.name);
  // if (err) { /* handle errors */ }

  // u32 upid = task->nsproxy->pid_ns_for_children->last_pid;
  u32 upid;
  upid = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, last_pid);

  bpf_printk("name=%s; pid=%d; upid=%d!", name, pid, upid);
  return 0;
}

#define KBUILD_MODNAME "parca-agent-btf-test"
volatile const char bpf_metadata_name[] SEC(".rodata") = "parca-agent-btf-test";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
