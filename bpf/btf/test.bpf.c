// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler
//
// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2022 The Parca Authors
//
#include "../vmlinux.h"
// #include "../common.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef struct event {
  int pid;
  int tgid;
  int start_time;
} event_t;

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
  __uint(max_entries, 8192);
} events SEC(".maps");

static __always_inline void send_process_info(struct bpf_perf_event_data *ctx, event_t *payload) {
  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, payload, sizeof(event_t));
}

// TODO(kakkoyun): clean up.
SEC("perf_event")
int profile_cpu(struct bpf_perf_event_data *ctx) {
  u64 pid_tgid = bpf_get_current_pid_tgid();
  int pid = pid_tgid;
  int tgid = pid_tgid >> 32;

  if (pid == 0) {
    return 0;
  }

  bpf_printk("pid=%d; tgid=%d!", pid, tgid);

  // bpf_get_current_task_btf();
  // bpf_get_current_task();
  struct task_struct *task = (void *)bpf_get_current_task();

  pid_t tpid, ttgid;
  tpid = BPF_CORE_READ(task, pid);
  ttgid = BPF_CORE_READ(task, tgid);
  ttgid = BPF_CORE_READ(task, start_time);

  bpf_printk("tpid=%d; ttgid=%d!", tpid, ttgid);

  event_t payload = {
    .pid = pid,
    .tgid = tgid,
    .start_time = ttgid,
  };
  send_process_info(ctx, &payload);


  // struct task_struct *parent_task;
  // int err;

  // err = BPF_CORE_READ_INTO(&parent_task, task, parent);
  // if (err) {
  //   bpf_printk("err=%d!", err);
  // }
  // bpf_printk("parent_task=%p!", parent_task);

  // const char *name;
  // name = BPF_CORE_READ(task, mm, exe_file, f_path.dentry, d_name.name);

  // int upid;
  // upid = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, pid_allocated);
  // bpf_printk("name=%s; pid=%d; upid=%d!", name, pid, upid);
  return 0;
}

#define KBUILD_MODNAME "parca-agent-btf-test"
volatile const char bpf_metadata_name[] SEC(".rodata") = "parca-agent-btf-test";
unsigned int VERSION SEC("version") = 1;
char LICENSE[] SEC("license") = "GPL";
