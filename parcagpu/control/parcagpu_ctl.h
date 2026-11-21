// Copyright 2026 The Parca Authors
// SPDX-License-Identifier: Apache-2.0
//
// Runtime control schema between parca-agent and parcagpu, carried by procctl
// (procctl.h): the agent writes a parcagpu_ctl_config as the payload, parcagpu
// reports a parcagpu_ctl_state as its consumer state. parca-agent generates
// its Go types from this file with cgo -godefs; keep it plain C with
// fixed-width fields and no implicit padding.

#ifndef PARCAGPU_CTL_H_
#define PARCAGPU_CTL_H_

#include <stdint.h>

#define PARCAGPU_CTL_CONSUMER "parcagpu"
// 1: PC sampling and launch rate limits. 2: features. 3: pc_hw_buffer_mb,
// metadata_refresh_ms, blocking_threshold_us.
#define PARCAGPU_CTL_SCHEMA_VERSION 3
#define PARCAGPU_CTL_MAX_DEVICES 16
// The config's size in 32-bit words, room for knobs to come included.
#define PARCAGPU_CTL_CONFIG_WORDS 32

// Agent -> process. An empty payload means "not controlling": the process
// behaves as with no agent (PARCAGPU_* environment variables). Otherwise a
// granted device samples in windows of pc_sampling_window_ms with
// pc_sampling_gap_ms between them (a window opens on the first kernel launch
// after the gap), and PC sampling stays disabled on devices not granted.
struct parcagpu_ctl_config {
  uint32_t pc_sampling_devices;   // bit i: PC sample on state.devices[i]
  uint32_t pc_sampling_factor;    // CUPTI sampling period, 2^N cycles: 0 =
                                  // environment/CUPTI default, else [5,31]
  uint32_t pc_sampling_window_ms; // sampling window length; 0 = 30 ms
  uint32_t pc_sampling_gap_ms;    // pause between windows on a device
  // Launch probe rate limits, events per second per thread (as
  // PARCAGPU_RATE_LIMIT and PARCAGPU_GRAPH_RATE_LIMIT): 0 = environment/
  // default, else [1,1000000].
  uint32_t rate_limit;       // kernel launches
  uint32_t graph_rate_limit; // CUDA graph launches

  // PARCAGPU_FEATURE_* bits: optional instrumentation, off unless set.
  // Unknown bits are ignored. Schema version 2.
  uint32_t features;

  // CUPTI's PC sampling hardware buffer, MB (as PARCAGPU_PC_HW_BUFFER_MB):
  // 0 = environment/CUPTI default (512 MB), else [1,4096]. A context takes
  // the size when it is set up for PC sampling, so a change doesn't touch one
  // that is set up already until its next setup: a granted device is set up
  // again (disabled and re-enabled, as for a new factor) on its next kernel
  // launch outside a window, a device not granted when it is granted. The ack
  // comes at once, before that. On a GB10 forcing any size has made
  // cuptiPCSamplingGetData fail with CUPTI_ERROR_OUT_OF_MEMORY (see
  // pc_sampling.cpp), which is why parcagpu leaves CUPTI's default by
  // default. Schema version 3.
  uint32_t pc_hw_buffer_mb;

  // Period of the forced re-emission of cubins, the stall reason map and
  // gpu_config, ms (as PARCAGPU_METADATA_REFRESH_MS): 0 = environment/
  // default (30000), else any value (as the environment's: 1 re-emits on
  // nearly every launch). Takes effect at the next kernel launch: the period
  // is checked against the time since the last refresh, so lowering it from
  // 30 s to 1 s refreshes at once rather than waiting out the old period.
  // Not reported in the state. Schema version 3.
  uint32_t metadata_refresh_ms;

  // cuda_blocking_call threshold T, us (as PARCAGPU_BLOCKING_THRESHOLD_US):
  // 0 = environment/default (10 us), else [1,1000000]. Calls blocked at least
  // T are reported with weight = duration, shorter ones with probability
  // duration/T and weight T. The environment's 0 (every call) has no
  // equivalent here; 1 differs from it only for calls under 1 us. Takes
  // effect at the next blocking call. Stored, and without effect, while
  // PARCAGPU_FEATURE_BLOCKING_CALLS is off. Not reported in the state.
  // Schema version 3.
  uint32_t blocking_threshold_us;

  // Knobs to come. Each is 0 = default, so an agent that doesn't know one
  // leaves it alone; a process ignores those it doesn't know, so an agent
  // sets one only for a process whose schema_version (procctl's header)
  // has it. The config's size never changes.
  uint32_t reserved[PARCAGPU_CTL_CONFIG_WORDS - 10];
};

// kernel_stats: exact kernel execution counts and durations. Without an
// agent, they are counted whenever a consumer is attached to the probe.
#define PARCAGPU_FEATURE_KERNEL_STATS (1u << 0)
// cuda_blocking_call: host time blocked in CUDA API calls. Without an agent,
// on if PARCAGPU_BLOCKING_CALLS is set.
#define PARCAGPU_FEATURE_BLOCKING_CALLS (1u << 1)

enum {
  PARCAGPU_PC_OFF = 0,
  PARCAGPU_PC_ON = 1,
  PARCAGPU_PC_UNAVAILABLE = 2, // another process samples the GPU, or failed
};

// Process -> agent. Devices are appended as the process creates contexts on
// them; a slot never changes meaning.
struct parcagpu_ctl_device {
  uint8_t uuid[16];         // cuDeviceGetUuid: the same in every process
  uint32_t sampling_factor; // applied, as CUPTI reports it; 0 = not configured
  uint32_t clock_khz;
  uint32_t sm_count;
  uint32_t pc_state; // PARCAGPU_PC_*
};

struct parcagpu_ctl_state {
  uint32_t pc_capable; // contexts are set up for PC sampling
  uint32_t rate_limit; // launch probe rate limits in effect
  uint32_t graph_rate_limit;
  uint32_t num_devices;
  struct parcagpu_ctl_device devices[PARCAGPU_CTL_MAX_DEVICES];
  uint32_t features; // PARCAGPU_FEATURE_* in effect
  // PC sampling hardware buffer, MB, that contexts are set up with from now
  // on: the agent's, else PARCAGPU_PC_HW_BUFFER_MB; 0 = CUPTI's default.
  // Schema version 3.
  uint32_t pc_hw_buffer_mb;
};

#endif // PARCAGPU_CTL_H_
