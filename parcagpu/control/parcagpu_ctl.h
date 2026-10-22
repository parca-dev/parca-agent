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
#define PARCAGPU_CTL_SCHEMA_VERSION 1
#define PARCAGPU_CTL_MAX_DEVICES 16

// Agent -> process. An empty payload means "not controlling PC sampling": the
// process behaves as with no agent (PARCAGPU_* environment variables).
struct parcagpu_ctl_config {
  uint32_t pc_sampling_devices;   // bit i: PC sample on state.devices[i]
  uint32_t pc_sampling_factor;    // CUPTI sampling period, 2^N cycles: 0 =
                                  // environment/CUPTI default, else [5,31]
  uint32_t pc_sampling_window_ms; // sampling window length; 0 = 30 ms
  uint32_t reserved;
};

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
  uint32_t num_devices;
  struct parcagpu_ctl_device devices[PARCAGPU_CTL_MAX_DEVICES];
};

#endif // PARCAGPU_CTL_H_
