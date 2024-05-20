// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler
//
// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 The Parca Authors

#include "vmlinux.h"
#include "basic_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "tls.h"

struct go_runtime_offsets {
    u32 m;
    u32 vdso_sp;
    u32 vdso_pc;
    u32 curg;
    u32 labels;
    u32 hmap_count;
    u32 hmap_log_2_bucket_count;
    u32 hmap_buckets;
};

struct go_string {
    char *str;
    s64 len;
};

struct go_slice {
    void *array;
    s64 len;
    s64 cap;
};

struct map_bucket {
    char tophash[8];
    struct go_string keys[8];
    struct go_string values[8];
    void *overflow;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct map_bucket));
    __uint(max_entries, 1);
} golang_mapbucket_storage_map SEC(".maps");

// length of "otel.traceid" is 12
#define TRACEID_MAP_KEY_LENGTH 12
#define TRACEID_MAP_VAL_LENGTH 32
#define MAX_BUCKETS 8

static __always_inline bool bpf_memcmp(char *s1, char *s2, s32 size) {
    for (int i = 0; i < size; i++) {
        if (s1[i] != s2[i]) {
            return false;
        }
    }

    return true;
}

static __always_inline void hex_string_to_bytes(char *str, u32 size, unsigned char *out) {
    for (int i = 0; i < (size / 2); i++) {
        char ch0 = str[2 * i];
        char ch1 = str[2 * i + 1];
        u8 nib0 = (ch0 & 0xF) + (ch0 >> 6) | ((ch0 >> 3) & 0x8);
        u8 nib1 = (ch1 & 0xF) + (ch1 >> 6) | ((ch1 >> 3) & 0x8);
        out[i] = (nib0 << 4) | nib1;
    }
}

static __always_inline void *get_m_ptr(struct bpf_perf_event_data *ctx, struct go_runtime_offsets *offs) {
    long res;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (task == NULL) {
        return NULL;
    }

    size_t g_addr;
#if __TARGET_ARCH_x86
    u64 g_addr_offset = 0xfffffffffffffff8;
    res = bpf_probe_read_user(&g_addr, sizeof(void *), (void *)(read_tls_base(task) + g_addr_offset));
    if (res < 0) {
        bpf_printk("Failed g_addr");
        return false;
    }
#elif __TARGET_ARCH_arm64
    g_addr = ctx->regs.regs[28];
#endif

    void *m_ptr_addr;
    res = bpf_probe_read_user(&m_ptr_addr, sizeof(void *), (void *)(g_addr + offs->m));
    if (res < 0) {
        bpf_printk("Failed m_ptr_addr");
        return NULL;
    }

    return m_ptr_addr;
}

static __always_inline bool get_go_vdso_state(struct bpf_perf_event_data *ctx, struct go_runtime_offsets *offs, u64 *vdso_sp, u64 *vdso_pc) {
    long res;
    size_t m_ptr_addr = (size_t)get_m_ptr(ctx, offs);
    if (!m_ptr_addr) {
        bpf_printk("Failed to get m");
        return false;
    }

    res = bpf_probe_read_user(vdso_sp, sizeof(u64), (void *)(m_ptr_addr + offs->vdso_sp));
    if (res < 0) {
        bpf_printk("Failed sp");
        return false;
    }
    res = bpf_probe_read_user(vdso_pc, sizeof(u64), (void *)(m_ptr_addr + offs->vdso_pc));
    if (res < 0) {
        bpf_printk("Failed pc");
        return false;
    }
    return true;
}

// Go processes store the current goroutine in thread local store. From there
// this reads the g (aka goroutine) struct, then the m (the actual operating
// system thread) of that goroutine, and finally curg (current goroutine). This
// chain is necessary because getg().m.curg points to the current user g
// assigned to the thread (curg == getg() when not on the system stack). curg
// may be nil if there is no user g, such as when running in the scheduler. If
// curg is nil, then g is either a system stack (called g0) or a signal handler
// g (gsignal). Neither one will ever have labels.
static __always_inline bool get_trace_id(struct bpf_perf_event_data *ctx, struct go_runtime_offsets *offs, unsigned char *res_trace_id) {
    long res;
    size_t m_ptr_addr = (size_t)get_m_ptr(ctx, offs);
    if (!m_ptr_addr) {
        return false;
    }

    size_t curg_ptr_addr;
    res = bpf_probe_read_user(&curg_ptr_addr, sizeof(void *), (void *)(m_ptr_addr + offs->curg));
    if (res < 0) {
        return false;
    }

    void *labels_map_ptr_ptr;
    res = bpf_probe_read_user(&labels_map_ptr_ptr, sizeof(void *), (void *)(curg_ptr_addr + offs->labels));
    if (res < 0) {
        return false;
    }

    void *labels_map_ptr;
    res = bpf_probe_read(&labels_map_ptr, sizeof(labels_map_ptr), labels_map_ptr_ptr);
    if (res < 0) {
        return false;
    }

    u64 labels_count = 0;
    res = bpf_probe_read(&labels_count, sizeof(labels_count), labels_map_ptr + offs->hmap_count);
    if (res < 0) {
        return false;
    }
    if (labels_count == 0) {
        return false;
    }

    unsigned char log_2_bucket_count;
    res = bpf_probe_read(&log_2_bucket_count, sizeof(log_2_bucket_count), labels_map_ptr + offs->hmap_log_2_bucket_count);
    if (res < 0) {
        return false;
    }
    u64 bucket_count = 1 << log_2_bucket_count;
    void *label_buckets;
    res = bpf_probe_read(&label_buckets, sizeof(label_buckets), labels_map_ptr + offs->hmap_buckets);
    if (res < 0) {
        return false;
    }

    u32 map_id = 0;
    // This needs to be allocated in a per-cpu map, because it's too large and
    // can't be allocated on the stack (which is limited to 512 bytes in bpf).
    struct map_bucket *map_value = bpf_map_lookup_elem(&golang_mapbucket_storage_map, &map_id);
    if (!map_value) {
        return NULL;
    }

    for (u64 j = 0; j < MAX_BUCKETS; j++) {
        if (j >= bucket_count) {
            break;
        }
        res = bpf_probe_read(map_value, sizeof(struct map_bucket), label_buckets + (j * sizeof(struct map_bucket)));
        if (res < 0) {
            continue;
        }
        for (u64 i = 0; i < 8; i++) {
            if (map_value->tophash[i] == 0) {
                continue;
            }
            if (map_value->keys[i].len != TRACEID_MAP_KEY_LENGTH) {
                continue;
            }

            char current_label_key[TRACEID_MAP_KEY_LENGTH];
            bpf_probe_read(current_label_key, sizeof(current_label_key), map_value->keys[i].str);
            if (!bpf_memcmp(current_label_key, "otel.traceid", TRACEID_MAP_KEY_LENGTH)) {
                continue;
            }

            if (map_value->values[i].len != TRACEID_MAP_VAL_LENGTH) {
                continue;
            }

            char trace_id[TRACEID_MAP_VAL_LENGTH];
            bpf_probe_read(trace_id, TRACEID_MAP_VAL_LENGTH, map_value->values[i].str);

            hex_string_to_bytes(trace_id, TRACEID_MAP_VAL_LENGTH, res_trace_id);
            return true;
        }
    }

    return false;
}
