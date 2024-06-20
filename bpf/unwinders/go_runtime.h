// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler
//
// SPDX-License-Identifier: GPL-2.0-only
// Copyright 2024 The Parca Authors

#include <bpf/bpf_core_read.h>
#include "shared.h"
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

static __always_inline void *get_m_ptr(struct bpf_perf_event_data *ctx, struct go_runtime_offsets *offs, unwind_state_t *state) {
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
        return NULL;
    }
#elif __TARGET_ARCH_arm64
    g_addr = state->x28;
#endif

    void *m_ptr_addr;
    res = bpf_probe_read_user(&m_ptr_addr, sizeof(void *), (void *)(g_addr + offs->m));
    if (res < 0) {
        bpf_printk("Failed m_ptr_addr");
        return NULL;
    }

    return m_ptr_addr;
}

static __always_inline bool get_go_vdso_state(struct bpf_perf_event_data *ctx, unwind_state_t *state, struct go_runtime_offsets *offs, u64 *vdso_sp, u64 *vdso_pc) {
    long res;
    size_t m_ptr_addr = (size_t)get_m_ptr(ctx, offs, state);
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
static __always_inline bool get_custom_labels(struct bpf_perf_event_data *ctx, unwind_state_t *state, struct go_runtime_offsets *offs, custom_labels_array_t *out) {
    bpf_large_memzero((void *)out, sizeof(*out));
    long res;
    size_t m_ptr_addr = (size_t)get_m_ptr(ctx, offs, state);
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

    u64 len = 0;
    for (u64 j = 0; j < MAX_BUCKETS; j++) {
        if (j >= bucket_count) {
            break;
        }
        res = bpf_probe_read(map_value, sizeof(struct map_bucket), label_buckets + (j * sizeof(struct map_bucket)));
        if (res < 0) {
            continue;
        }
        for (int i = 0; i < 8; ++i) {
            len = opaquify64(len, bucket_count);
            if (!(len < MAX_CUSTOM_LABELS))
                return true;
            if (map_value->tophash[i] == 0)
                continue;
            u64 key_len = map_value->keys[i].len;
            u64 val_len = map_value->values[i].len;
            custom_label_t *lbl = &out->labels[len];
            lbl->key_len = key_len;
            lbl->val_len = val_len;
            if (key_len > CUSTOM_LABEL_MAX_KEY_LEN) {
                LOG("[warn] failed to read custom label: key too long");
                continue;
            }
            res = bpf_probe_read(lbl->key, key_len, map_value->keys[i].str);
            if (res) {
                LOG("[warn] failed to read key for custom label: %d", res);
                continue;
            }
            if (val_len > CUSTOM_LABEL_MAX_VAL_LEN) {
                LOG("[warn] failed to read custom label: value too long");
                continue;
            }
            // The following assembly statement is equivalent to:
            // if (val_len > CUSTOM_LABEL_MAX_VAL_LEN)
            //     res = bpf_probe_read(lbl->val, val_len, map_value->values[i].str);
            // else
            //     res = -1;
            //
            // We need to write this in assembly because the verifier doesn't understand
            // that val_len has already been bounds-checked above, apparently
            // because clang has spilled it to the stack rather than
            // keeping it in a register.
            // clang-format off
            asm volatile(
                // Note: this branch is never taken, but we
                // need it to appease the verifier.
                "if %2 > " STR(CUSTOM_LABEL_MAX_VAL_LEN) " goto bad%=\n"
                "r1 = %1\n"
                "r2 = %2\n"
                "r3 = %3\n"
                "call 4\n"
                "%0 = r0\n"
                "goto good%=\n"
                "bad%=: %0 = -1\n"
                "good%=:\n"
                : "=r"(res)
                : "r"(lbl->val), "r"(val_len), "r"(map_value->values[i].str)
                  // all r0-r5 are clobbered since we make a function call.
                : "r0", "r1", "r2", "r3", "r4", "r5", "memory"
            );
            // clang-format on
            if (res) {
                LOG("[warn] failed to read value for custom label: %d", res);
                continue;
            }
            ++len;
        }
    }

    out->len = len;
    return true;
}
