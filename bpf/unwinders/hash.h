#include "shared.h"

// Avoid pulling in any other headers.
typedef unsigned int uint32_t;

// murmurhash2 from
// https://github.com/aappleby/smhasher/blob/92cf3702fcfaadc84eb7bef59825a23e0cd84f56/src/MurmurHash2.cpp

static __always_inline u64 hash_stack(stack_trace_t *stack, int seed) {
    const unsigned long long m = 0xc6a4a7935bd1e995LLU;
    const int r = 47;
    unsigned long long hash = seed ^ (stack->len * m);
    hash ^= stack->truncated;

    for (int i = 0; i < MAX_STACK_DEPTH; i++) {
        unsigned long long k = stack->addresses[i];

        k *= m;
        k ^= k >> r;
        k *= m;

        hash ^= k;
        hash *= m;
    }

    return hash;
}

#define ROUNDUP_8(x) ((x + 7) & ~7)
static __always_inline bool hash_custom_labels(custom_labels_array_t *lbls, int seed, u64 *out) {
    // apply murmurhash2 as though this is an array of
    // the number of labels (8 bytes), followed by all the key/val lengths,
    // followed by all the keys/vals.
    const u64 m = 0xc6a4a7935bd1e995LLU;
    const int r = 47;

    int len = 8;
    for (int i = 0; i < MAX_CUSTOM_LABELS; ++i) {
        if (i >= lbls->len)
            break;
        len += 8;
        len += ROUNDUP_8(lbls->labels[i].key_len);
        len += ROUNDUP_8(lbls->labels[i].val_len);
    }

    u64 h = seed ^ (len * m);

    // hash the number of labels
    {
        u64 k = lbls->len;
        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    // hash each k/v len
    for (int i = 0; i < MAX_CUSTOM_LABELS; ++i) {
        if (i >= lbls->len)
            break;
        u64 k = (((u64)lbls->labels[i].key_len) << 32) | ((u64)lbls->labels[i].val_len);
        k *= m;
        k ^= k >> r;
        k *= m;

        h ^= k;
        h *= m;
    }

    // hash each k/v
    for (int i = 0; i < MAX_CUSTOM_LABELS; ++i) {
        if (i >= lbls->len)
            break;
        custom_label_t *lbl = &lbls->labels[i];
        u64 kl = ROUNDUP_8(lbl->key_len);
        for (int j = 0; j < CUSTOM_LABEL_MAX_VAL_LEN / 8; ++j) {
            if (j >= kl)
                return false;
            u64 k = lbl->key[j];
            k *= m;
            k ^= k >> r;
            k *= m;

            h ^= k;
            h *= m;
        }
        u64 vl = ROUNDUP_8(lbl->val_len);
        for (int j = 0; j < CUSTOM_LABEL_MAX_VAL_LEN / 8; ++j) {
            if (j >= vl)
                return false;
            u64 k = lbl->val[j];
            k *= m;
            k ^= k >> r;
            k *= m;

            h ^= k;
            h *= m;
        }
    }

    h ^= h >> r;
    h *= m;
    h ^= h >> r;

    *out = h;
    return true;
}
#undef ROUNDUP_8
