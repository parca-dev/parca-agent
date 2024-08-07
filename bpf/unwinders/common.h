#ifndef __LINUX_PAGE_CONSTANTS_HACK__
#define __LINUX_PAGE_CONSTANTS_HACK__

// see https://gcc.gnu.org/onlinedocs/cpp/Stringizing.html#Stringizing
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

// Values for x86_64 as of 6.0.18-200.
#define TOP_OF_KERNEL_STACK_PADDING 0
#define THREAD_SIZE_ORDER 2
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define THREAD_SIZE (PAGE_SIZE << THREAD_SIZE_ORDER)

#endif

#ifndef __ERROR_CONSTANTS_HACK__
#define __ERROR_CONSTANTS_HACK__

#define EFAULT 14
#define EEXIST 17
#endif

#ifndef __AGENT_STACK_TRACE_DEFINITION__
#define __AGENT_STACK_TRACE_DEFINITION__

#include "basic_types.h"
#define MAX_STACK_DEPTH 127

typedef struct {
    u32 len;
    bool truncated;
    u64 addresses[MAX_STACK_DEPTH];
} stack_trace_t;
// NOTICE: stack_t is defined in vmlinux.h.

#define CLASS_NAME_MAXLEN 32
#define METHOD_MAXLEN 64
#define PATH_MAXLEN 128

typedef struct {
    char class_name[CLASS_NAME_MAXLEN];
    char method_name[METHOD_MAXLEN];
    char path[PATH_MAXLEN];
    // Only set for errors.
    u8 bpf_program_id_plus_one;
} symbol_t;

// Programs.
#define NATIVE_UNWINDER_PROGRAM_ID 0
#define RUBY_UNWINDER_PROGRAM_ID 1
#define PYTHON_UNWINDER_PROGRAM_ID 2
#define JAVA_UNWINDER_PROGRAM_ID 3
#define LUA_UNWINDER_PROGRAM_ID 4

typedef struct {
    symbol_t sym;
    u32 line;
} error_t;

#define ENABLE_ADDRESSES_IN_ERRORS false

#define ERROR_HEX(_e, msg, val)                                                        \
    ({                                                                                 \
        _Static_assert(sizeof(msg) + 16 < sizeof(_e->sym.class_name), "msg too long"); \
        ERROR_MSG(_e, msg);                                                            \
        if (ENABLE_ADDRESSES_IN_ERRORS) {                                              \
            __builtin_strncpy(&err_ctx->sym.class_name[sizeof(msg) - 1], ":0x", 3);    \
            append_as_hex(&err_ctx->sym.class_name[sizeof(msg) + 2], val);             \
        }                                                                              \
    })

#define ERROR_MSG(_e, msg)                                                                 \
    ({                                                                                     \
        __builtin_strncpy(_e->sym.path, __FILE__, sizeof(_e->sym.path));                   \
        __builtin_strncpy(_e->sym.method_name, __FUNCTION__, sizeof(_e->sym.method_name)); \
        __builtin_strncpy(_e->sym.class_name, msg, sizeof(_e->sym.class_name));            \
        _e->line = __LINE__;                                                               \
        _e->sym.bpf_program_id_plus_one = BPF_PROGRAM + 1;                                 \
    })

// Use ERROR_SAMPLE to report one stack frame of an error message as an interpreter symbol.
// class -> msg provided in macro
// function -> __FUNCTION__ from C compiler
// line     -> __LINE__ from C compiler
// file     -> __FILE__ from C compiler
// Most uses should just return after calling this.
#define ERROR_SAMPLE(unw_state, _e)                                                   \
    ({                                                                                \
        __builtin_memset((void *)&unw_state->stack, 0, sizeof(stack_trace_t));        \
        u64 id = get_symbol_id(&_e->sym);                                             \
        u64 line = _e->line;                                                          \
        add_frame(unw_state, (line << 32) | id);                                      \
        u64 stack_id = hash_stack(&unw_state->stack, 0);                              \
        unw_state->stack_key.interpreter_stack_id = stack_id;                         \
        bpf_map_update_elem(&stack_traces, &stack_id, &unwind_state->stack, BPF_ANY); \
        aggregate_stacks();                                                           \
    })
// These must be divisible by 8
#define CUSTOM_LABEL_MAX_KEY_LEN 64
#define CUSTOM_LABEL_MAX_VAL_LEN 64

typedef struct custom_label {
    unsigned key_len;
    unsigned val_len;
    // If we use unaligned `unsigned char` instead of `u64`
    // buffers, the hash function becomes too complex to verify.
    u64 key[CUSTOM_LABEL_MAX_KEY_LEN / 8];
    u64 val[CUSTOM_LABEL_MAX_VAL_LEN / 8];
} custom_label_t;

#define MAX_CUSTOM_LABELS 16

typedef struct custom_labels_array {
    int len;
    struct custom_label labels[MAX_CUSTOM_LABELS];
} custom_labels_array_t;
#endif
