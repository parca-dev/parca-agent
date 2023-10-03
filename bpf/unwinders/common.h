#ifndef __LINUX_PAGE_CONSTANTS_HACK__
#define __LINUX_PAGE_CONSTANTS_HACK__

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
  u64 len;
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
  u32 lineno;
} symbol_t;

// TODO(kakkoyun): Merge
// - SampleState, RubyStack, ProcessData, ruby_stack_status,
// with
// - State, Sample, InterpreterInfo, python_stack_status.
#endif
