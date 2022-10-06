// Maximum value an `unsigned long int' can hold.  (Minimum is 0.)
#if __WORDSIZE == 64
#define ULONG_MAX 18446744073709551615UL
#else
#define ULONG_MAX 4294967295UL
#endif

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;

typedef int __s32;

typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u64 u64;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;


typedef __s32 s32;
typedef __s64 s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef _Bool bool;
typedef u64 phys_addr_t;

typedef int __kernel_pid_t;
typedef __kernel_pid_t pid_t;

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
};

enum {
	BPF_F_SKIP_FIELD_MASK = 255,
	BPF_F_USER_STACK = 256,
	BPF_F_FAST_STACK_CMP = 512,
	BPF_F_REUSE_STACKID = 1024,
	BPF_F_USER_BUILD_ID = 2048,
};

enum {
	BPF_F_INDEX_MASK = 4294967295,
	BPF_F_CURRENT_CPU = 4294967295,
	BPF_F_CTXLEN_MASK = 0,
};

struct pt_regs {
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
	long unsigned int r12;
	long unsigned int bp;
	long unsigned int bx;
	long unsigned int r11;
	long unsigned int r10;
	long unsigned int r9;
	long unsigned int r8;
	long unsigned int ax;
	long unsigned int cx;
	long unsigned int dx;
	long unsigned int si;
	long unsigned int di;
	long unsigned int orig_ax;
	long unsigned int ip;
	long unsigned int cs;
	long unsigned int flags;
	long unsigned int sp;
	long unsigned int ss;
};

typedef struct pt_regs bpf_user_pt_regs_t;

struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
};
