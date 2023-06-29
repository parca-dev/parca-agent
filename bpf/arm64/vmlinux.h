// Git revision: 1ef6663a587ba3e57dc5065a477db1c64481eedd
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef unsigned int __u32;

typedef __u32 u32;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef short unsigned int umode_t;

enum umh_disable_depth {
	UMH_ENABLED = 0,
	UMH_FREEZING = 1,
	UMH_DISABLED = 2,
};

enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK = 0,
	PERF_COUNT_SW_TASK_CLOCK = 1,
	PERF_COUNT_SW_PAGE_FAULTS = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
	PERF_COUNT_SW_EMULATION_FAULTS = 8,
	PERF_COUNT_SW_DUMMY = 9,
	PERF_COUNT_SW_BPF_OUTPUT = 10,
	PERF_COUNT_SW_CGROUP_SWITCHES = 11,
	PERF_COUNT_SW_MAX = 12,
};

enum {
	TRACE_EVENT_FL_FILTERED_BIT = 0,
	TRACE_EVENT_FL_CAP_ANY_BIT = 1,
	TRACE_EVENT_FL_NO_SET_FILTER_BIT = 2,
	TRACE_EVENT_FL_IGNORE_ENABLE_BIT = 3,
	TRACE_EVENT_FL_TRACEPOINT_BIT = 4,
	TRACE_EVENT_FL_DYNAMIC_BIT = 5,
	TRACE_EVENT_FL_KPROBE_BIT = 6,
	TRACE_EVENT_FL_UPROBE_BIT = 7,
	TRACE_EVENT_FL_EPROBE_BIT = 8,
	TRACE_EVENT_FL_CUSTOM_BIT = 9,
};

enum {
	EVENT_FILE_FL_ENABLED_BIT = 0,
	EVENT_FILE_FL_RECORDED_CMD_BIT = 1,
	EVENT_FILE_FL_RECORDED_TGID_BIT = 2,
	EVENT_FILE_FL_FILTERED_BIT = 3,
	EVENT_FILE_FL_NO_SET_FILTER_BIT = 4,
	EVENT_FILE_FL_SOFT_MODE_BIT = 5,
	EVENT_FILE_FL_SOFT_DISABLED_BIT = 6,
	EVENT_FILE_FL_TRIGGER_MODE_BIT = 7,
	EVENT_FILE_FL_TRIGGER_COND_BIT = 8,
	EVENT_FILE_FL_PID_FILTER_BIT = 9,
	EVENT_FILE_FL_WAS_ENABLED_BIT = 10,
};

typedef signed char __s8;

typedef unsigned char __u8;

typedef short unsigned int __u16;

typedef int __s32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __u16 u16;

typedef __s32 s32;

typedef __s64 s64;

typedef __u64 u64;

enum {
	false = 0,
	true = 1,
};

typedef long int __kernel_long_t;

typedef long unsigned int __kernel_ulong_t;

typedef int __kernel_pid_t;

typedef unsigned int __kernel_uid32_t;

typedef unsigned int __kernel_gid32_t;

typedef __kernel_ulong_t __kernel_size_t;

typedef __kernel_long_t __kernel_ssize_t;

typedef long long int __kernel_loff_t;

typedef long long int __kernel_time64_t;

typedef __kernel_long_t __kernel_clock_t;

typedef int __kernel_timer_t;

typedef int __kernel_clockid_t;

typedef __u32 __le32;

typedef unsigned int __poll_t;

typedef __kernel_pid_t pid_t;

typedef __kernel_clockid_t clockid_t;

typedef _Bool bool;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef long unsigned int uintptr_t;

typedef __kernel_loff_t loff_t;

typedef __kernel_size_t size_t;

typedef __kernel_ssize_t ssize_t;

typedef u32 uint32_t;

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef unsigned int gfp_t;

typedef unsigned int fmode_t;

typedef u64 phys_addr_t;

typedef struct {
	int counter;
} atomic_t;

typedef struct {
	s64 counter;
} atomic64_t;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct hlist_node;

struct hlist_head {
	struct hlist_node *first;
};

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

struct kernel_symbol {
	int value_offset;
	int name_offset;
	int namespace_offset;
};

struct lock_class_key {};

struct fs_context;

struct fs_parameter_spec;

struct dentry;

struct super_block;

struct module;

struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry * (*mount)(struct file_system_type *, int, const char *, void *);
	void (*kill_sb)(struct super_block *);
	struct module *owner;
	struct file_system_type *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

typedef atomic64_t atomic_long_t;

struct qspinlock {
	union {
		atomic_t val;
		struct {
			u8 locked;
			u8 pending;
		};
		struct {
			u16 locked_pending;
			u16 tail;
		};
	};
};

typedef struct qspinlock arch_spinlock_t;

struct qrwlock {
	union {
		atomic_t cnts;
		struct {
			u8 wlocked;
			u8 __lstate[3];
		};
	};
	arch_spinlock_t wait_lock;
};

typedef struct qrwlock arch_rwlock_t;

struct lockdep_map {};

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct raw_spinlock raw_spinlock_t;

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	long unsigned int begin;
	long unsigned int flags;
};

typedef void *fl_owner_t;

struct file;

struct kiocb;

struct iov_iter;

struct io_comp_batch;

struct dir_context;

struct poll_table_struct;

struct vm_area_struct;

struct inode;

struct file_lock;

struct page;

struct pipe_inode_info;

struct seq_file;

struct io_uring_cmd;

struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file *, struct dir_context *);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long int (*unlocked_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap)(struct file *, struct vm_area_struct *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	ssize_t (*sendpage)(struct file *, struct page *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long int, struct file_lock **, void **);
	long int (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
	int (*uring_cmd)(struct io_uring_cmd *, unsigned int);
	int (*uring_cmd_iopoll)(struct io_uring_cmd *, struct io_comp_batch *, unsigned int);
};

struct static_key {
	atomic_t enabled;
};

struct static_call_key {
	void *func;
};

struct user_pt_regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
};

struct user_fpsimd_state {
	__int128 unsigned vregs[32];
	__u32 fpsr;
	__u32 fpcr;
	__u32 __reserved[2];
};

struct user_sve_header {
	__u32 size;
	__u32 max_size;
	__u16 vl;
	__u16 max_vl;
	__u16 flags;
	__u16 __reserved;
};

struct user_pac_mask {
	__u64 data_mask;
	__u64 insn_mask;
};

struct user_za_header {
	__u32 size;
	__u32 max_size;
	__u16 vl;
	__u16 max_vl;
	__u16 flags;
	__u16 __reserved;
};

struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
	u64 orig_x0;
	s32 syscallno;
	u32 unused2;
	u64 sdei_ttbr1;
	u64 pmr_save;
	u64 stackframe[2];
	u64 lockdep_hardirqs;
	u64 exit_rcu;
};

typedef __s64 time64_t;

struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};

struct timespec64 {
	time64_t tv_sec;
	long int tv_nsec;
};

enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

typedef s32 old_time32_t;

struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};

struct pollfd {
	int fd;
	short int events;
	short int revents;
};

struct restart_block {
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union {
		struct {
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};

struct thread_info {
	long unsigned int flags;
	union {
		u64 preempt_count;
		struct {
			u32 count;
			u32 need_resched;
		} preempt;
	};
	u32 cpu;
};

struct cpumask {
	long unsigned int bits[4];
};

typedef struct cpumask cpumask_t;

typedef struct cpumask cpumask_var_t[1];

struct llist_node;

struct llist_head {
	struct llist_node *first;
};

struct llist_node {
	struct llist_node *next;
};

struct __call_single_node {
	struct llist_node llist;
	union {
		unsigned int u_flags;
		atomic_t a_flags;
	};
	u16 src;
	u16 dst;
};

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

struct load_weight {
	long unsigned int weight;
	u32 inv_weight;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct util_est {
	unsigned int enqueued;
	unsigned int ewma;
};

struct sched_avg {
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_sum;
	u32 util_sum;
	u32 period_contrib;
	long unsigned int load_avg;
	long unsigned int runnable_avg;
	long unsigned int util_avg;
	struct util_est util_est;
};

struct sched_entity {
	struct load_weight load;
	struct rb_node run_node;
	struct list_head group_node;
	unsigned int on_rq;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 vruntime;
	u64 prev_sum_exec_runtime;
	u64 nr_migrations;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg;
};

struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
};

typedef s64 ktime_t;

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
};

struct sched_dl_entity {
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled: 1;
	unsigned int dl_yielded: 1;
	unsigned int dl_non_contending: 1;
	unsigned int dl_overrun: 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
};

struct sched_statistics {};

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};

struct sched_info {};

struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};

struct posix_cputimers {};

typedef struct {
	long unsigned int sig[1];
} sigset_t;

struct sigpending {
	struct list_head list;
	sigset_t signal;
};

struct seccomp {};

struct syscall_user_dispatch {};

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

struct wake_q_node {
	struct wake_q_node *next;
};

struct task_io_accounting {};

struct optimistic_spin_queue {
	atomic_t tail;
};

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct optimistic_spin_queue osq;
	struct list_head wait_list;
};

struct tlbflush_unmap_batch {};

struct page_frag {
	struct page *page;
	__u32 offset;
	__u32 size;
};

struct kmap_ctrl {};

struct timer_list {
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
};

struct cpu_context {
	long unsigned int x19;
	long unsigned int x20;
	long unsigned int x21;
	long unsigned int x22;
	long unsigned int x23;
	long unsigned int x24;
	long unsigned int x25;
	long unsigned int x26;
	long unsigned int x27;
	long unsigned int x28;
	long unsigned int fp;
	long unsigned int sp;
	long unsigned int pc;
};

enum fp_type {
	FP_STATE_CURRENT = 0,
	FP_STATE_FPSIMD = 1,
	FP_STATE_SVE = 2,
};

struct perf_event;

struct debug_info {
	int suspended_step;
	int bps_disabled;
	int wps_disabled;
	struct perf_event *hbp_break[16];
	struct perf_event *hbp_watch[16];
};

struct ptrauth_key {
	long unsigned int lo;
	long unsigned int hi;
};

struct ptrauth_keys_user {
	struct ptrauth_key apia;
	struct ptrauth_key apib;
	struct ptrauth_key apda;
	struct ptrauth_key apdb;
	struct ptrauth_key apga;
};

struct ptrauth_keys_kernel {
	struct ptrauth_key apia;
};

struct thread_struct {
	struct cpu_context cpu_context;
	long: 64;
	struct {
		long unsigned int tp_value;
		long unsigned int tp2_value;
		struct user_fpsimd_state fpsimd_state;
	} uw;
	enum fp_type fp_type;
	unsigned int fpsimd_cpu;
	void *sve_state;
	void *sme_state;
	unsigned int vl[2];
	unsigned int vl_onexec[2];
	long unsigned int fault_address;
	long unsigned int fault_code;
	struct debug_info debug;
	struct ptrauth_keys_user keys_user;
	struct ptrauth_keys_kernel keys_kernel;
	u64 mte_ctrl;
	u64 sctlr_user;
	u64 svcr;
	u64 tpidr2_el0;
	long: 64;
};

struct sched_class;

struct mm_struct;

struct pid;

struct completion;

struct cred;

struct nameidata;

struct fs_struct;

struct files_struct;

struct nsproxy;

struct signal_struct;

struct sighand_struct;

struct bio_list;

struct blk_plug;

struct reclaim_state;

struct backing_dev_info;

struct io_context;

struct kernel_siginfo;

typedef struct kernel_siginfo kernel_siginfo_t;

struct perf_event_context;

struct ftrace_ret_stack;

struct uprobe_task;

struct vm_struct;

struct bpf_local_storage;

struct bpf_run_ctx;

struct task_struct {
	struct thread_info thread_info;
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_cpu;
	struct __call_single_node wake_entry;
	unsigned int wakee_flips;
	long unsigned int wakee_flip_decay_ts;
	struct task_struct *last_wakee;
	int recent_used_cpu;
	int wake_cpu;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_statistics stats;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_disabled;
	short unsigned int migration_flags;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	struct list_head trc_holdout_list;
	struct list_head trc_blkd_node;
	int trc_blkd_cpu;
	struct sched_info sched_info;
	struct list_head tasks;
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	long: 29;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	char comm[16];
	struct nameidata *nameidata;
	struct fs_struct *fs;
	struct files_struct *files;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info *backing_dev_info;
	struct io_context *io_context;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	struct perf_event_context *perf_event_ctxp;
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	struct tlbflush_unmap_batch tlb_ubc;
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	int curr_ret_stack;
	int curr_ret_depth;
	struct ftrace_ret_stack *ret_stack;
	long long unsigned int ftrace_timestamp;
	atomic_t trace_overrun;
	atomic_t tracing_graph_pause;
	long unsigned int trace_recursion;
	struct uprobe_task *utask;
	struct kmap_ctrl kmap_ctrl;
	struct callback_head rcu;
	refcount_t rcu_users;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct vm_struct *stack_vm_area;
	refcount_t stack_refcount;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	struct llist_head kretprobe_instances;
	struct thread_struct thread;
};

struct arch_hw_breakpoint_ctrl {
	u32 __reserved: 19;
	u32 len: 8;
	u32 type: 2;
	u32 privilege: 2;
	u32 enabled: 1;
};

struct arch_hw_breakpoint {
	u64 address;
	u64 trigger;
	struct arch_hw_breakpoint_ctrl ctrl;
};

typedef u64 pteval_t;

typedef u64 pmdval_t;

typedef u64 pgdval_t;

typedef struct {
	pteval_t pte;
} pte_t;

typedef struct {
	pmdval_t pmd;
} pmd_t;

typedef struct {
	pgdval_t pgd;
} pgd_t;

typedef struct {
	pteval_t pgprot;
} pgprot_t;

typedef struct {
	pgd_t pgd;
} p4d_t;

typedef struct {
	p4d_t p4d;
} pud_t;

enum perf_event_state {
	PERF_EVENT_STATE_DEAD = -4,
	PERF_EVENT_STATE_EXIT = -3,
	PERF_EVENT_STATE_ERROR = -2,
	PERF_EVENT_STATE_OFF = -1,
	PERF_EVENT_STATE_INACTIVE = 0,
	PERF_EVENT_STATE_ACTIVE = 1,
};

typedef struct {
	atomic_long_t a;
} local_t;

typedef struct {
	local_t a;
} local64_t;

struct perf_event_attr {
	__u32 type;
	__u32 size;
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 disabled: 1;
	__u64 inherit: 1;
	__u64 pinned: 1;
	__u64 exclusive: 1;
	__u64 exclude_user: 1;
	__u64 exclude_kernel: 1;
	__u64 exclude_hv: 1;
	__u64 exclude_idle: 1;
	__u64 mmap: 1;
	__u64 comm: 1;
	__u64 freq: 1;
	__u64 inherit_stat: 1;
	__u64 enable_on_exec: 1;
	__u64 task: 1;
	__u64 watermark: 1;
	__u64 precise_ip: 2;
	__u64 mmap_data: 1;
	__u64 sample_id_all: 1;
	__u64 exclude_host: 1;
	__u64 exclude_guest: 1;
	__u64 exclude_callchain_kernel: 1;
	__u64 exclude_callchain_user: 1;
	__u64 mmap2: 1;
	__u64 comm_exec: 1;
	__u64 use_clockid: 1;
	__u64 context_switch: 1;
	__u64 write_backward: 1;
	__u64 namespaces: 1;
	__u64 ksymbol: 1;
	__u64 bpf_event: 1;
	__u64 aux_output: 1;
	__u64 cgroup: 1;
	__u64 text_poke: 1;
	__u64 build_id: 1;
	__u64 inherit_thread: 1;
	__u64 remove_on_exec: 1;
	__u64 sigtrap: 1;
	__u64 __reserved_1: 26;
	union {
		__u32 wakeup_events;
		__u32 wakeup_watermark;
	};
	__u32 bp_type;
	union {
		__u64 bp_addr;
		__u64 kprobe_func;
		__u64 uprobe_path;
		__u64 config1;
	};
	union {
		__u64 bp_len;
		__u64 kprobe_addr;
		__u64 probe_offset;
		__u64 config2;
	};
	__u64 branch_sample_type;
	__u64 sample_regs_user;
	__u32 sample_stack_user;
	__s32 clockid;
	__u64 sample_regs_intr;
	__u32 aux_watermark;
	__u16 sample_max_stack;
	__u16 __reserved_2;
	__u32 aux_sample_size;
	__u32 __reserved_3;
	__u64 sig_data;
	__u64 config3;
};

struct hw_perf_event_extra {
	u64 config;
	unsigned int reg;
	int alloc;
	int idx;
};

struct rhash_head {
	struct rhash_head *next;
};

struct rhlist_head {
	struct rhash_head rhead;
	struct rhlist_head *next;
};

struct hw_perf_event {
	union {
		struct {
			u64 config;
			u64 last_tag;
			long unsigned int config_base;
			long unsigned int event_base;
			int event_base_rdpmc;
			int idx;
			int last_cpu;
			int flags;
			struct hw_perf_event_extra extra_reg;
			struct hw_perf_event_extra branch_reg;
		};
		struct {
			struct hrtimer hrtimer;
		};
		struct {
			struct list_head tp_list;
		};
		struct {
			u64 pwr_acc;
			u64 ptsc;
		};
		struct {
			struct arch_hw_breakpoint info;
			struct rhlist_head bp_list;
		};
		struct {
			u8 iommu_bank;
			u8 iommu_cntr;
			u16 padding;
			u64 conf;
			u64 conf1;
		};
	};
	struct task_struct *target;
	void *addr_filters;
	long unsigned int addr_filters_gen;
	int state;
	local64_t prev_count;
	u64 sample_period;
	union {
		struct {
			u64 last_period;
			local64_t period_left;
		};
		struct {
			u64 saved_metric;
			u64 saved_slots;
		};
	};
	u64 interrupts_seq;
	u64 interrupts;
	u64 freq_time_stamp;
	u64 freq_count_stamp;
};

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

struct rcuwait {
	struct task_struct *task;
};

struct irq_work {
	struct __call_single_node node;
	void (*func)(struct irq_work *);
	struct rcuwait irqwait;
};

struct perf_addr_filters_head {
	struct list_head list;
	raw_spinlock_t lock;
	unsigned int nr_file_filters;
};

struct perf_sample_data;

typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);

struct ftrace_ops;

struct ftrace_regs;

typedef void (*ftrace_func_t)(long unsigned int, long unsigned int, struct ftrace_ops *, struct ftrace_regs *);

struct ftrace_hash;

struct ftrace_ops_hash {
	struct ftrace_hash *notrace_hash;
	struct ftrace_hash *filter_hash;
	struct mutex regex_lock;
};

enum ftrace_ops_cmd {
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_SELF = 0,
	FTRACE_OPS_CMD_ENABLE_SHARE_IPMODIFY_PEER = 1,
	FTRACE_OPS_CMD_DISABLE_SHARE_IPMODIFY_PEER = 2,
};

typedef int (*ftrace_ops_func_t)(struct ftrace_ops *, enum ftrace_ops_cmd);

struct ftrace_ops {
	ftrace_func_t func;
	struct ftrace_ops *next;
	long unsigned int flags;
	void *private;
	ftrace_func_t saved_func;
	struct ftrace_ops_hash local_hash;
	struct ftrace_ops_hash *func_hash;
	struct ftrace_ops_hash old_hash;
	long unsigned int trampoline;
	long unsigned int trampoline_size;
	struct list_head list;
	ftrace_ops_func_t ops_func;
};

struct pmu;

struct perf_event_pmu_context;

struct perf_buffer;

struct fasync_struct;

struct perf_addr_filter_range;

struct pid_namespace;

struct bpf_prog;

struct trace_event_call;

struct event_filter;

struct perf_event {
	struct list_head event_entry;
	struct list_head sibling_list;
	struct list_head active_list;
	struct rb_node group_node;
	u64 group_index;
	struct list_head migrate_entry;
	struct hlist_node hlist_entry;
	struct list_head active_entry;
	int nr_siblings;
	int event_caps;
	int group_caps;
	struct perf_event *group_leader;
	struct pmu *pmu;
	void *pmu_private;
	enum perf_event_state state;
	unsigned int attach_state;
	local64_t count;
	atomic64_t child_count;
	u64 total_time_enabled;
	u64 total_time_running;
	u64 tstamp;
	struct perf_event_attr attr;
	u16 header_size;
	u16 id_header_size;
	u16 read_size;
	struct hw_perf_event hw;
	struct perf_event_context *ctx;
	struct perf_event_pmu_context *pmu_ctx;
	atomic_long_t refcount;
	atomic64_t child_total_time_enabled;
	atomic64_t child_total_time_running;
	struct mutex child_mutex;
	struct list_head child_list;
	struct perf_event *parent;
	int oncpu;
	int cpu;
	struct list_head owner_entry;
	struct task_struct *owner;
	struct mutex mmap_mutex;
	atomic_t mmap_count;
	struct perf_buffer *rb;
	struct list_head rb_entry;
	long unsigned int rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	unsigned int pending_wakeup;
	unsigned int pending_kill;
	unsigned int pending_disable;
	unsigned int pending_sigtrap;
	long unsigned int pending_addr;
	struct irq_work pending_irq;
	struct callback_head pending_task;
	unsigned int pending_work;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
	struct perf_event *aux_event;
	void (*destroy)(struct perf_event *);
	struct callback_head callback_head;
	struct pid_namespace *ns;
	u64 id;
	atomic64_t lost_samples;
	u64 (*clock)();
	perf_overflow_handler_t overflow_handler;
	void *overflow_handler_context;
	perf_overflow_handler_t orig_overflow_handler;
	struct bpf_prog *prog;
	u64 bpf_cookie;
	struct trace_event_call *tp_event;
	struct event_filter *filter;
	struct ftrace_ops ftrace_ops;
	struct list_head sb_list;
};

enum vec_type {
	ARM64_VEC_SVE = 0,
	ARM64_VEC_SME = 1,
	ARM64_VEC_MAX = 2,
};

struct vl_info {
	enum vec_type type;
	const char *name;
	int min_vl;
	int max_vl;
	int max_virtualisable_vl;
	long unsigned int vq_map[8];
	long unsigned int vq_partial_map[8];
};

typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};

struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};

struct proc_ns_operations;

struct ns_common {
	atomic_long_t stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};

struct kmem_cache;

struct user_namespace;

struct ucounts;

struct pid_namespace {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
};

struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid numbers[1];
};

struct uid_gid_extent {
	u32 first;
	u32 lower_first;
	u32 count;
};

struct uid_gid_map {
	u32 nr_extents;
	union {
		struct uid_gid_extent extent[5];
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

typedef struct {
	uid_t val;
} kuid_t;

typedef struct {
	gid_t val;
} kgid_t;

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};

struct user_namespace {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	struct uid_gid_map projid_map;
	struct user_namespace *parent;
	int level;
	kuid_t owner;
	kgid_t group;
	struct ns_common ns;
	long unsigned int flags;
	bool parent_could_setfcap;
	struct work_struct work;
	struct ucounts *ucounts;
	long int ucount_max[8];
	long int rlimit_max[4];
};

struct workqueue_struct;

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};

typedef struct page *pgtable_t;

struct address_space;

struct page_pool;

struct dev_pagemap;

struct page {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			struct address_space *mapping;
			union {
				long unsigned int index;
				long unsigned int share;
			};
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	long: 64;
};

struct rb_root {
	struct rb_node *rb_node;
};

struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

struct seqcount {
	unsigned int sequence;
};

typedef struct seqcount seqcount_t;

struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

struct timerqueue_head {
	struct rb_root_cached rb_root;
};

struct hrtimer_cpu_base;

struct hrtimer_clock_base {
	struct hrtimer_cpu_base *cpu_base;
	unsigned int index;
	clockid_t clockid;
	seqcount_raw_spinlock_t seq;
	struct hrtimer *running;
	struct timerqueue_head active;
	ktime_t (*get_time)();
	ktime_t offset;
};

struct hrtimer_cpu_base {
	raw_spinlock_t lock;
	unsigned int cpu;
	unsigned int active_bases;
	unsigned int clock_was_set_seq;
	unsigned int hres_active: 1;
	unsigned int in_hrtirq: 1;
	unsigned int hang_detected: 1;
	unsigned int softirq_activated: 1;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	long: 64;
	struct hrtimer_clock_base clock_base[8];
};

struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t();

typedef __restorefn_t *__sigrestore_t;

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef union sigval sigval_t;

union __sifields {
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
	} _kill;
	struct {
		__kernel_timer_t _tid;
		int _overrun;
		sigval_t _sigval;
		int _sys_private;
	} _timer;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		sigval_t _sigval;
	} _rt;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		int _status;
		__kernel_clock_t _utime;
		__kernel_clock_t _stime;
	} _sigchld;
	struct {
		void *_addr;
		union {
			int _trapno;
			short int _addr_lsb;
			struct {
				char _dummy_bnd[8];
				void *_lower;
				void *_upper;
			} _addr_bnd;
			struct {
				char _dummy_pkey[8];
				__u32 _pkey;
			} _addr_pkey;
			struct {
				long unsigned int _data;
				__u32 _type;
				__u32 _flags;
			} _perf;
		};
	} _sigfault;
	struct {
		long int _band;
		int _fd;
	} _sigpoll;
	struct {
		void *_call_addr;
		int _syscall;
		unsigned int _arch;
	} _sigsys;
};

struct kernel_siginfo {
	struct {
		int si_signo;
		int si_errno;
		int si_code;
		union __sifields _sifields;
	};
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[8];
	atomic_long_t rlimit[4];
};

struct sigaction {
	__sighandler_t sa_handler;
	long unsigned int sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

struct k_sigaction {
	struct sigaction sa;
};

struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	struct optimistic_spin_queue osq;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct core_state;

struct tty_struct;

struct signal_struct {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	int quick_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct rq;

struct rq_flags;

struct affinity_context;

struct sched_class {
	void (*enqueue_task)(struct rq *, struct task_struct *, int);
	void (*dequeue_task)(struct rq *, struct task_struct *, int);
	void (*yield_task)(struct rq *);
	bool (*yield_to_task)(struct rq *, struct task_struct *);
	void (*check_preempt_curr)(struct rq *, struct task_struct *, int);
	struct task_struct * (*pick_next_task)(struct rq *);
	void (*put_prev_task)(struct rq *, struct task_struct *);
	void (*set_next_task)(struct rq *, struct task_struct *, bool);
	int (*balance)(struct rq *, struct task_struct *, struct rq_flags *);
	int (*select_task_rq)(struct task_struct *, int, int);
	struct task_struct * (*pick_task)(struct rq *);
	void (*migrate_task_rq)(struct task_struct *, int);
	void (*task_woken)(struct rq *, struct task_struct *);
	void (*set_cpus_allowed)(struct task_struct *, struct affinity_context *);
	void (*rq_online)(struct rq *);
	void (*rq_offline)(struct rq *);
	struct rq * (*find_lock_rq)(struct task_struct *, struct rq *);
	void (*task_tick)(struct rq *, struct task_struct *, int);
	void (*task_fork)(struct task_struct *);
	void (*task_dead)(struct task_struct *);
	void (*switched_from)(struct rq *, struct task_struct *);
	void (*switched_to)(struct rq *, struct task_struct *);
	void (*prio_changed)(struct rq *, struct task_struct *, int);
	unsigned int (*get_rr_interval)(struct rq *, struct task_struct *);
	void (*update_curr)(struct rq *);
};

typedef struct {} lockdep_map_p;

struct maple_tree {
	union {
		spinlock_t ma_lock;
		lockdep_map_p ma_external_lock;
	};
	void *ma_root;
	unsigned int ma_flags;
};

struct percpu_counter {
	raw_spinlock_t lock;
	s64 count;
	struct list_head list;
	s32 *counters;
};

typedef struct {
	atomic64_t id;
	refcount_t pinned;
	void *vdso;
	long unsigned int flags;
} mm_context_t;

struct xol_area;

struct uprobes_state {
	struct xol_area *xol_area;
};

struct linux_binfmt;

struct mm_struct {
	struct {
		struct maple_tree mm_mt;
		long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int task_size;
		pgd_t *pgd;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		int mm_lock_seq;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[50];
		struct percpu_counter rss_stat[4];
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		struct user_namespace *user_ns;
		struct file *exe_file;
		atomic_t tlb_flush_pending;
		struct uprobes_state uprobes_state;
		struct work_struct async_put_work;
	};
	long unsigned int cpu_bitmap[0];
};

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

typedef struct {
	u64 val;
} kernel_cap_t;

struct user_struct;

struct group_info;

struct cred {
	atomic_t usage;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned int securebits;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	kernel_cap_t cap_bset;
	kernel_cap_t cap_ambient;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union {
		int non_rcu;
		struct callback_head rcu;
	};
};

struct uts_namespace;

struct ipc_namespace;

struct mnt_namespace;

struct net;

struct time_namespace;

struct cgroup_namespace;

struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct sighand_struct {
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[64];
};

struct io_context {
	atomic_long_t refcount;
	atomic_t active_ref;
	short unsigned int ioprio;
};

struct perf_event_groups {
	struct rb_root tree;
	u64 index;
};

struct perf_event_context {
	raw_spinlock_t lock;
	struct mutex mutex;
	struct list_head pmu_ctx_list;
	struct perf_event_groups pinned_groups;
	struct perf_event_groups flexible_groups;
	struct list_head event_list;
	int nr_events;
	int nr_user;
	int is_active;
	int nr_task_data;
	int nr_stat;
	int nr_freq;
	int rotate_disable;
	refcount_t refcount;
	struct task_struct *task;
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	struct perf_event_context *parent_ctx;
	u64 parent_gen;
	u64 generation;
	int pin_count;
	struct callback_head callback_head;
	local_t nr_pending;
};

struct ftrace_ret_stack {
	long unsigned int ret;
	long unsigned int func;
	long long unsigned int calltime;
	long unsigned int fp;
	long unsigned int *retp;
};

enum uprobe_task_state {
	UTASK_RUNNING = 0,
	UTASK_SSTEP = 1,
	UTASK_SSTEP_ACK = 2,
	UTASK_SSTEP_TRAPPED = 3,
};

struct arch_uprobe_task {};

struct uprobe;

struct return_instance;

struct uprobe_task {
	enum uprobe_task_state state;
	union {
		struct {
			struct arch_uprobe_task autask;
			long unsigned int vaddr;
		};
		struct {
			struct callback_head dup_xol_work;
			long unsigned int dup_xol_addr;
		};
	};
	struct uprobe *active_uprobe;
	long unsigned int xol_vaddr;
	struct return_instance *return_instances;
	unsigned int depth;
};

struct vm_struct {
	struct vm_struct *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page **pages;
	unsigned int page_order;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

struct kref {
	refcount_t refcount;
};

struct return_instance {
	struct uprobe *uprobe;
	long unsigned int func;
	long unsigned int stack;
	long unsigned int orig_ret_vaddr;
	bool chained;
	struct return_instance *next;
};

typedef u32 errseq_t;

struct address_space_operations;

struct address_space {
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

struct vmem_altmap {
	long unsigned int base_pfn;
	const long unsigned int end_pfn;
	const long unsigned int reserve;
	long unsigned int free;
	long unsigned int align;
	long unsigned int alloc;
};

struct percpu_ref_data;

struct percpu_ref {
	long unsigned int percpu_count_ptr;
	struct percpu_ref_data *data;
};

enum memory_type {
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_COHERENT = 2,
	MEMORY_DEVICE_FS_DAX = 3,
	MEMORY_DEVICE_GENERIC = 4,
	MEMORY_DEVICE_PCI_P2PDMA = 5,
};

struct range {
	u64 start;
	u64 end;
};

struct dev_pagemap_ops;

struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct {
			struct {} __empty_ranges;
			struct range ranges[0];
		};
	};
};

struct folio {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
		};
		struct page page;
	};
	union {
		struct {
			long unsigned int _flags_1;
			long unsigned int _head_1;
			unsigned char _folio_dtor;
			unsigned char _folio_order;
			atomic_t _entire_mapcount;
			atomic_t _nr_pages_mapped;
			atomic_t _pincount;
			unsigned int _folio_nr_pages;
		};
		struct page __page_1;
	};
	union {
		struct {
			long unsigned int _flags_2;
			long unsigned int _head_2;
			void *_hugetlb_subpool;
			void *_hugetlb_cgroup;
			void *_hugetlb_cgroup_rsvd;
			void *_hugetlb_hwpoison;
		};
		struct {
			long unsigned int _flags_2a;
			long unsigned int _head_2a;
			struct list_head _deferred_list;
		};
		struct page __page_2;
	};
};

typedef long unsigned int vm_flags_t;

struct fown_struct {
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct file_ra_state {
	long unsigned int start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};

struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct file {
	union {
		struct llist_node f_llist;
		struct callback_head f_rcuhead;
		unsigned int f_iocb_flags;
	};
	spinlock_t f_lock;
	fmode_t f_mode;
	atomic_long_t f_count;
	struct mutex f_pos_lock;
	loff_t f_pos;
	unsigned int f_flags;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	struct path f_path;
	struct inode *f_inode;
	const struct file_operations *f_op;
	u64 f_version;
	void *private_data;
	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct vm_userfaultfd_ctx {};

struct vma_lock {
	struct rw_semaphore lock;
};

struct anon_vma;

struct vm_operations_struct;

struct vm_area_struct {
	union {
		struct {
			long unsigned int vm_start;
			long unsigned int vm_end;
		};
		struct callback_head vm_rcu;
	};
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	union {
		const vm_flags_t vm_flags;
		vm_flags_t __vm_flags;
	};
	int vm_lock_seq;
	struct vma_lock *vm_lock;
	bool detached;
	struct {
		struct rb_node rb;
		long unsigned int rb_subtree_last;
	} shared;
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	long unsigned int vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

typedef unsigned int vm_fault_t;

enum page_entry_size {
	PE_SIZE_PTE = 0,
	PE_SIZE_PMD = 1,
	PE_SIZE_PUD = 2,
};

struct vm_fault;

struct vm_operations_struct {
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, long unsigned int);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct *);
	struct page * (*find_special_page)(struct vm_area_struct *, long unsigned int);
};

enum fault_flag {
	FAULT_FLAG_WRITE = 1,
	FAULT_FLAG_MKWRITE = 2,
	FAULT_FLAG_ALLOW_RETRY = 4,
	FAULT_FLAG_RETRY_NOWAIT = 8,
	FAULT_FLAG_KILLABLE = 16,
	FAULT_FLAG_TRIED = 32,
	FAULT_FLAG_USER = 64,
	FAULT_FLAG_REMOTE = 128,
	FAULT_FLAG_INSTRUCTION = 256,
	FAULT_FLAG_INTERRUPTIBLE = 512,
	FAULT_FLAG_UNSHARE = 1024,
	FAULT_FLAG_ORIG_PTE_VALID = 2048,
	FAULT_FLAG_VMA_LOCK = 4096,
};

struct vm_fault {
	const struct {
		struct vm_area_struct *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page *cow_page;
	struct page *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t prealloc_pte;
};

struct exception_table_entry {
	int insn;
	int fixup;
	short int type;
	short int data;
};

struct css_set;

struct user_struct {
	refcount_t __count;
	long unsigned int unix_inflight;
	atomic_long_t pipe_bufs;
	struct hlist_node uidhash_node;
	kuid_t uid;
	atomic_long_t locked_vm;
	struct ratelimit_state ratelimit;
};

struct group_info {
	atomic_t usage;
	int ngroups;
	kgid_t gid[0];
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	long int len;
	long int seglen[4];
	u8 flags;
};

struct srcu_node;

struct srcu_struct;

struct srcu_data {
	atomic_long_t srcu_lock_count[2];
	atomic_long_t srcu_unlock_count[2];
	int srcu_nmi_safety;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t lock;
	struct rcu_segcblist srcu_cblist;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	bool srcu_cblist_invoking;
	struct timer_list delay_work;
	struct work_struct work;
	struct callback_head srcu_barrier_head;
	struct srcu_node *mynode;
	long unsigned int grpmask;
	int cpu;
	struct srcu_struct *ssp;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct srcu_node {
	spinlock_t lock;
	long unsigned int srcu_have_cbs[4];
	long unsigned int srcu_data_have_cbs[4];
	long unsigned int srcu_gp_seq_needed_exp;
	struct srcu_node *srcu_parent;
	int grplo;
	int grphi;
};

struct srcu_usage;

struct srcu_struct {
	unsigned int srcu_idx;
	struct srcu_data *sda;
	struct lockdep_map dep_map;
	struct srcu_usage *srcu_sup;
};

struct srcu_usage {
	struct srcu_node *node;
	struct srcu_node *level[3];
	int srcu_size_state;
	struct mutex srcu_cb_mutex;
	spinlock_t lock;
	struct mutex srcu_gp_mutex;
	long unsigned int srcu_gp_seq;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	long unsigned int srcu_gp_start;
	long unsigned int srcu_last_gp_end;
	long unsigned int srcu_size_jiffies;
	long unsigned int srcu_n_lock_retries;
	long unsigned int srcu_n_exp_nodelay;
	bool sda_is_static;
	long unsigned int srcu_barrier_seq;
	struct mutex srcu_barrier_mutex;
	struct completion srcu_barrier_completion;
	atomic_t srcu_barrier_cpu_cnt;
	long unsigned int reschedule_jiffies;
	long unsigned int reschedule_count;
	struct delayed_work work;
	struct srcu_struct *srcu_ssp;
};

struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

struct tracepoint {
	const char *name;
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

typedef const int tracepoint_ptr_t;

struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	long: 64;
};

typedef void percpu_ref_func_t(struct percpu_ref *);

struct percpu_ref_data {
	atomic_long_t count;
	percpu_ref_func_t *release;
	percpu_ref_func_t *confirm_switch;
	bool force_atomic: 1;
	bool allow_reinit: 1;
	struct callback_head rcu;
	struct percpu_ref *ref;
};

struct mem_cgroup;

struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup *memcg;
};

struct shrinker {
	long unsigned int (*count_objects)(struct shrinker *, struct shrink_control *);
	long unsigned int (*scan_objects)(struct shrinker *, struct shrink_control *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	atomic_long_t *nr_deferred;
};

struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
	int (*memory_failure)(struct dev_pagemap *, long unsigned int, long unsigned int, int);
};

struct hlist_bl_node;

struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};

struct lockref {
	union {
		__u64 lock_count;
		struct {
			spinlock_t lock;
			int count;
		};
	};
};

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct dentry_operations;

struct dentry {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[32];
	struct lockref d_lockref;
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct inode_operations;

struct file_lock_context;

struct cdev;

struct inode {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	union {
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	void *i_private;
};

struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char * (*d_dname)(struct dentry *, char *, int);
	struct vfsmount * (*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry * (*d_real)(struct dentry *, const struct inode *);
	long: 64;
	long: 64;
	long: 64;
};

struct mtd_info;

typedef long long int qsize_t;

struct quota_format_type;

struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops;

struct quota_info {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode *files[3];
	struct mem_dqinfo info[3];
	const struct quota_format_ops *ops[3];
};

struct rcu_sync {
	int gp_state;
	int gp_count;
	wait_queue_head_t gp_wait;
	struct callback_head cb_head;
};

struct percpu_rw_semaphore {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore rw_sem[3];
};

typedef struct {
	__u8 b[16];
} uuid_t;

struct list_lru_node;

struct list_lru {
	struct list_lru_node *node;
};

struct super_operations;

struct dquot_operations;

struct quotactl_ops;

struct export_operations;

struct xattr_handler;

struct block_device;

struct super_block {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct dquot_operations *dq_op;
	const struct quotactl_ops *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	const struct xattr_handler **s_xattr;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device *s_bdev;
	struct backing_dev_info *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info s_dquot;
	struct sb_writers s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations *s_d_op;
	struct shrinker s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	long: 0;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
	long: 64;
	long: 64;
};

struct mnt_idmap;

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
	struct mnt_idmap *mnt_idmap;
};

struct kstat {
	u32 result_mask;
	umode_t mode;
	unsigned int nlink;
	uint32_t blksize;
	u64 attributes;
	u64 attributes_mask;
	u64 ino;
	dev_t dev;
	dev_t rdev;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct timespec64 btime;
	u64 blocks;
	u64 mnt_id;
	u32 dio_mem_align;
	u32 dio_offset_align;
	u64 change_cookie;
};

struct list_lru_one {
	struct list_head list;
	long int nr_items;
};

struct list_lru_node {
	spinlock_t lock;
	struct list_lru_one lru;
	long int nr_items;
	long: 64;
	long: 64;
	long: 64;
};

enum migrate_mode {
	MIGRATE_ASYNC = 0,
	MIGRATE_SYNC_LIGHT = 1,
	MIGRATE_SYNC = 2,
	MIGRATE_SYNC_NO_COPY = 3,
};

struct delayed_call {
	void (*fn)(void *);
	void *arg;
};

typedef struct {
	uid_t val;
} vfsuid_t;

typedef struct {
	gid_t val;
} vfsgid_t;

struct wait_page_queue;

struct kiocb {
	struct file *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct iattr {
	unsigned int ia_valid;
	umode_t ia_mode;
	union {
		kuid_t ia_uid;
		vfsuid_t ia_vfsuid;
	};
	union {
		kgid_t ia_gid;
		vfsgid_t ia_vfsgid;
	};
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file *ia_file;
};

typedef __kernel_uid32_t projid_t;

typedef struct {
	projid_t val;
} kprojid_t;

enum quota_type {
	USRQUOTA = 0,
	GRPQUOTA = 1,
	PRJQUOTA = 2,
};

struct kqid {
	union {
		kuid_t uid;
		kgid_t gid;
		kprojid_t projid;
	};
	enum quota_type type;
};

struct mem_dqblk {
	qsize_t dqb_bhardlimit;
	qsize_t dqb_bsoftlimit;
	qsize_t dqb_curspace;
	qsize_t dqb_rsvspace;
	qsize_t dqb_ihardlimit;
	qsize_t dqb_isoftlimit;
	qsize_t dqb_curinodes;
	time64_t dqb_btime;
	time64_t dqb_itime;
};

struct dquot {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type {
	int qf_fmt_id;
	const struct quota_format_ops *qf_ops;
	struct module *qf_owner;
	struct quota_format_type *qf_next;
};

struct quota_format_ops {
	int (*check_quota_file)(struct super_block *, int);
	int (*read_file_info)(struct super_block *, int);
	int (*write_file_info)(struct super_block *, int);
	int (*free_file_info)(struct super_block *, int);
	int (*read_dqblk)(struct dquot *);
	int (*commit_dqblk)(struct dquot *);
	int (*release_dqblk)(struct dquot *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct dquot_operations {
	int (*write_dquot)(struct dquot *);
	struct dquot * (*alloc_dquot)(struct super_block *, int);
	void (*destroy_dquot)(struct dquot *);
	int (*acquire_dquot)(struct dquot *);
	int (*release_dquot)(struct dquot *);
	int (*mark_dirty)(struct dquot *);
	int (*write_info)(struct super_block *, int);
	qsize_t * (*get_reserved_space)(struct inode *);
	int (*get_projid)(struct inode *, kprojid_t *);
	int (*get_inode_usage)(struct inode *, qsize_t *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct qc_dqblk {
	int d_fieldmask;
	u64 d_spc_hardlimit;
	u64 d_spc_softlimit;
	u64 d_ino_hardlimit;
	u64 d_ino_softlimit;
	u64 d_space;
	u64 d_ino_count;
	s64 d_ino_timer;
	s64 d_spc_timer;
	int d_ino_warns;
	int d_spc_warns;
	u64 d_rt_spc_hardlimit;
	u64 d_rt_spc_softlimit;
	u64 d_rt_space;
	s64 d_rt_spc_timer;
	int d_rt_spc_warns;
};

struct qc_type_state {
	unsigned int flags;
	unsigned int spc_timelimit;
	unsigned int ino_timelimit;
	unsigned int rt_spc_timelimit;
	unsigned int spc_warnlimit;
	unsigned int ino_warnlimit;
	unsigned int rt_spc_warnlimit;
	long long unsigned int ino;
	blkcnt_t blocks;
	blkcnt_t nextents;
};

struct qc_state {
	unsigned int s_incoredqs;
	struct qc_type_state s_state[3];
};

struct qc_info {
	int i_fieldmask;
	unsigned int i_flags;
	unsigned int i_spc_timelimit;
	unsigned int i_ino_timelimit;
	unsigned int i_rt_spc_timelimit;
	unsigned int i_spc_warnlimit;
	unsigned int i_ino_warnlimit;
	unsigned int i_rt_spc_warnlimit;
};

struct quotactl_ops {
	int (*quota_on)(struct super_block *, int, int, const struct path *);
	int (*quota_off)(struct super_block *, int);
	int (*quota_enable)(struct super_block *, unsigned int);
	int (*quota_disable)(struct super_block *, unsigned int);
	int (*quota_sync)(struct super_block *, int);
	int (*set_info)(struct super_block *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block *, struct qc_state *);
	int (*rm_xquota)(struct super_block *, unsigned int);
};

enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
};

struct kset;

struct kobj_type;

struct kernfs_node;

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct module_param_attrs;

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct latch_tree_node {
	struct rb_node node[2];
};

struct mod_tree_node {
	struct module *mod;
	struct latch_tree_node node;
};

struct module_memory {
	void *base;
	unsigned int size;
	struct mod_tree_node mtn;
};

struct mod_plt_sec {
	int plt_shndx;
	int plt_num_entries;
	int plt_max_entries;
};

struct plt_entry;

struct mod_arch_specific {
	struct mod_plt_sec core;
	struct mod_plt_sec init;
	struct plt_entry *ftrace_trampolines;
};

struct elf64_sym;

typedef struct elf64_sym Elf64_Sym;

struct mod_kallsyms {
	Elf64_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};

struct module_sect_attrs;

struct module_notes_attrs;

struct module_attribute;

struct kernel_param;

struct trace_eval_map;

struct error_injection_entry;

struct module {
	enum module_state state;
	struct list_head list;
	char name[56];
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct kernel_param *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct module_memory mem[7];
	struct mod_arch_specific arch;
	long unsigned int taints;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *percpu;
	unsigned int percpu_size;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	unsigned int num_ftrace_callsites;
	long unsigned int *ftrace_callsites;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	struct error_injection_entry *ei_funcs;
	unsigned int num_ei_funcs;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct writeback_control;

struct readahead_control;

struct swap_info_struct;

struct address_space_operations {
	int (*writepage)(struct page *, struct writeback_control *);
	int (*read_folio)(struct file *, struct folio *);
	int (*writepages)(struct address_space *, struct writeback_control *);
	bool (*dirty_folio)(struct address_space *, struct folio *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file *, struct address_space *, loff_t, unsigned int, struct page **, void **);
	int (*write_end)(struct file *, struct address_space *, loff_t, unsigned int, unsigned int, struct page *, void *);
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidate_folio)(struct folio *, size_t, size_t);
	bool (*release_folio)(struct folio *, gfp_t);
	void (*free_folio)(struct folio *);
	ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *);
	int (*migrate_folio)(struct address_space *, struct folio *, struct folio *, enum migrate_mode);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct folio *, bool *, bool *);
	int (*error_remove_page)(struct address_space *, struct page *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
	int (*swap_rw)(struct kiocb *, struct iov_iter *);
};

struct iovec {
	void *iov_base;
	__kernel_size_t iov_len;
};

struct kvec;

struct bio_vec;

struct iov_iter {
	u8 iter_type;
	bool copy_mc;
	bool nofault;
	bool data_source;
	bool user_backed;
	union {
		size_t iov_offset;
		int last_offset;
	};
	union {
		struct iovec __ubuf_iovec;
		struct {
			union {
				const struct iovec *__iov;
				const struct kvec *kvec;
				const struct bio_vec *bvec;
				struct xarray *xarray;
				void *ubuf;
			};
			size_t count;
		};
	};
	union {
		long unsigned int nr_segs;
		loff_t xarray_start;
	};
};

struct posix_acl;

struct fiemap_extent_info;

struct fileattr;

struct inode_operations {
	struct dentry * (*lookup)(struct inode *, struct dentry *, unsigned int);
	const char * (*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct mnt_idmap *, struct inode *, int);
	struct posix_acl * (*get_inode_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char *, int);
	int (*create)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, bool);
	int (*link)(struct dentry *, struct inode *, struct dentry *);
	int (*unlink)(struct inode *, struct dentry *);
	int (*symlink)(struct mnt_idmap *, struct inode *, struct dentry *, const char *);
	int (*mkdir)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t);
	int (*rmdir)(struct inode *, struct dentry *);
	int (*mknod)(struct mnt_idmap *, struct inode *, struct dentry *, umode_t, dev_t);
	int (*rename)(struct mnt_idmap *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
	int (*setattr)(struct mnt_idmap *, struct dentry *, struct iattr *);
	int (*getattr)(struct mnt_idmap *, const struct path *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode *, struct timespec64 *, int);
	int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned int, umode_t);
	int (*tmpfile)(struct mnt_idmap *, struct inode *, struct file *, umode_t);
	struct posix_acl * (*get_acl)(struct mnt_idmap *, struct dentry *, int);
	int (*set_acl)(struct mnt_idmap *, struct dentry *, struct posix_acl *, int);
	int (*fileattr_set)(struct mnt_idmap *, struct dentry *, struct fileattr *);
	int (*fileattr_get)(struct dentry *, struct fileattr *);
};

struct fasync_struct {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	struct file *fa_file;
	struct callback_head fa_rcu;
};

struct kstatfs;

struct super_operations {
	struct inode * (*alloc_inode)(struct super_block *);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);
	void (*dirty_inode)(struct inode *, int);
	int (*write_inode)(struct inode *, struct writeback_control *);
	int (*drop_inode)(struct inode *);
	void (*evict_inode)(struct inode *);
	void (*put_super)(struct super_block *);
	int (*sync_fs)(struct super_block *, int);
	int (*freeze_super)(struct super_block *);
	int (*freeze_fs)(struct super_block *);
	int (*thaw_super)(struct super_block *);
	int (*unfreeze_fs)(struct super_block *);
	int (*statfs)(struct dentry *, struct kstatfs *);
	int (*remount_fs)(struct super_block *, int *, char *);
	void (*umount_begin)(struct super_block *);
	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	int (*show_stats)(struct seq_file *, struct dentry *);
	long int (*nr_cached_objects)(struct super_block *, struct shrink_control *);
	long int (*free_cached_objects)(struct super_block *, struct shrink_control *);
	void (*shutdown)(struct super_block *);
};

struct iomap;

struct fid;

struct export_operations {
	int (*encode_fh)(struct inode *, __u32 *, int *, struct inode *);
	struct dentry * (*fh_to_dentry)(struct super_block *, struct fid *, int, int);
	struct dentry * (*fh_to_parent)(struct super_block *, struct fid *, int, int);
	int (*get_name)(struct dentry *, char *, struct dentry *);
	struct dentry * (*get_parent)(struct dentry *);
	int (*commit_metadata)(struct inode *);
	int (*get_uuid)(struct super_block *, u8 *, u32 *, u64 *);
	int (*map_blocks)(struct inode *, loff_t, u64, struct iomap *, bool, u32 *);
	int (*commit_blocks)(struct inode *, struct iomap *, int, struct iattr *);
	long unsigned int flags;
};

struct xattr_handler {
	const char *name;
	const char *prefix;
	int flags;
	bool (*list)(struct dentry *);
	int (*get)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t);
	int (*set)(const struct xattr_handler *, struct mnt_idmap *, struct dentry *, struct inode *, const char *, const void *, size_t, int);
};

typedef bool (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);

struct dir_context {
	filldir_t actor;
	loff_t pos;
};

typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
};

struct seq_operations;

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

struct p_log;

struct fs_parameter;

struct fs_parse_result;

typedef int fs_param_type(struct p_log *, const struct fs_parameter_spec *, struct fs_parameter *, struct fs_parse_result *);

struct fs_parameter_spec {
	const char *name;
	fs_param_type *type;
	u8 opt;
	short unsigned int flags;
	const void *data;
};

struct attribute;

struct bin_attribute;

struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
	struct attribute **attrs;
	struct bin_attribute **bin_attrs;
};

struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};

struct nsset;

struct proc_ns_operations {
	const char *name;
	const char *real_ns_name;
	int type;
	struct ns_common * (*get)(struct task_struct *);
	void (*put)(struct ns_common *);
	int (*install)(struct nsset *, struct ns_common *);
	struct user_namespace * (*owner)(struct ns_common *);
	struct ns_common * (*get_parent)(struct ns_common *);
};

struct kvec {
	void *iov_base;
	size_t iov_len;
};

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

enum perf_type_id {
	PERF_TYPE_HARDWARE = 0,
	PERF_TYPE_SOFTWARE = 1,
	PERF_TYPE_TRACEPOINT = 2,
	PERF_TYPE_HW_CACHE = 3,
	PERF_TYPE_RAW = 4,
	PERF_TYPE_BREAKPOINT = 5,
	PERF_TYPE_MAX = 6,
};

enum perf_branch_sample_type_shift {
	PERF_SAMPLE_BRANCH_USER_SHIFT = 0,
	PERF_SAMPLE_BRANCH_KERNEL_SHIFT = 1,
	PERF_SAMPLE_BRANCH_HV_SHIFT = 2,
	PERF_SAMPLE_BRANCH_ANY_SHIFT = 3,
	PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT = 4,
	PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT = 5,
	PERF_SAMPLE_BRANCH_IND_CALL_SHIFT = 6,
	PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT = 7,
	PERF_SAMPLE_BRANCH_IN_TX_SHIFT = 8,
	PERF_SAMPLE_BRANCH_NO_TX_SHIFT = 9,
	PERF_SAMPLE_BRANCH_COND_SHIFT = 10,
	PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11,
	PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT = 12,
	PERF_SAMPLE_BRANCH_CALL_SHIFT = 13,
	PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT = 14,
	PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT = 15,
	PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT = 16,
	PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT = 17,
	PERF_SAMPLE_BRANCH_PRIV_SAVE_SHIFT = 18,
	PERF_SAMPLE_BRANCH_MAX_SHIFT = 19,
};

union perf_mem_data_src {
	__u64 val;
	struct {
		__u64 mem_op: 5;
		__u64 mem_lvl: 14;
		__u64 mem_snoop: 5;
		__u64 mem_lock: 2;
		__u64 mem_dtlb: 7;
		__u64 mem_lvl_num: 4;
		__u64 mem_remote: 1;
		__u64 mem_snoopx: 2;
		__u64 mem_blk: 3;
		__u64 mem_hops: 3;
		__u64 mem_rsvd: 18;
	};
};

struct perf_branch_entry {
	__u64 from;
	__u64 to;
	__u64 mispred: 1;
	__u64 predicted: 1;
	__u64 in_tx: 1;
	__u64 abort: 1;
	__u64 cycles: 16;
	__u64 type: 4;
	__u64 spec: 2;
	__u64 new_type: 4;
	__u64 priv: 3;
	__u64 reserved: 31;
};

union perf_sample_weight {
	__u64 full;
	struct {
		__u32 var1_dw;
		__u16 var2_w;
		__u16 var3_w;
	};
};

struct fwnode_operations;

struct device;

struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

enum dev_dma_attr {
	DEV_DMA_NOT_SUPPORTED = 0,
	DEV_DMA_NON_COHERENT = 1,
	DEV_DMA_COHERENT = 2,
};

struct fwnode_reference_args;

struct fwnode_endpoint;

struct fwnode_operations {
	struct fwnode_handle * (*get)(struct fwnode_handle *);
	void (*put)(struct fwnode_handle *);
	bool (*device_is_available)(const struct fwnode_handle *);
	const void * (*device_get_match_data)(const struct fwnode_handle *, const struct device *);
	bool (*device_dma_supported)(const struct fwnode_handle *);
	enum dev_dma_attr (*device_get_dma_attr)(const struct fwnode_handle *);
	bool (*property_present)(const struct fwnode_handle *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle *);
	const char * (*get_name_prefix)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_parent)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_next_child_node)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*get_named_child_node)(const struct fwnode_handle *, const char *);
	int (*get_reference_args)(const struct fwnode_handle *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args *);
	struct fwnode_handle * (*graph_get_next_endpoint)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_remote_endpoint)(const struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_port_parent)(struct fwnode_handle *);
	int (*graph_parse_endpoint)(const struct fwnode_handle *, struct fwnode_endpoint *);
	void * (*iomap)(struct fwnode_handle *, int);
	int (*irq_get)(const struct fwnode_handle *, unsigned int);
	int (*add_links)(struct fwnode_handle *);
};

enum dl_dev_state {
	DL_DEV_NO_DRIVER = 0,
	DL_DEV_PROBING = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING = 3,
};

struct dev_links_info {
	struct list_head suppliers;
	struct list_head consumers;
	struct list_head defer_sync;
	enum dl_dev_state status;
};

struct pm_message {
	int event;
};

typedef struct pm_message pm_message_t;

struct pm_subsys_data;

struct dev_pm_qos;

struct dev_pm_info {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	unsigned int should_wakeup: 1;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device *, s32);
	struct dev_pm_qos *qos;
};

struct irq_domain;

struct msi_device_data;

struct dev_msi_info {
	struct irq_domain *domain;
	struct msi_device_data *data;
};

struct dev_archdata {};

struct dev_iommu;

enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN = 1,
	DEVICE_FIXED = 2,
	DEVICE_REMOVABLE = 3,
};

struct device_private;

struct device_type;

struct bus_type;

struct device_driver;

struct dev_pm_domain;

struct bus_dma_region;

struct device_dma_parameters;

struct dma_coherent_mem;

struct io_tlb_mem;

struct device_node;

struct class;

struct iommu_group;

struct device_physical_location;

struct device {
	struct kobject kobj;
	struct device *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type *type;
	const struct bus_type *bus;
	struct device_driver *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info power;
	struct dev_pm_domain *pm_domain;
	struct dev_msi_info msi;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct dma_coherent_mem *dma_mem;
	struct io_tlb_mem *dma_io_tlb_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	const struct class *class;
	const struct attribute_group **groups;
	void (*release)(struct device *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	struct device_physical_location *physical_location;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
	bool dma_coherent: 1;
};

struct fwnode_endpoint {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle *local_fwnode;
};

struct fwnode_reference_args {
	struct fwnode_handle *fwnode;
	unsigned int nargs;
	u64 args[8];
};

struct kernfs_root;

struct kernfs_elem_dir {
	long unsigned int subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	long unsigned int rev;
};

struct kernfs_elem_symlink {
	struct kernfs_node *target_kn;
};

struct kernfs_open_node;

struct kernfs_ops;

struct kernfs_elem_attr {
	const struct kernfs_ops *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node *notify_next;
};

struct kernfs_iattrs;

struct kernfs_node {
	atomic_t count;
	atomic_t active;
	struct kernfs_node *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink symlink;
		struct kernfs_elem_attr attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file;

struct kernfs_ops {
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	ssize_t (*read)(struct kernfs_open_file *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	int (*mmap)(struct kernfs_open_file *, struct vm_area_struct *);
};

struct kernfs_open_file {
	struct kernfs_node *kn;
	struct file *file;
	struct seq_file *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct *vm_ops;
};

enum kobj_ns_type {
	KOBJ_NS_TYPE_NONE = 0,
	KOBJ_NS_TYPE_NET = 1,
	KOBJ_NS_TYPES = 2,
};

struct sock;

struct kobj_ns_type_operations {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct attribute {
	const char *name;
	umode_t mode;
};

struct bin_attribute {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space * (*f_mapping)();
	ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*write)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	int (*mmap)(struct file *, struct kobject *, struct bin_attribute *, struct vm_area_struct *);
};

struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops;

struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};

struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(const struct kobject *);
	const void * (*namespace)(const struct kobject *);
	void (*get_ownership)(const struct kobject *, kuid_t *, kgid_t *);
};

struct kobj_uevent_env {
	char *argv[3];
	char *envp[64];
	int envp_idx;
	char buf[2048];
	int buflen;
};

struct kset_uevent_ops {
	int (* const filter)(const struct kobject *);
	const char * (* const name)(const struct kobject *);
	int (* const uevent)(const struct kobject *, struct kobj_uevent_env *);
};

enum {
	HI_SOFTIRQ = 0,
	TIMER_SOFTIRQ = 1,
	NET_TX_SOFTIRQ = 2,
	NET_RX_SOFTIRQ = 3,
	BLOCK_SOFTIRQ = 4,
	IRQ_POLL_SOFTIRQ = 5,
	TASKLET_SOFTIRQ = 6,
	SCHED_SOFTIRQ = 7,
	HRTIMER_SOFTIRQ = 8,
	RCU_SOFTIRQ = 9,
	NR_SOFTIRQS = 10,
};

typedef __u64 Elf64_Addr;

typedef __u16 Elf64_Half;

typedef __u32 Elf64_Word;

typedef __u64 Elf64_Xword;

struct elf64_sym {
	Elf64_Word st_name;
	unsigned char st_info;
	unsigned char st_other;
	Elf64_Half st_shndx;
	Elf64_Addr st_value;
	Elf64_Xword st_size;
};

struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
};

struct kparam_string;

struct kparam_array;

struct kernel_param {
	const char *name;
	struct module *mod;
	const struct kernel_param_ops *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array *arr;
	};
};

struct kparam_string {
	unsigned int maxlen;
	char *string;
};

struct kparam_array {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};

struct error_injection_entry {
	long unsigned int addr;
	int etype;
};

struct plt_entry {
	__le32 adrp;
	__le32 add;
	__le32 br;
};

struct module_attribute {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
	ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
};

enum mod_mem_type {
	MOD_TEXT = 0,
	MOD_DATA = 1,
	MOD_RODATA = 2,
	MOD_RO_AFTER_INIT = 3,
	MOD_INIT_TEXT = 4,
	MOD_INIT_DATA = 5,
	MOD_INIT_RODATA = 6,
	MOD_MEM_NUM_TYPES = 7,
	MOD_INVALID = -1,
};

struct trace_event_functions;

struct trace_event {
	struct hlist_node node;
	int type;
	struct trace_event_functions *funcs;
};

struct trace_event_class;

struct bpf_prog_array;

struct trace_event_call {
	struct list_head list;
	struct trace_event_class *class;
	union {
		char *name;
		struct tracepoint *tp;
	};
	struct trace_event event;
	char *print_fmt;
	struct event_filter *filter;
	union {
		void *module;
		atomic_t refcnt;
	};
	void *data;
	int flags;
	int perf_refcount;
	struct hlist_head *perf_events;
	struct bpf_prog_array *prog_array;
	int (*perf_perm)(struct trace_event_call *, struct perf_event *);
};

struct trace_eval_map {
	const char *system;
	const char *eval_string;
	long unsigned int eval_value;
};

struct ftrace_regs {
	long unsigned int regs[9];
	long unsigned int __unused;
	long unsigned int fp;
	long unsigned int lr;
	long unsigned int sp;
	long unsigned int pc;
};

enum {
	__SD_BALANCE_NEWIDLE = 0,
	__SD_BALANCE_EXEC = 1,
	__SD_BALANCE_FORK = 2,
	__SD_BALANCE_WAKE = 3,
	__SD_WAKE_AFFINE = 4,
	__SD_ASYM_CPUCAPACITY = 5,
	__SD_ASYM_CPUCAPACITY_FULL = 6,
	__SD_SHARE_CPUCAPACITY = 7,
	__SD_SHARE_PKG_RESOURCES = 8,
	__SD_SERIALIZE = 9,
	__SD_ASYM_PACKING = 10,
	__SD_PREFER_SIBLING = 11,
	__SD_OVERLAP = 12,
	__SD_NUMA = 13,
	__SD_FLAG_CNT = 14,
};

struct dev_pm_ops {
	int (*prepare)(struct device *);
	void (*complete)(struct device *);
	int (*suspend)(struct device *);
	int (*resume)(struct device *);
	int (*freeze)(struct device *);
	int (*thaw)(struct device *);
	int (*poweroff)(struct device *);
	int (*restore)(struct device *);
	int (*suspend_late)(struct device *);
	int (*resume_early)(struct device *);
	int (*freeze_late)(struct device *);
	int (*thaw_early)(struct device *);
	int (*poweroff_late)(struct device *);
	int (*restore_early)(struct device *);
	int (*suspend_noirq)(struct device *);
	int (*resume_noirq)(struct device *);
	int (*freeze_noirq)(struct device *);
	int (*thaw_noirq)(struct device *);
	int (*poweroff_noirq)(struct device *);
	int (*restore_noirq)(struct device *);
	int (*runtime_suspend)(struct device *);
	int (*runtime_resume)(struct device *);
	int (*runtime_idle)(struct device *);
};

struct pm_subsys_data {
	spinlock_t lock;
	unsigned int refcount;
};

struct dev_pm_domain {
	struct dev_pm_ops ops;
	int (*start)(struct device *);
	void (*detach)(struct device *, bool);
	int (*activate)(struct device *);
	void (*sync)(struct device *);
	void (*dismiss)(struct device *);
};

struct iommu_ops;

struct bus_type {
	const char *name;
	const char *dev_name;
	const struct attribute_group **bus_groups;
	const struct attribute_group **dev_groups;
	const struct attribute_group **drv_groups;
	int (*match)(struct device *, struct device_driver *);
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	void (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*online)(struct device *);
	int (*offline)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	int (*num_vf)(struct device *);
	int (*dma_configure)(struct device *);
	void (*dma_cleanup)(struct device *);
	const struct dev_pm_ops *pm;
	const struct iommu_ops *iommu_ops;
	bool need_parent_lock;
};

enum probe_type {
	PROBE_DEFAULT_STRATEGY = 0,
	PROBE_PREFER_ASYNCHRONOUS = 1,
	PROBE_FORCE_SYNCHRONOUS = 2,
};

struct of_device_id;

struct acpi_device_id;

struct driver_private;

struct device_driver {
	const char *name;
	const struct bus_type *bus;
	struct module *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	int (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	const struct dev_pm_ops *pm;
	void (*coredump)(struct device *);
	struct driver_private *p;
};

struct iommu_ops {};

struct class {
	const char *name;
	const struct attribute_group **class_groups;
	const struct attribute_group **dev_groups;
	int (*dev_uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *);
	void (*class_release)(const struct class *);
	void (*dev_release)(struct device *);
	int (*shutdown_pre)(struct device *);
	const struct kobj_ns_type_operations *ns_type;
	const void * (*namespace)(const struct device *);
	void (*get_ownership)(const struct device *, kuid_t *, kgid_t *);
	const struct dev_pm_ops *pm;
};

struct device_type {
	const char *name;
	const struct attribute_group **groups;
	int (*uevent)(const struct device *, struct kobj_uevent_env *);
	char * (*devnode)(const struct device *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device *);
	const struct dev_pm_ops *pm;
};

struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
	const void *data;
};

typedef long unsigned int kernel_ulong_t;

struct acpi_device_id {
	__u8 id[16];
	kernel_ulong_t driver_data;
	__u32 cls;
	__u32 cls_msk;
};

struct device_dma_parameters {
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	long unsigned int segment_boundary_mask;
};

enum device_physical_location_panel {
	DEVICE_PANEL_TOP = 0,
	DEVICE_PANEL_BOTTOM = 1,
	DEVICE_PANEL_LEFT = 2,
	DEVICE_PANEL_RIGHT = 3,
	DEVICE_PANEL_FRONT = 4,
	DEVICE_PANEL_BACK = 5,
	DEVICE_PANEL_UNKNOWN = 6,
};

enum device_physical_location_vertical_position {
	DEVICE_VERT_POS_UPPER = 0,
	DEVICE_VERT_POS_CENTER = 1,
	DEVICE_VERT_POS_LOWER = 2,
};

enum device_physical_location_horizontal_position {
	DEVICE_HORI_POS_LEFT = 0,
	DEVICE_HORI_POS_CENTER = 1,
	DEVICE_HORI_POS_RIGHT = 2,
};

struct device_physical_location {
	enum device_physical_location_panel panel;
	enum device_physical_location_vertical_position vertical_position;
	enum device_physical_location_horizontal_position horizontal_position;
	bool dock;
	bool lid;
};

typedef u64 dma_addr_t;

struct bus_dma_region {
	phys_addr_t cpu_start;
	dma_addr_t dma_start;
	u64 size;
	u64 offset;
};

struct perf_regs {
	__u64 abi;
	struct pt_regs *regs;
};

enum {
	TASKSTATS_CMD_UNSPEC = 0,
	TASKSTATS_CMD_GET = 1,
	TASKSTATS_CMD_NEW = 2,
	__TASKSTATS_CMD_MAX = 3,
};

struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};

enum ucount_type {
	UCOUNT_USER_NAMESPACES = 0,
	UCOUNT_PID_NAMESPACES = 1,
	UCOUNT_UTS_NAMESPACES = 2,
	UCOUNT_IPC_NAMESPACES = 3,
	UCOUNT_NET_NAMESPACES = 4,
	UCOUNT_MNT_NAMESPACES = 5,
	UCOUNT_CGROUP_NAMESPACES = 6,
	UCOUNT_TIME_NAMESPACES = 7,
	UCOUNT_COUNTS = 8,
};

enum rlimit_type {
	UCOUNT_RLIMIT_NPROC = 0,
	UCOUNT_RLIMIT_MSGQUEUE = 1,
	UCOUNT_RLIMIT_SIGPENDING = 2,
	UCOUNT_RLIMIT_MEMLOCK = 3,
	UCOUNT_RLIMIT_COUNTS = 4,
};

enum cpu_usage_stat {
	CPUTIME_USER = 0,
	CPUTIME_NICE = 1,
	CPUTIME_SYSTEM = 2,
	CPUTIME_SOFTIRQ = 3,
	CPUTIME_IRQ = 4,
	CPUTIME_IDLE = 5,
	CPUTIME_IOWAIT = 6,
	CPUTIME_STEAL = 7,
	CPUTIME_GUEST = 8,
	CPUTIME_GUEST_NICE = 9,
	NR_STATS = 10,
};

struct perf_callchain_entry {
	__u64 nr;
	__u64 ip[0];
};

typedef long unsigned int (*perf_copy_f)(void *, const void *, long unsigned int, long unsigned int);

struct perf_raw_frag {
	union {
		struct perf_raw_frag *next;
		long unsigned int pad;
	};
	perf_copy_f copy;
	void *data;
	u32 size;
} __attribute__((packed));

struct perf_raw_record {
	struct perf_raw_frag frag;
	u32 size;
};

struct perf_branch_stack {
	__u64 nr;
	__u64 hw_idx;
	struct perf_branch_entry entries[0];
};

struct perf_cpu_pmu_context;

struct perf_output_handle;

struct pmu {
	struct list_head entry;
	struct module *module;
	struct device *dev;
	const struct attribute_group **attr_groups;
	const struct attribute_group **attr_update;
	const char *name;
	int type;
	int capabilities;
	int *pmu_disable_count;
	struct perf_cpu_pmu_context *cpu_pmu_context;
	atomic_t exclusive_cnt;
	int task_ctx_nr;
	int hrtimer_interval_ms;
	unsigned int nr_addr_filters;
	void (*pmu_enable)(struct pmu *);
	void (*pmu_disable)(struct pmu *);
	int (*event_init)(struct perf_event *);
	void (*event_mapped)(struct perf_event *, struct mm_struct *);
	void (*event_unmapped)(struct perf_event *, struct mm_struct *);
	int (*add)(struct perf_event *, int);
	void (*del)(struct perf_event *, int);
	void (*start)(struct perf_event *, int);
	void (*stop)(struct perf_event *, int);
	void (*read)(struct perf_event *);
	void (*start_txn)(struct pmu *, unsigned int);
	int (*commit_txn)(struct pmu *);
	void (*cancel_txn)(struct pmu *);
	int (*event_idx)(struct perf_event *);
	void (*sched_task)(struct perf_event_pmu_context *, bool);
	struct kmem_cache *task_ctx_cache;
	void (*swap_task_ctx)(struct perf_event_pmu_context *, struct perf_event_pmu_context *);
	void * (*setup_aux)(struct perf_event *, void **, int, bool);
	void (*free_aux)(void *);
	long int (*snapshot_aux)(struct perf_event *, struct perf_output_handle *, long unsigned int);
	int (*addr_filters_validate)(struct list_head *);
	void (*addr_filters_sync)(struct perf_event *);
	int (*aux_output_match)(struct perf_event *);
	bool (*filter)(struct pmu *, int);
	int (*check_period)(struct perf_event *, u64);
};

struct perf_event_pmu_context {
	struct pmu *pmu;
	struct perf_event_context *ctx;
	struct list_head pmu_ctx_entry;
	struct list_head pinned_active;
	struct list_head flexible_active;
	unsigned int embedded: 1;
	unsigned int nr_events;
	atomic_t refcount;
	struct callback_head callback_head;
	void *task_ctx_data;
	int rotate_necessary;
};

struct perf_cpu_pmu_context {
	struct perf_event_pmu_context epc;
	struct perf_event_pmu_context *task_epc;
	struct list_head sched_cb_entry;
	int sched_cb_usage;
	int active_oncpu;
	int exclusive;
	raw_spinlock_t hrtimer_lock;
	struct hrtimer hrtimer;
	ktime_t hrtimer_interval;
	unsigned int hrtimer_active;
};

struct perf_output_handle {
	struct perf_event *event;
	struct perf_buffer *rb;
	long unsigned int wakeup;
	long unsigned int size;
	u64 aux_flags;
	union {
		void *addr;
		long unsigned int head;
	};
	int page;
};

struct perf_addr_filter_range {
	long unsigned int start;
	long unsigned int size;
};

struct perf_sample_data {
	u64 sample_flags;
	u64 period;
	u64 dyn_size;
	u64 type;
	struct {
		u32 pid;
		u32 tid;
	} tid_entry;
	u64 time;
	u64 id;
	struct {
		u32 cpu;
		u32 reserved;
	} cpu_entry;
	u64 ip;
	struct perf_callchain_entry *callchain;
	struct perf_raw_record *raw;
	struct perf_branch_stack *br_stack;
	union perf_sample_weight weight;
	union perf_mem_data_src data_src;
	u64 txn;
	struct perf_regs regs_user;
	struct perf_regs regs_intr;
	u64 stack_user_size;
	u64 stream_id;
	u64 cgroup;
	u64 addr;
	u64 phys_addr;
	u64 data_page_size;
	u64 code_page_size;
	u64 aux_size;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum {
	HW_BREAKPOINT_LEN_1 = 1,
	HW_BREAKPOINT_LEN_2 = 2,
	HW_BREAKPOINT_LEN_3 = 3,
	HW_BREAKPOINT_LEN_4 = 4,
	HW_BREAKPOINT_LEN_5 = 5,
	HW_BREAKPOINT_LEN_6 = 6,
	HW_BREAKPOINT_LEN_7 = 7,
	HW_BREAKPOINT_LEN_8 = 8,
};

enum {
	HW_BREAKPOINT_EMPTY = 0,
	HW_BREAKPOINT_R = 1,
	HW_BREAKPOINT_W = 2,
	HW_BREAKPOINT_RW = 3,
	HW_BREAKPOINT_X = 4,
	HW_BREAKPOINT_INVALID = 7,
};

enum bp_type_idx {
	TYPE_INST = 0,
	TYPE_DATA = 1,
	TYPE_MAX = 2,
};

struct membuf {
	void *p;
	size_t left;
};

struct user_regset;

typedef int user_regset_active_fn(struct task_struct *, const struct user_regset *);

typedef int user_regset_get2_fn(struct task_struct *, const struct user_regset *, struct membuf);

typedef int user_regset_set_fn(struct task_struct *, const struct user_regset *, unsigned int, unsigned int, const void *, const void *);

typedef int user_regset_writeback_fn(struct task_struct *, const struct user_regset *, int);

struct user_regset {
	user_regset_get2_fn *regset_get;
	user_regset_set_fn *set;
	user_regset_active_fn *active;
	user_regset_writeback_fn *writeback;
	unsigned int n;
	unsigned int size;
	unsigned int align;
	unsigned int bias;
	unsigned int core_note_type;
};

struct user_regset_view {
	const char *name;
	const struct user_regset *regsets;
	unsigned int n;
	u32 e_flags;
	u16 e_machine;
	u8 ei_osabi;
};

struct stack_info {
	long unsigned int low;
	long unsigned int high;
};

struct ring_buffer_event {
	u32 type_len: 5;
	u32 time_delta: 27;
	u32 array[0];
};

struct seq_buf {
	char *buffer;
	size_t size;
	size_t len;
	loff_t readpos;
};

struct trace_seq {
	char buffer[4096];
	struct seq_buf seq;
	int full;
};

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_array;

struct tracer;

struct array_buffer;

struct ring_buffer_iter;

struct trace_iterator {
	struct trace_array *tr;
	struct tracer *trace;
	struct array_buffer *array_buffer;
	void *private;
	int cpu_file;
	struct mutex mutex;
	struct ring_buffer_iter **buffer_iter;
	long unsigned int iter_flags;
	void *temp;
	unsigned int temp_size;
	char *fmt;
	unsigned int fmt_size;
	long int wait_index;
	struct trace_seq tmp_seq;
	cpumask_var_t started;
	bool snapshot;
	struct trace_seq seq;
	struct trace_entry *ent;
	long unsigned int lost_events;
	int leftover;
	int ent_size;
	int cpu;
	u64 ts;
	loff_t pos;
	long int idx;
};

enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE = 0,
	TRACE_TYPE_HANDLED = 1,
	TRACE_TYPE_UNHANDLED = 2,
	TRACE_TYPE_NO_CONSUME = 3,
};

typedef enum print_line_t (*trace_print_func)(struct trace_iterator *, int, struct trace_event *);

struct trace_event_functions {
	trace_print_func trace;
	trace_print_func raw;
	trace_print_func hex;
	trace_print_func binary;
};

enum trace_reg {
	TRACE_REG_REGISTER = 0,
	TRACE_REG_UNREGISTER = 1,
	TRACE_REG_PERF_REGISTER = 2,
	TRACE_REG_PERF_UNREGISTER = 3,
	TRACE_REG_PERF_OPEN = 4,
	TRACE_REG_PERF_CLOSE = 5,
	TRACE_REG_PERF_ADD = 6,
	TRACE_REG_PERF_DEL = 7,
};

struct trace_event_fields {
	const char *type;
	union {
		struct {
			const char *name;
			const int size;
			const int align;
			const int is_signed;
			const int filter_type;
			const int len;
		};
		int (*define_fields)(struct trace_event_call *);
	};
};

struct trace_event_class {
	const char *system;
	void *probe;
	void *perf_probe;
	int (*reg)(struct trace_event_call *, enum trace_reg, void *);
	struct trace_event_fields *fields_array;
	struct list_head * (*get_fields)(struct trace_event_call *);
	struct list_head fields;
	int (*raw_init)(struct trace_event_call *);
};

struct trace_buffer;

struct trace_event_file;

struct trace_event_buffer {
	struct trace_buffer *buffer;
	struct ring_buffer_event *event;
	struct trace_event_file *trace_file;
	void *entry;
	unsigned int trace_ctx;
	struct pt_regs *regs;
};

struct trace_subsystem_dir;

struct trace_event_file {
	struct list_head list;
	struct trace_event_call *event_call;
	struct event_filter *filter;
	struct dentry *dir;
	struct trace_array *tr;
	struct trace_subsystem_dir *system;
	struct list_head triggers;
	long unsigned int flags;
	atomic_t sm_ref;
	atomic_t tm_ref;
};

enum {
	TRACE_EVENT_FL_FILTERED = 1,
	TRACE_EVENT_FL_CAP_ANY = 2,
	TRACE_EVENT_FL_NO_SET_FILTER = 4,
	TRACE_EVENT_FL_IGNORE_ENABLE = 8,
	TRACE_EVENT_FL_TRACEPOINT = 16,
	TRACE_EVENT_FL_DYNAMIC = 32,
	TRACE_EVENT_FL_KPROBE = 64,
	TRACE_EVENT_FL_UPROBE = 128,
	TRACE_EVENT_FL_EPROBE = 256,
	TRACE_EVENT_FL_CUSTOM = 512,
};

enum {
	EVENT_FILE_FL_ENABLED = 1,
	EVENT_FILE_FL_RECORDED_CMD = 2,
	EVENT_FILE_FL_RECORDED_TGID = 4,
	EVENT_FILE_FL_FILTERED = 8,
	EVENT_FILE_FL_NO_SET_FILTER = 16,
	EVENT_FILE_FL_SOFT_MODE = 32,
	EVENT_FILE_FL_SOFT_DISABLED = 64,
	EVENT_FILE_FL_TRIGGER_MODE = 128,
	EVENT_FILE_FL_TRIGGER_COND = 256,
	EVENT_FILE_FL_PID_FILTER = 512,
	EVENT_FILE_FL_WAS_ENABLED = 1024,
};

enum {
	FILTER_OTHER = 0,
	FILTER_STATIC_STRING = 1,
	FILTER_DYN_STRING = 2,
	FILTER_RDYN_STRING = 3,
	FILTER_PTR_STRING = 4,
	FILTER_TRACE_FN = 5,
	FILTER_COMM = 6,
	FILTER_CPU = 7,
	FILTER_STACKTRACE = 8,
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};

struct trace_event_data_offsets_sys_enter {};

struct trace_event_data_offsets_sys_exit {};

typedef void (*btf_trace_sys_enter)(void *, struct pt_regs *, long int);

typedef void (*btf_trace_sys_exit)(void *, struct pt_regs *, long int);

struct pt_regs_offset {
	const char *name;
	int offset;
};

enum aarch64_regset {
	REGSET_GPR = 0,
	REGSET_FPR = 1,
	REGSET_TLS = 2,
	REGSET_HW_BREAK = 3,
	REGSET_HW_WATCH = 4,
	REGSET_SYSTEM_CALL = 5,
	REGSET_SVE = 6,
	REGSET_SSVE = 7,
	REGSET_ZA = 8,
	REGSET_ZT = 9,
	REGSET_PAC_MASK = 10,
	REGSET_PAC_ENABLED_KEYS = 11,
	REGSET_TAGGED_ADDR_CTRL = 12,
};

enum ptrace_syscall_dir {
	PTRACE_SYSCALL_ENTER = 0,
	PTRACE_SYSCALL_EXIT = 1,
};

typedef short int __s16;

typedef __s16 s16;

typedef __u64 Elf64_Off;

typedef __s64 Elf64_Sxword;

struct elf64_rela {
	Elf64_Addr r_offset;
	Elf64_Xword r_info;
	Elf64_Sxword r_addend;
};

typedef struct elf64_rela Elf64_Rela;

struct elf64_hdr {
	unsigned char e_ident[16];
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;
	Elf64_Off e_phoff;
	Elf64_Off e_shoff;
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_phnum;
	Elf64_Half e_shentsize;
	Elf64_Half e_shnum;
	Elf64_Half e_shstrndx;
};

typedef struct elf64_hdr Elf64_Ehdr;

struct elf64_shdr {
	Elf64_Word sh_name;
	Elf64_Word sh_type;
	Elf64_Xword sh_flags;
	Elf64_Addr sh_addr;
	Elf64_Off sh_offset;
	Elf64_Xword sh_size;
	Elf64_Word sh_link;
	Elf64_Word sh_info;
	Elf64_Xword sh_addralign;
	Elf64_Xword sh_entsize;
};

typedef struct elf64_shdr Elf64_Shdr;

enum pcpu_fc {
	PCPU_FC_AUTO = 0,
	PCPU_FC_EMBED = 1,
	PCPU_FC_PAGE = 2,
	PCPU_FC_NR = 3,
};

enum node_states {
	N_POSSIBLE = 0,
	N_ONLINE = 1,
	N_NORMAL_MEMORY = 2,
	N_HIGH_MEMORY = 2,
	N_MEMORY = 3,
	N_CPU = 4,
	N_GENERIC_INITIATOR = 5,
	NR_NODE_STATES = 6,
};

enum {
	UNAME26 = 131072,
	ADDR_NO_RANDOMIZE = 262144,
	FDPIC_FUNCPTRS = 524288,
	MMAP_PAGE_ZERO = 1048576,
	ADDR_COMPAT_LAYOUT = 2097152,
	READ_IMPLIES_EXEC = 4194304,
	ADDR_LIMIT_32BIT = 8388608,
	SHORT_INODE = 16777216,
	WHOLE_SECONDS = 33554432,
	STICKY_TIMEOUTS = 67108864,
	ADDR_LIMIT_3GB = 134217728,
};

enum {
	MM_FILEPAGES = 0,
	MM_ANONPAGES = 1,
	MM_SWAPENTS = 2,
	MM_SHMEMPAGES = 3,
	NR_MM_COUNTERS = 4,
};

enum aarch64_insn_imm_type {
	AARCH64_INSN_IMM_ADR = 0,
	AARCH64_INSN_IMM_26 = 1,
	AARCH64_INSN_IMM_19 = 2,
	AARCH64_INSN_IMM_16 = 3,
	AARCH64_INSN_IMM_14 = 4,
	AARCH64_INSN_IMM_12 = 5,
	AARCH64_INSN_IMM_9 = 6,
	AARCH64_INSN_IMM_7 = 7,
	AARCH64_INSN_IMM_6 = 8,
	AARCH64_INSN_IMM_S = 9,
	AARCH64_INSN_IMM_R = 10,
	AARCH64_INSN_IMM_N = 11,
	AARCH64_INSN_IMM_MAX = 12,
};

enum aarch64_insn_branch_type {
	AARCH64_INSN_BRANCH_NOLINK = 0,
	AARCH64_INSN_BRANCH_LINK = 1,
	AARCH64_INSN_BRANCH_RETURN = 2,
	AARCH64_INSN_BRANCH_COMP_ZERO = 3,
	AARCH64_INSN_BRANCH_COMP_NONZERO = 4,
};

enum migratetype {
	MIGRATE_UNMOVABLE = 0,
	MIGRATE_MOVABLE = 1,
	MIGRATE_RECLAIMABLE = 2,
	MIGRATE_PCPTYPES = 3,
	MIGRATE_HIGHATOMIC = 3,
	MIGRATE_TYPES = 4,
};

enum zone_stat_item {
	NR_FREE_PAGES = 0,
	NR_ZONE_LRU_BASE = 1,
	NR_ZONE_INACTIVE_ANON = 1,
	NR_ZONE_ACTIVE_ANON = 2,
	NR_ZONE_INACTIVE_FILE = 3,
	NR_ZONE_ACTIVE_FILE = 4,
	NR_ZONE_UNEVICTABLE = 5,
	NR_ZONE_WRITE_PENDING = 6,
	NR_MLOCK = 7,
	NR_BOUNCE = 8,
	NR_FREE_CMA_PAGES = 9,
	NR_VM_ZONE_STAT_ITEMS = 10,
};

enum node_stat_item {
	NR_LRU_BASE = 0,
	NR_INACTIVE_ANON = 0,
	NR_ACTIVE_ANON = 1,
	NR_INACTIVE_FILE = 2,
	NR_ACTIVE_FILE = 3,
	NR_UNEVICTABLE = 4,
	NR_SLAB_RECLAIMABLE_B = 5,
	NR_SLAB_UNRECLAIMABLE_B = 6,
	NR_ISOLATED_ANON = 7,
	NR_ISOLATED_FILE = 8,
	WORKINGSET_NODES = 9,
	WORKINGSET_REFAULT_BASE = 10,
	WORKINGSET_REFAULT_ANON = 10,
	WORKINGSET_REFAULT_FILE = 11,
	WORKINGSET_ACTIVATE_BASE = 12,
	WORKINGSET_ACTIVATE_ANON = 12,
	WORKINGSET_ACTIVATE_FILE = 13,
	WORKINGSET_RESTORE_BASE = 14,
	WORKINGSET_RESTORE_ANON = 14,
	WORKINGSET_RESTORE_FILE = 15,
	WORKINGSET_NODERECLAIM = 16,
	NR_ANON_MAPPED = 17,
	NR_FILE_MAPPED = 18,
	NR_FILE_PAGES = 19,
	NR_FILE_DIRTY = 20,
	NR_WRITEBACK = 21,
	NR_WRITEBACK_TEMP = 22,
	NR_SHMEM = 23,
	NR_SHMEM_THPS = 24,
	NR_SHMEM_PMDMAPPED = 25,
	NR_FILE_THPS = 26,
	NR_FILE_PMDMAPPED = 27,
	NR_ANON_THPS = 28,
	NR_VMSCAN_WRITE = 29,
	NR_VMSCAN_IMMEDIATE = 30,
	NR_DIRTIED = 31,
	NR_WRITTEN = 32,
	NR_THROTTLED_WRITTEN = 33,
	NR_KERNEL_MISC_RECLAIMABLE = 34,
	NR_FOLL_PIN_ACQUIRED = 35,
	NR_FOLL_PIN_RELEASED = 36,
	NR_KERNEL_STACK_KB = 37,
	NR_PAGETABLE = 38,
	NR_SECONDARY_PAGETABLE = 39,
	NR_VM_NODE_STAT_ITEMS = 40,
};

enum lru_list {
	LRU_INACTIVE_ANON = 0,
	LRU_ACTIVE_ANON = 1,
	LRU_INACTIVE_FILE = 2,
	LRU_ACTIVE_FILE = 3,
	LRU_UNEVICTABLE = 4,
	NR_LRU_LISTS = 5,
};

enum vmscan_throttle_state {
	VMSCAN_THROTTLE_WRITEBACK = 0,
	VMSCAN_THROTTLE_ISOLATED = 1,
	VMSCAN_THROTTLE_NOPROGRESS = 2,
	VMSCAN_THROTTLE_CONGESTED = 3,
	NR_VMSCAN_THROTTLE = 4,
};

enum zone_watermarks {
	WMARK_MIN = 0,
	WMARK_LOW = 1,
	WMARK_HIGH = 2,
	WMARK_PROMO = 3,
	NR_WMARK = 4,
};

enum {
	ZONELIST_FALLBACK = 0,
	MAX_ZONELISTS = 1,
};

enum hrtimer_base_type {
	HRTIMER_BASE_MONOTONIC = 0,
	HRTIMER_BASE_REALTIME = 1,
	HRTIMER_BASE_BOOTTIME = 2,
	HRTIMER_BASE_TAI = 3,
	HRTIMER_BASE_MONOTONIC_SOFT = 4,
	HRTIMER_BASE_REALTIME_SOFT = 5,
	HRTIMER_BASE_BOOTTIME_SOFT = 6,
	HRTIMER_BASE_TAI_SOFT = 7,
	HRTIMER_MAX_CLOCK_BASES = 8,
};

enum rseq_cs_flags_bit {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT = 0,
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT = 1,
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT = 2,
};

enum {
	TASK_COMM_LEN = 16,
};

enum kmalloc_cache_type {
	KMALLOC_NORMAL = 0,
	KMALLOC_CGROUP = 0,
	KMALLOC_RECLAIM = 1,
	KMALLOC_DMA = 2,
	NR_KMALLOC_TYPES = 3,
};

enum {
	DQF_ROOT_SQUASH_B = 0,
	DQF_SYS_FILE_B = 16,
	DQF_PRIVATE = 17,
};

enum {
	DQST_LOOKUPS = 0,
	DQST_DROPS = 1,
	DQST_READS = 2,
	DQST_WRITES = 3,
	DQST_CACHE_HITS = 4,
	DQST_ALLOC_DQUOTS = 5,
	DQST_FREE_DQUOTS = 6,
	DQST_SYNCS = 7,
	_DQST_DQSTAT_LAST = 8,
};

enum {
	SB_UNFROZEN = 0,
	SB_FREEZE_WRITE = 1,
	SB_FREEZE_PAGEFAULT = 2,
	SB_FREEZE_FS = 3,
	SB_FREEZE_COMPLETE = 4,
};

enum compound_dtor_id {
	NULL_COMPOUND_DTOR = 0,
	COMPOUND_PAGE_DTOR = 1,
	NR_COMPOUND_DTORS = 2,
};

enum aarch64_reloc_op {
	RELOC_OP_NONE = 0,
	RELOC_OP_ABS = 1,
	RELOC_OP_PREL = 2,
	RELOC_OP_PAGE = 3,
};

enum aarch64_insn_movw_imm_type {
	AARCH64_INSN_IMM_MOVNZ = 0,
	AARCH64_INSN_IMM_MOVKZ = 1,
};

enum pageflags {
	PG_locked = 0,
	PG_referenced = 1,
	PG_uptodate = 2,
	PG_dirty = 3,
	PG_lru = 4,
	PG_active = 5,
	PG_workingset = 6,
	PG_waiters = 7,
	PG_error = 8,
	PG_slab = 9,
	PG_owner_priv_1 = 10,
	PG_arch_1 = 11,
	PG_reserved = 12,
	PG_private = 13,
	PG_private_2 = 14,
	PG_writeback = 15,
	PG_head = 16,
	PG_mappedtodisk = 17,
	PG_reclaim = 18,
	PG_swapbacked = 19,
	PG_unevictable = 20,
	PG_mlocked = 21,
	PG_arch_2 = 22,
	PG_arch_3 = 23,
	__NR_PAGEFLAGS = 24,
	PG_readahead = 18,
	PG_anon_exclusive = 17,
	PG_checked = 10,
	PG_swapcache = 10,
	PG_fscache = 14,
	PG_pinned = 10,
	PG_savepinned = 3,
	PG_foreign = 10,
	PG_xen_remapped = 10,
	PG_isolated = 18,
	PG_reported = 2,
};

struct wait_queue_entry;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned int, int, void *);

struct wait_queue_entry {
	unsigned int flags;
	void *private;
	wait_queue_func_t func;
	struct list_head entry;
};

typedef struct wait_queue_entry wait_queue_entry_t;

typedef struct {
	long unsigned int val;
} swp_entry_t;

struct reclaim_state {
	long unsigned int reclaimed;
};

struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
};

enum wb_reason {
	WB_REASON_BACKGROUND = 0,
	WB_REASON_VMSCAN = 1,
	WB_REASON_SYNC = 2,
	WB_REASON_PERIODIC = 3,
	WB_REASON_LAPTOP_TIMER = 4,
	WB_REASON_FS_FREE_SPACE = 5,
	WB_REASON_FORKER_THREAD = 6,
	WB_REASON_FOREIGN_FLUSH = 7,
	WB_REASON_MAX = 8,
};

struct bdi_writeback {
	struct backing_dev_info *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
};

struct backing_dev_info {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback wb;
	struct list_head wb_list;
	wait_queue_head_t wb_waitq;
	struct device *dev;
	char dev_name[64];
	struct device *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry *debug_dir;
};

struct xa_node {
	unsigned char shift;
	unsigned char offset;
	unsigned char count;
	unsigned char nr_values;
	struct xa_node *parent;
	struct xarray *array;
	union {
		struct list_head private_list;
		struct callback_head callback_head;
	};
	void *slots[16];
	union {
		long unsigned int tags[3];
		long unsigned int marks[3];
	};
};

typedef void (*xa_update_node_t)(struct xa_node *);

struct xa_state {
	struct xarray *xa;
	long unsigned int xa_index;
	unsigned char xa_shift;
	unsigned char xa_sibs;
	unsigned char xa_offset;
	unsigned char xa_pad;
	struct xa_node *xa_node;
	struct xa_node *xa_alloc;
	xa_update_node_t xa_update;
	struct list_lru *xa_lru;
};

struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};

enum writeback_sync_modes {
	WB_SYNC_NONE = 0,
	WB_SYNC_ALL = 1,
};

struct swap_iocb;

struct writeback_control {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	struct swap_iocb **swap_plug;
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	long unsigned int _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
	bool _workingset;
	long unsigned int _pflags;
};

struct swap_cluster_info {
	spinlock_t lock;
	unsigned int data: 24;
	unsigned int flags: 8;
};

struct swap_cluster_list {
	struct swap_cluster_info head;
	struct swap_cluster_info tail;
};

struct percpu_cluster;

struct swap_info_struct {
	struct percpu_ref users;
	long unsigned int flags;
	short int prio;
	struct plist_node list;
	signed char type;
	unsigned int max;
	unsigned char *swap_map;
	struct swap_cluster_info *cluster_info;
	struct swap_cluster_list free_clusters;
	unsigned int lowest_bit;
	unsigned int highest_bit;
	unsigned int pages;
	unsigned int inuse_pages;
	unsigned int cluster_next;
	unsigned int cluster_nr;
	unsigned int *cluster_next_cpu;
	struct percpu_cluster *percpu_cluster;
	struct rb_root swap_extent_root;
	struct block_device *bdev;
	struct file *swap_file;
	unsigned int old_block_size;
	struct completion comp;
	spinlock_t lock;
	spinlock_t cont_lock;
	struct work_struct discard_work;
	struct swap_cluster_list discard_clusters;
	struct plist_node avail_lists[0];
};

struct disk_stats;

struct gendisk;

struct request_queue;

struct blk_holder_ops;

struct partition_meta_info;

struct block_device {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	u8 bd_partno;
	bool bd_write_holder;
	bool bd_has_submit_bio;
	dev_t bd_dev;
	atomic_t bd_openers;
	spinlock_t bd_size_lock;
	struct inode *bd_inode;
	struct super_block *bd_super;
	void *bd_claiming;
	void *bd_holder;
	const struct blk_holder_ops *bd_holder_ops;
	struct mutex bd_holder_lock;
	int bd_fsfreeze_count;
	int bd_holders;
	struct kobject *bd_holder_dir;
	struct mutex bd_fsfreeze_mutex;
	struct super_block *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
	struct device bd_device;
};

enum wb_stat_item {
	WB_RECLAIMABLE = 0,
	WB_WRITEBACK = 1,
	WB_DIRTIED = 2,
	WB_WRITTEN = 3,
	NR_WB_STAT_ITEMS = 4,
};

struct blk_holder_ops {
	void (*mark_dead)(struct block_device *);
};

typedef __u32 blk_opf_t;

struct percpu_cluster {
	struct swap_cluster_info index;
	unsigned int next;
};

struct static_key_false {
	struct static_key key;
};

struct sysinfo {
	__kernel_long_t uptime;
	__kernel_ulong_t loads[3];
	__kernel_ulong_t totalram;
	__kernel_ulong_t freeram;
	__kernel_ulong_t sharedram;
	__kernel_ulong_t bufferram;
	__kernel_ulong_t totalswap;
	__kernel_ulong_t freeswap;
	__u16 procs;
	__u16 pad;
	__kernel_ulong_t totalhigh;
	__kernel_ulong_t freehigh;
	__u32 mem_unit;
	char _f[0];
};

struct __kernel_old_timeval {
	__kernel_long_t tv_sec;
	__kernel_long_t tv_usec;
};

struct prctl_mm_map {
	__u64 start_code;
	__u64 end_code;
	__u64 start_data;
	__u64 end_data;
	__u64 start_brk;
	__u64 brk;
	__u64 start_stack;
	__u64 arg_start;
	__u64 arg_end;
	__u64 env_start;
	__u64 env_end;
	__u64 *auxv;
	__u32 auxv_size;
	__u32 exe_fd;
};

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF = 0,
	REFCOUNT_ADD_OVF = 1,
	REFCOUNT_ADD_UAF = 2,
	REFCOUNT_SUB_UAF = 3,
	REFCOUNT_DEC_LEAK = 4,
};

enum tk_offsets {
	TK_OFFS_REAL = 0,
	TK_OFFS_BOOT = 1,
	TK_OFFS_TAI = 2,
	TK_OFFS_MAX = 3,
};

struct anon_vma {
	struct anon_vma *root;
	struct rw_semaphore rwsem;
	atomic_t refcount;
	long unsigned int num_children;
	long unsigned int num_active_vmas;
	struct anon_vma *parent;
	struct rb_root_cached rb_root;
};

struct linux_binprm;

struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *);
	int (*load_shlib)(struct file *);
};

struct rusage {
	struct __kernel_old_timeval ru_utime;
	struct __kernel_old_timeval ru_stime;
	__kernel_long_t ru_maxrss;
	__kernel_long_t ru_ixrss;
	__kernel_long_t ru_idrss;
	__kernel_long_t ru_isrss;
	__kernel_long_t ru_minflt;
	__kernel_long_t ru_majflt;
	__kernel_long_t ru_nswap;
	__kernel_long_t ru_inblock;
	__kernel_long_t ru_oublock;
	__kernel_long_t ru_msgsnd;
	__kernel_long_t ru_msgrcv;
	__kernel_long_t ru_nsignals;
	__kernel_long_t ru_nvcsw;
	__kernel_long_t ru_nivcsw;
};

struct rlimit64 {
	__u64 rlim_cur;
	__u64 rlim_max;
};

struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_spinlock_t seq;
	int umask;
	int in_exec;
	struct path root;
	struct path pwd;
};

struct ld_semaphore {
	atomic_long_t count;
	raw_spinlock_t wait_lock;
	unsigned int wait_readers;
	struct list_head read_wait;
	struct list_head write_wait;
};

typedef unsigned int tcflag_t;

typedef unsigned char cc_t;

typedef unsigned int speed_t;

struct ktermios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[19];
	speed_t c_ispeed;
	speed_t c_ospeed;
};

struct winsize {
	short unsigned int ws_row;
	short unsigned int ws_col;
	short unsigned int ws_xpixel;
	short unsigned int ws_ypixel;
};

struct tty_driver;

struct tty_operations;

struct tty_ldisc;

struct tty_port;

struct tty_struct {
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;
	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	struct ktermios termios;
	struct ktermios termios_locked;
	char name[64];
	long unsigned int flags;
	int count;
	struct winsize winsize;
	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		long unsigned int unused[0];
	} flow;
	struct {
		spinlock_t lock;
		struct pid *pgrp;
		struct pid *session;
		unsigned char pktstatus;
		bool packet;
		long unsigned int unused[0];
	} ctrl;
	bool hw_stopped;
	unsigned int receive_room;
	int flow_change;
	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;
	struct list_head tty_files;
	int closing;
	unsigned char *write_buf;
	int write_cnt;
	struct work_struct SAK_work;
	struct tty_port *port;
};

typedef int (*proc_visitor)(struct task_struct *, void *);

struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct uts_namespace {
	struct new_utsname name;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
};

struct timens_offsets {
	struct timespec64 monotonic;
	struct timespec64 boottime;
};

struct time_namespace {
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
	struct timens_offsets offsets;
	struct page *vvar_page;
	bool frozen_offsets;
};

struct proc_dir_entry;

enum {
	EI_ETYPE_NULL = 0,
	EI_ETYPE_ERRNO = 1,
	EI_ETYPE_ERRNO_NULL = 2,
	EI_ETYPE_TRUE = 3,
};

enum uts_proc {
	UTS_PROC_ARCH = 0,
	UTS_PROC_OSTYPE = 1,
	UTS_PROC_OSRELEASE = 2,
	UTS_PROC_VERSION = 3,
	UTS_PROC_HOSTNAME = 4,
	UTS_PROC_DOMAINNAME = 5,
};

struct fd {
	struct file *file;
	unsigned int flags;
};

struct tms {
	__kernel_clock_t tms_utime;
	__kernel_clock_t tms_stime;
	__kernel_clock_t tms_cutime;
	__kernel_clock_t tms_cstime;
};

struct tty_buffer {
	union {
		struct tty_buffer *next;
		struct llist_node free;
	};
	int used;
	int size;
	int commit;
	int lookahead;
	int read;
	bool flags;
	long unsigned int data[0];
};

struct tty_bufhead {
	struct tty_buffer *head;
	struct work_struct work;
	struct mutex lock;
	atomic_t priority;
	struct tty_buffer sentinel;
	struct llist_head free;
	atomic_t mem_used;
	int mem_limit;
	struct tty_buffer *tail;
};

struct serial_icounter_struct;

struct serial_struct;

struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *, struct file *, int);
	int (*install)(struct tty_driver *, struct tty_struct *);
	void (*remove)(struct tty_driver *, struct tty_struct *);
	int (*open)(struct tty_struct *, struct file *);
	void (*close)(struct tty_struct *, struct file *);
	void (*shutdown)(struct tty_struct *);
	void (*cleanup)(struct tty_struct *);
	int (*write)(struct tty_struct *, const unsigned char *, int);
	int (*put_char)(struct tty_struct *, unsigned char);
	void (*flush_chars)(struct tty_struct *);
	unsigned int (*write_room)(struct tty_struct *);
	unsigned int (*chars_in_buffer)(struct tty_struct *);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, const struct ktermios *);
	void (*throttle)(struct tty_struct *);
	void (*unthrottle)(struct tty_struct *);
	void (*stop)(struct tty_struct *);
	void (*start)(struct tty_struct *);
	void (*hangup)(struct tty_struct *);
	int (*break_ctl)(struct tty_struct *, int);
	void (*flush_buffer)(struct tty_struct *);
	void (*set_ldisc)(struct tty_struct *);
	void (*wait_until_sent)(struct tty_struct *, int);
	void (*send_xchar)(struct tty_struct *, char);
	int (*tiocmget)(struct tty_struct *);
	int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);
	int (*resize)(struct tty_struct *, struct winsize *);
	int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *);
	int (*get_serial)(struct tty_struct *, struct serial_struct *);
	int (*set_serial)(struct tty_struct *, struct serial_struct *);
	void (*show_fdinfo)(struct tty_struct *, struct seq_file *);
	int (*proc_show)(struct seq_file *, void *);
};

struct tty_driver {
	struct kref kref;
	struct cdev **cdevs;
	struct module *owner;
	const char *driver_name;
	const char *name;
	int name_base;
	int major;
	int minor_start;
	unsigned int num;
	short int type;
	short int subtype;
	struct ktermios init_termios;
	long unsigned int flags;
	struct proc_dir_entry *proc_entry;
	struct tty_driver *other;
	struct tty_struct **ttys;
	struct tty_port **ports;
	struct ktermios **termios;
	void *driver_state;
	const struct tty_operations *ops;
	struct list_head tty_drivers;
};

struct __kfifo {
	unsigned int in;
	unsigned int out;
	unsigned int mask;
	unsigned int esize;
	void *data;
};

struct tty_port_operations;

struct tty_port_client_operations;

struct tty_port {
	struct tty_bufhead buf;
	struct tty_struct *tty;
	struct tty_struct *itty;
	const struct tty_port_operations *ops;
	const struct tty_port_client_operations *client_ops;
	spinlock_t lock;
	int blocked_open;
	int count;
	wait_queue_head_t open_wait;
	wait_queue_head_t delta_msr_wait;
	long unsigned int flags;
	long unsigned int iflags;
	unsigned char console: 1;
	struct mutex mutex;
	struct mutex buf_mutex;
	unsigned char *xmit_buf;
	struct {
		union {
			struct __kfifo kfifo;
			unsigned char *type;
			const unsigned char *const_type;
			char (*rectype)[0];
			unsigned char *ptr;
			const unsigned char *ptr_const;
		};
		unsigned char buf[0];
	} xmit_fifo;
	unsigned int close_delay;
	unsigned int closing_wait;
	int drain_delay;
	struct kref kref;
	void *client_data;
};

struct tty_ldisc_ops {
	char *name;
	int num;
	int (*open)(struct tty_struct *);
	void (*close)(struct tty_struct *);
	void (*flush_buffer)(struct tty_struct *);
	ssize_t (*read)(struct tty_struct *, struct file *, unsigned char *, size_t, void **, long unsigned int);
	ssize_t (*write)(struct tty_struct *, struct file *, const unsigned char *, size_t);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, const struct ktermios *);
	__poll_t (*poll)(struct tty_struct *, struct file *, struct poll_table_struct *);
	void (*hangup)(struct tty_struct *);
	void (*receive_buf)(struct tty_struct *, const unsigned char *, const char *, int);
	void (*write_wakeup)(struct tty_struct *);
	void (*dcd_change)(struct tty_struct *, bool);
	int (*receive_buf2)(struct tty_struct *, const unsigned char *, const char *, int);
	void (*lookahead_buf)(struct tty_struct *, const unsigned char *, const unsigned char *, unsigned int);
	struct module *owner;
};

struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
};

struct tty_port_operations {
	bool (*carrier_raised)(struct tty_port *);
	void (*dtr_rts)(struct tty_port *, bool);
	void (*shutdown)(struct tty_port *);
	int (*activate)(struct tty_port *, struct tty_struct *);
	void (*destruct)(struct tty_port *);
};

struct tty_port_client_operations {
	int (*receive_buf)(struct tty_port *, const unsigned char *, const unsigned char *, size_t);
	void (*lookahead_buf)(struct tty_port *, const unsigned char *, const unsigned char *, unsigned int);
	void (*write_wakeup)(struct tty_port *);
};

struct getcpu_cache {
	long unsigned int blob[16];
};

struct linux_binprm {
	struct vm_area_struct *vma;
	long unsigned int vma_pages;
	struct mm_struct *mm;
	long unsigned int p;
	long unsigned int argmin;
	unsigned int have_execfd: 1;
	unsigned int execfd_creds: 1;
	unsigned int secureexec: 1;
	unsigned int point_of_no_return: 1;
	struct file *executable;
	struct file *interpreter;
	struct file *file;
	struct cred *cred;
	int unsafe;
	unsigned int per_clear;
	int argc;
	int envc;
	const char *filename;
	const char *interp;
	const char *fdpath;
	unsigned int interp_flags;
	int execfd;
	long unsigned int loader;
	long unsigned int exec;
	struct rlimit rlim_stack;
	char buf[256];
};

struct irq_desc;

typedef void (*irq_flow_handler_t)(struct irq_desc *);

struct msi_desc;

struct irq_common_data {
	unsigned int state_use_accessors;
	void *handler_data;
	struct msi_desc *msi_desc;
	cpumask_var_t affinity;
	cpumask_var_t effective_affinity;
	unsigned int ipi_offset;
};

struct irq_chip;

struct irq_data {
	u32 mask;
	unsigned int irq;
	long unsigned int hwirq;
	struct irq_common_data *common;
	struct irq_chip *chip;
	struct irq_domain *domain;
	struct irq_data *parent_data;
	void *chip_data;
};

struct irqaction;

struct irq_affinity_notify;

struct irq_desc {
	struct irq_common_data irq_common_data;
	struct irq_data irq_data;
	unsigned int *kstat_irqs;
	irq_flow_handler_t handle_irq;
	struct irqaction *action;
	unsigned int status_use_accessors;
	unsigned int core_internal_state__do_not_mess_with_it;
	unsigned int depth;
	unsigned int wake_depth;
	unsigned int tot_count;
	unsigned int irq_count;
	long unsigned int last_unhandled;
	unsigned int irqs_unhandled;
	atomic_t threads_handled;
	int threads_handled_last;
	raw_spinlock_t lock;
	struct cpumask *percpu_enabled;
	const struct cpumask *percpu_affinity;
	const struct cpumask *affinity_hint;
	struct irq_affinity_notify *affinity_notify;
	long unsigned int threads_oneshot;
	atomic_t threads_active;
	wait_queue_head_t wait_for_threads;
	struct callback_head rcu;
	struct kobject kobj;
	struct mutex request_mutex;
	int parent_irq;
	struct module *owner;
	const char *name;
	struct hlist_node resend_node;
};

enum irqreturn {
	IRQ_NONE = 0,
	IRQ_HANDLED = 1,
	IRQ_WAKE_THREAD = 2,
};

typedef enum irqreturn irqreturn_t;

enum {
	IRQ_TYPE_NONE = 0,
	IRQ_TYPE_EDGE_RISING = 1,
	IRQ_TYPE_EDGE_FALLING = 2,
	IRQ_TYPE_EDGE_BOTH = 3,
	IRQ_TYPE_LEVEL_HIGH = 4,
	IRQ_TYPE_LEVEL_LOW = 8,
	IRQ_TYPE_LEVEL_MASK = 12,
	IRQ_TYPE_SENSE_MASK = 15,
	IRQ_TYPE_DEFAULT = 15,
	IRQ_TYPE_PROBE = 16,
	IRQ_LEVEL = 256,
	IRQ_PER_CPU = 512,
	IRQ_NOPROBE = 1024,
	IRQ_NOREQUEST = 2048,
	IRQ_NOAUTOEN = 4096,
	IRQ_NO_BALANCING = 8192,
	IRQ_MOVE_PCNTXT = 16384,
	IRQ_NESTED_THREAD = 32768,
	IRQ_NOTHREAD = 65536,
	IRQ_PER_CPU_DEVID = 131072,
	IRQ_IS_POLLED = 262144,
	IRQ_DISABLE_UNLAZY = 524288,
	IRQ_HIDDEN = 1048576,
	IRQ_NO_DEBUG = 2097152,
};

enum irqchip_irq_state {
	IRQCHIP_STATE_PENDING = 0,
	IRQCHIP_STATE_ACTIVE = 1,
	IRQCHIP_STATE_MASKED = 2,
	IRQCHIP_STATE_LINE_LEVEL = 3,
};

struct msi_msg;

struct irq_chip {
	const char *name;
	unsigned int (*irq_startup)(struct irq_data *);
	void (*irq_shutdown)(struct irq_data *);
	void (*irq_enable)(struct irq_data *);
	void (*irq_disable)(struct irq_data *);
	void (*irq_ack)(struct irq_data *);
	void (*irq_mask)(struct irq_data *);
	void (*irq_mask_ack)(struct irq_data *);
	void (*irq_unmask)(struct irq_data *);
	void (*irq_eoi)(struct irq_data *);
	int (*irq_set_affinity)(struct irq_data *, const struct cpumask *, bool);
	int (*irq_retrigger)(struct irq_data *);
	int (*irq_set_type)(struct irq_data *, unsigned int);
	int (*irq_set_wake)(struct irq_data *, unsigned int);
	void (*irq_bus_lock)(struct irq_data *);
	void (*irq_bus_sync_unlock)(struct irq_data *);
	void (*irq_suspend)(struct irq_data *);
	void (*irq_resume)(struct irq_data *);
	void (*irq_pm_shutdown)(struct irq_data *);
	void (*irq_calc_mask)(struct irq_data *);
	void (*irq_print_chip)(struct irq_data *, struct seq_file *);
	int (*irq_request_resources)(struct irq_data *);
	void (*irq_release_resources)(struct irq_data *);
	void (*irq_compose_msi_msg)(struct irq_data *, struct msi_msg *);
	void (*irq_write_msi_msg)(struct irq_data *, struct msi_msg *);
	int (*irq_get_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool *);
	int (*irq_set_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool);
	int (*irq_set_vcpu_affinity)(struct irq_data *, void *);
	void (*ipi_send_single)(struct irq_data *, unsigned int);
	void (*ipi_send_mask)(struct irq_data *, const struct cpumask *);
	int (*irq_nmi_setup)(struct irq_data *);
	void (*irq_nmi_teardown)(struct irq_data *);
	long unsigned int flags;
};

enum {
	IRQD_TRIGGER_MASK = 15,
	IRQD_SETAFFINITY_PENDING = 256,
	IRQD_ACTIVATED = 512,
	IRQD_NO_BALANCING = 1024,
	IRQD_PER_CPU = 2048,
	IRQD_AFFINITY_SET = 4096,
	IRQD_LEVEL = 8192,
	IRQD_WAKEUP_STATE = 16384,
	IRQD_MOVE_PCNTXT = 32768,
	IRQD_IRQ_DISABLED = 65536,
	IRQD_IRQ_MASKED = 131072,
	IRQD_IRQ_INPROGRESS = 262144,
	IRQD_WAKEUP_ARMED = 524288,
	IRQD_FORWARDED_TO_VCPU = 1048576,
	IRQD_AFFINITY_MANAGED = 2097152,
	IRQD_IRQ_STARTED = 4194304,
	IRQD_MANAGED_SHUTDOWN = 8388608,
	IRQD_SINGLE_TARGET = 16777216,
	IRQD_DEFAULT_TRIGGER_SET = 33554432,
	IRQD_CAN_RESERVE = 67108864,
	IRQD_MSI_NOMASK_QUIRK = 134217728,
	IRQD_HANDLE_ENFORCE_IRQCTX = 268435456,
	IRQD_AFFINITY_ON_ACTIVATE = 536870912,
	IRQD_IRQ_ENABLED_ON_SUSPEND = 1073741824,
	IRQD_RESEND_WHEN_IN_PROGRESS = 2147483648,
};

typedef irqreturn_t (*irq_handler_t)(int, void *);

struct irqaction {
	irq_handler_t handler;
	void *dev_id;
	void *percpu_dev_id;
	struct irqaction *next;
	irq_handler_t thread_fn;
	struct task_struct *thread;
	struct irqaction *secondary;
	unsigned int irq;
	unsigned int flags;
	long unsigned int thread_flags;
	long unsigned int thread_mask;
	const char *name;
	struct proc_dir_entry *dir;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct irq_affinity_notify {
	unsigned int irq;
	struct kref kref;
	struct work_struct work;
	void (*notify)(struct irq_affinity_notify *, const cpumask_t *);
	void (*release)(struct kref *);
};

struct kernel_stat {
	long unsigned int irqs_sum;
	unsigned int softirqs[10];
};

enum {
	IRQTF_RUNTHREAD = 0,
	IRQTF_WARNED = 1,
	IRQTF_AFFINITY = 2,
	IRQTF_FORCED_THREAD = 3,
	IRQTF_READY = 4,
};

enum {
	IRQS_AUTODETECT = 1,
	IRQS_SPURIOUS_DISABLED = 2,
	IRQS_POLL_INPROGRESS = 8,
	IRQS_ONESHOT = 32,
	IRQS_REPLAY = 64,
	IRQS_WAITING = 128,
	IRQS_PENDING = 512,
	IRQS_SUSPENDED = 2048,
	IRQS_TIMINGS = 4096,
	IRQS_NMI = 8192,
	IRQS_SYSFS = 16384,
};

enum {
	_IRQ_DEFAULT_INIT_FLAGS = 0,
	_IRQ_PER_CPU = 512,
	_IRQ_LEVEL = 256,
	_IRQ_NOPROBE = 1024,
	_IRQ_NOREQUEST = 2048,
	_IRQ_NOTHREAD = 65536,
	_IRQ_NOAUTOEN = 4096,
	_IRQ_MOVE_PCNTXT = 16384,
	_IRQ_NO_BALANCING = 8192,
	_IRQ_NESTED_THREAD = 32768,
	_IRQ_PER_CPU_DEVID = 131072,
	_IRQ_IS_POLLED = 262144,
	_IRQ_DISABLE_UNLAZY = 524288,
	_IRQ_HIDDEN = 1048576,
	_IRQ_NO_DEBUG = 2097152,
	_IRQF_MODIFY_MASK = 2096911,
};

typedef long unsigned int irq_hw_number_t;

struct arch_msi_msg_addr_lo {
	u32 address_lo;
};

typedef struct arch_msi_msg_addr_lo arch_msi_msg_addr_lo_t;

struct arch_msi_msg_addr_hi {
	u32 address_hi;
};

typedef struct arch_msi_msg_addr_hi arch_msi_msg_addr_hi_t;

struct arch_msi_msg_data {
	u32 data;
};

typedef struct arch_msi_msg_data arch_msi_msg_data_t;

struct msi_msg {
	union {
		u32 address_lo;
		arch_msi_msg_addr_lo_t arch_addr_lo;
	};
	union {
		u32 address_hi;
		arch_msi_msg_addr_hi_t arch_addr_hi;
	};
	union {
		u32 data;
		arch_msi_msg_data_t arch_data;
	};
};

struct pci_msi_desc {
	union {
		u32 msi_mask;
		u32 msix_ctrl;
	};
	struct {
		u8 is_msix: 1;
		u8 multiple: 3;
		u8 multi_cap: 3;
		u8 can_mask: 1;
		u8 is_64: 1;
		u8 is_virtual: 1;
		unsigned int default_irq;
	} msi_attrib;
	union {
		u8 mask_pos;
		void *mask_base;
	};
};

union msi_domain_cookie {
	u64 value;
	void *ptr;
	void *iobase;
};

union msi_instance_cookie {
	u64 value;
	void *ptr;
};

struct msi_desc_data {
	union msi_domain_cookie dcookie;
	union msi_instance_cookie icookie;
};

struct irq_affinity_desc;

struct msi_desc {
	unsigned int irq;
	unsigned int nvec_used;
	struct device *dev;
	struct msi_msg msg;
	struct irq_affinity_desc *affinity;
	void (*write_msi_msg)(struct msi_desc *, void *);
	void *write_msi_msg_data;
	u16 msi_index;
	union {
		struct pci_msi_desc pci;
		struct msi_desc_data data;
	};
};

enum irq_domain_bus_token {
	DOMAIN_BUS_ANY = 0,
	DOMAIN_BUS_WIRED = 1,
	DOMAIN_BUS_GENERIC_MSI = 2,
	DOMAIN_BUS_PCI_MSI = 3,
	DOMAIN_BUS_PLATFORM_MSI = 4,
	DOMAIN_BUS_NEXUS = 5,
	DOMAIN_BUS_IPI = 6,
	DOMAIN_BUS_FSL_MC_MSI = 7,
	DOMAIN_BUS_TI_SCI_INTA_MSI = 8,
	DOMAIN_BUS_WAKEUP = 9,
	DOMAIN_BUS_VMD_MSI = 10,
	DOMAIN_BUS_PCI_DEVICE_MSI = 11,
	DOMAIN_BUS_PCI_DEVICE_MSIX = 12,
	DOMAIN_BUS_DMAR = 13,
	DOMAIN_BUS_AMDVI = 14,
	DOMAIN_BUS_PCI_DEVICE_IMS = 15,
};

struct irq_domain_ops;

struct irq_domain_chip_generic;

struct msi_parent_ops;

struct irq_domain {
	struct list_head link;
	const char *name;
	const struct irq_domain_ops *ops;
	void *host_data;
	unsigned int flags;
	unsigned int mapcount;
	struct mutex mutex;
	struct irq_domain *root;
	struct fwnode_handle *fwnode;
	enum irq_domain_bus_token bus_token;
	struct irq_domain_chip_generic *gc;
	struct device *dev;
	struct device *pm_dev;
	struct irq_domain *parent;
	const struct msi_parent_ops *msi_parent_ops;
	irq_hw_number_t hwirq_max;
	unsigned int revmap_size;
	struct xarray revmap_tree;
	struct irq_data *revmap[0];
};

enum {
	IRQCHIP_SET_TYPE_MASKED = 1,
	IRQCHIP_EOI_IF_HANDLED = 2,
	IRQCHIP_MASK_ON_SUSPEND = 4,
	IRQCHIP_ONOFFLINE_ENABLED = 8,
	IRQCHIP_SKIP_SET_WAKE = 16,
	IRQCHIP_ONESHOT_SAFE = 32,
	IRQCHIP_EOI_THREADED = 64,
	IRQCHIP_SUPPORTS_LEVEL_MSI = 128,
	IRQCHIP_SUPPORTS_NMI = 256,
	IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND = 512,
	IRQCHIP_AFFINITY_PRE_STARTUP = 1024,
	IRQCHIP_IMMUTABLE = 2048,
};

struct irq_chip_regs {
	long unsigned int enable;
	long unsigned int disable;
	long unsigned int mask;
	long unsigned int ack;
	long unsigned int eoi;
	long unsigned int type;
	long unsigned int polarity;
};

struct irq_chip_type {
	struct irq_chip chip;
	struct irq_chip_regs regs;
	irq_flow_handler_t handler;
	u32 type;
	u32 mask_cache_priv;
	u32 *mask_cache;
};

struct irq_chip_generic {
	raw_spinlock_t lock;
	void *reg_base;
	u32 (*reg_readl)(void *);
	void (*reg_writel)(u32, void *);
	void (*suspend)(struct irq_chip_generic *);
	void (*resume)(struct irq_chip_generic *);
	unsigned int irq_base;
	unsigned int irq_cnt;
	u32 mask_cache;
	u32 type_cache;
	u32 polarity_cache;
	u32 wake_enabled;
	u32 wake_active;
	unsigned int num_ct;
	void *private;
	long unsigned int installed;
	long unsigned int unused;
	struct irq_domain *domain;
	struct list_head list;
	struct irq_chip_type chip_types[0];
};

enum irq_gc_flags {
	IRQ_GC_INIT_MASK_CACHE = 1,
	IRQ_GC_INIT_NESTED_LOCK = 2,
	IRQ_GC_MASK_CACHE_PER_TYPE = 4,
	IRQ_GC_NO_MASK = 8,
	IRQ_GC_BE_IO = 16,
};

struct irq_domain_chip_generic {
	unsigned int irqs_per_chip;
	unsigned int num_chips;
	unsigned int irq_flags_to_clear;
	unsigned int irq_flags_to_set;
	enum irq_gc_flags gc_flags;
	struct irq_chip_generic *gc[0];
};

enum msi_domain_ids {
	MSI_DEFAULT_DOMAIN = 0,
	MSI_SECONDARY_DOMAIN = 1,
	MSI_MAX_DEVICE_IRQDOMAINS = 2,
};

struct msi_alloc_info {
	struct msi_desc *desc;
	irq_hw_number_t hwirq;
	long unsigned int flags;
	union {
		long unsigned int ul;
		void *ptr;
	} scratchpad[2];
};

typedef struct msi_alloc_info msi_alloc_info_t;

struct irq_affinity_desc {
	struct cpumask mask;
	unsigned int is_managed: 1;
};

struct msi_dev_domain {
	struct xarray store;
	struct irq_domain *domain;
};

struct platform_msi_priv_data;

struct msi_device_data {
	long unsigned int properties;
	struct platform_msi_priv_data *platform_data;
	struct mutex mutex;
	struct msi_dev_domain __domains[2];
	long unsigned int __iter_idx;
};

struct msi_domain_info;

struct msi_domain_ops {
	irq_hw_number_t (*get_hwirq)(struct msi_domain_info *, msi_alloc_info_t *);
	int (*msi_init)(struct irq_domain *, struct msi_domain_info *, unsigned int, irq_hw_number_t, msi_alloc_info_t *);
	void (*msi_free)(struct irq_domain *, struct msi_domain_info *, unsigned int);
	int (*msi_prepare)(struct irq_domain *, struct device *, int, msi_alloc_info_t *);
	void (*prepare_desc)(struct irq_domain *, msi_alloc_info_t *, struct msi_desc *);
	void (*set_desc)(msi_alloc_info_t *, struct msi_desc *);
	int (*domain_alloc_irqs)(struct irq_domain *, struct device *, int);
	void (*domain_free_irqs)(struct irq_domain *, struct device *);
	void (*msi_post_free)(struct irq_domain *, struct device *);
};

struct msi_domain_info {
	u32 flags;
	enum irq_domain_bus_token bus_token;
	unsigned int hwsize;
	struct msi_domain_ops *ops;
	struct irq_chip *chip;
	void *chip_data;
	irq_flow_handler_t handler;
	void *handler_data;
	const char *handler_name;
	void *data;
};

struct msi_parent_ops {
	u32 supported_flags;
	const char *prefix;
	bool (*init_dev_msi_info)(struct device *, struct irq_domain *, struct irq_domain *, struct msi_domain_info *);
};

typedef u32 phandle;

struct property {
	char *name;
	int length;
	void *value;
	struct property *next;
};

struct device_node {
	const char *name;
	phandle phandle;
	const char *full_name;
	struct fwnode_handle fwnode;
	struct property *properties;
	struct property *deadprops;
	struct device_node *parent;
	struct device_node *child;
	struct device_node *sibling;
	long unsigned int _flags;
	void *data;
};

struct irq_fwspec {
	struct fwnode_handle *fwnode;
	int param_count;
	u32 param[16];
};

struct irq_domain_ops {
	int (*match)(struct irq_domain *, struct device_node *, enum irq_domain_bus_token);
	int (*select)(struct irq_domain *, struct irq_fwspec *, enum irq_domain_bus_token);
	int (*map)(struct irq_domain *, unsigned int, irq_hw_number_t);
	void (*unmap)(struct irq_domain *, unsigned int);
	int (*xlate)(struct irq_domain *, struct device_node *, const u32 *, unsigned int, long unsigned int *, unsigned int *);
	int (*alloc)(struct irq_domain *, unsigned int, unsigned int, void *);
	void (*free)(struct irq_domain *, unsigned int, unsigned int);
	int (*activate)(struct irq_domain *, struct irq_data *, bool);
	void (*deactivate)(struct irq_domain *, struct irq_data *);
	int (*translate)(struct irq_domain *, struct irq_fwspec *, long unsigned int *, unsigned int *);
};

enum {
	IRQ_STARTUP_NORMAL = 0,
	IRQ_STARTUP_MANAGED = 1,
	IRQ_STARTUP_ABORT = 2,
};

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

typedef struct {
	long unsigned int bits[1];
} nodemask_t;

enum {
	WORK_STRUCT_PENDING_BIT = 0,
	WORK_STRUCT_INACTIVE_BIT = 1,
	WORK_STRUCT_PWQ_BIT = 2,
	WORK_STRUCT_LINKED_BIT = 3,
	WORK_STRUCT_COLOR_SHIFT = 4,
	WORK_STRUCT_COLOR_BITS = 4,
	WORK_STRUCT_PENDING = 1,
	WORK_STRUCT_INACTIVE = 2,
	WORK_STRUCT_PWQ = 4,
	WORK_STRUCT_LINKED = 8,
	WORK_STRUCT_STATIC = 0,
	WORK_NR_COLORS = 16,
	WORK_CPU_UNBOUND = 256,
	WORK_STRUCT_FLAG_BITS = 8,
	WORK_OFFQ_FLAG_BASE = 4,
	__WORK_OFFQ_CANCELING = 4,
	WORK_OFFQ_FLAG_BITS = 1,
	WORK_OFFQ_POOL_SHIFT = 5,
	WORK_OFFQ_LEFT = 59,
	WORK_OFFQ_POOL_BITS = 31,
	WORK_BUSY_PENDING = 1,
	WORK_BUSY_RUNNING = 2,
	WORKER_DESC_LEN = 24,
};

struct io_tlb_area;

struct io_tlb_slot;

struct io_tlb_mem {
	phys_addr_t start;
	phys_addr_t end;
	void *vaddr;
	long unsigned int nslabs;
	long unsigned int used;
	struct dentry *debugfs;
	bool late_alloc;
	bool force_bounce;
	bool for_alloc;
	unsigned int nareas;
	unsigned int area_nslabs;
	struct io_tlb_area *areas;
	struct io_tlb_slot *slots;
	atomic_long_t total_used;
	atomic_long_t used_hiwater;
};

struct gen_pool;

typedef long unsigned int (*genpool_algo_t)(long unsigned int *, long unsigned int, long unsigned int, unsigned int, void *, struct gen_pool *, long unsigned int);

struct gen_pool {
	spinlock_t lock;
	struct list_head chunks;
	int min_alloc_order;
	genpool_algo_t algo;
	void *data;
	const char *name;
};

struct cma;

typedef bool (*stack_trace_consume_fn)(void *, long unsigned int);

struct stacktrace_cookie {
	long unsigned int *store;
	unsigned int size;
	unsigned int skip;
	unsigned int len;
};

typedef u64 uint64_t;

enum clocksource_ids {
	CSID_GENERIC = 0,
	CSID_ARM_ARCH_COUNTER = 1,
	CSID_MAX = 2,
};

enum vdso_clock_mode {
	VDSO_CLOCKMODE_NONE = 0,
	VDSO_CLOCKMODE_ARCHTIMER = 1,
	VDSO_CLOCKMODE_ARCHTIMER_NOCOMPAT = 2,
	VDSO_CLOCKMODE_MAX = 3,
	VDSO_CLOCKMODE_TIMENS = 2147483647,
};

struct clocksource {
	u64 (*read)(struct clocksource *);
	u64 mask;
	u32 mult;
	u32 shift;
	u64 max_idle_ns;
	u32 maxadj;
	u32 uncertainty_margin;
	u64 max_cycles;
	const char *name;
	struct list_head list;
	int rating;
	enum clocksource_ids id;
	enum vdso_clock_mode vdso_clock_mode;
	long unsigned int flags;
	int (*enable)(struct clocksource *);
	void (*disable)(struct clocksource *);
	void (*suspend)(struct clocksource *);
	void (*resume)(struct clocksource *);
	void (*mark_unstable)(struct clocksource *);
	void (*tick_stable)(struct clocksource *);
	struct module *owner;
};

enum clock_event_state {
	CLOCK_EVT_STATE_DETACHED = 0,
	CLOCK_EVT_STATE_SHUTDOWN = 1,
	CLOCK_EVT_STATE_PERIODIC = 2,
	CLOCK_EVT_STATE_ONESHOT = 3,
	CLOCK_EVT_STATE_ONESHOT_STOPPED = 4,
};

struct clock_event_device {
	void (*event_handler)(struct clock_event_device *);
	int (*set_next_event)(long unsigned int, struct clock_event_device *);
	int (*set_next_ktime)(ktime_t, struct clock_event_device *);
	ktime_t next_event;
	u64 max_delta_ns;
	u64 min_delta_ns;
	u32 mult;
	u32 shift;
	enum clock_event_state state_use_accessors;
	unsigned int features;
	long unsigned int retries;
	int (*set_state_periodic)(struct clock_event_device *);
	int (*set_state_oneshot)(struct clock_event_device *);
	int (*set_state_oneshot_stopped)(struct clock_event_device *);
	int (*set_state_shutdown)(struct clock_event_device *);
	int (*tick_resume)(struct clock_event_device *);
	void (*broadcast)(const struct cpumask *);
	void (*suspend)(struct clock_event_device *);
	void (*resume)(struct clock_event_device *);
	long unsigned int min_delta_ticks;
	long unsigned int max_delta_ticks;
	const char *name;
	int rating;
	int irq;
	int bound_on;
	const struct cpumask *cpumask;
	struct list_head list;
	struct module *owner;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC = 0,
	TICKDEV_MODE_ONESHOT = 1,
};

struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

enum tick_broadcast_mode {
	TICK_BROADCAST_OFF = 0,
	TICK_BROADCAST_ON = 1,
	TICK_BROADCAST_FORCE = 2,
};

enum tick_broadcast_state {
	TICK_BROADCAST_EXIT = 0,
	TICK_BROADCAST_ENTER = 1,
};

typedef struct poll_table_struct poll_table;

enum ring_buffer_type {
	RINGBUF_TYPE_DATA_TYPE_LEN_MAX = 28,
	RINGBUF_TYPE_PADDING = 29,
	RINGBUF_TYPE_TIME_EXTEND = 30,
	RINGBUF_TYPE_TIME_STAMP = 31,
};

enum ring_buffer_flags {
	RB_FL_OVERWRITE = 1,
};

enum cpuhp_state {
	CPUHP_INVALID = -1,
	CPUHP_OFFLINE = 0,
	CPUHP_CREATE_THREADS = 1,
	CPUHP_PERF_PREPARE = 2,
	CPUHP_PERF_X86_PREPARE = 3,
	CPUHP_PERF_X86_AMD_UNCORE_PREP = 4,
	CPUHP_PERF_POWER = 5,
	CPUHP_PERF_SUPERH = 6,
	CPUHP_X86_HPET_DEAD = 7,
	CPUHP_X86_APB_DEAD = 8,
	CPUHP_X86_MCE_DEAD = 9,
	CPUHP_VIRT_NET_DEAD = 10,
	CPUHP_IBMVNIC_DEAD = 11,
	CPUHP_SLUB_DEAD = 12,
	CPUHP_DEBUG_OBJ_DEAD = 13,
	CPUHP_MM_WRITEBACK_DEAD = 14,
	CPUHP_MM_DEMOTION_DEAD = 15,
	CPUHP_MM_VMSTAT_DEAD = 16,
	CPUHP_SOFTIRQ_DEAD = 17,
	CPUHP_NET_MVNETA_DEAD = 18,
	CPUHP_CPUIDLE_DEAD = 19,
	CPUHP_ARM64_FPSIMD_DEAD = 20,
	CPUHP_ARM_OMAP_WAKE_DEAD = 21,
	CPUHP_IRQ_POLL_DEAD = 22,
	CPUHP_BLOCK_SOFTIRQ_DEAD = 23,
	CPUHP_BIO_DEAD = 24,
	CPUHP_ACPI_CPUDRV_DEAD = 25,
	CPUHP_S390_PFAULT_DEAD = 26,
	CPUHP_BLK_MQ_DEAD = 27,
	CPUHP_FS_BUFF_DEAD = 28,
	CPUHP_PRINTK_DEAD = 29,
	CPUHP_MM_MEMCQ_DEAD = 30,
	CPUHP_XFS_DEAD = 31,
	CPUHP_PERCPU_CNT_DEAD = 32,
	CPUHP_RADIX_DEAD = 33,
	CPUHP_PAGE_ALLOC = 34,
	CPUHP_NET_DEV_DEAD = 35,
	CPUHP_PCI_XGENE_DEAD = 36,
	CPUHP_IOMMU_IOVA_DEAD = 37,
	CPUHP_LUSTRE_CFS_DEAD = 38,
	CPUHP_AP_ARM_CACHE_B15_RAC_DEAD = 39,
	CPUHP_PADATA_DEAD = 40,
	CPUHP_AP_DTPM_CPU_DEAD = 41,
	CPUHP_RANDOM_PREPARE = 42,
	CPUHP_WORKQUEUE_PREP = 43,
	CPUHP_POWER_NUMA_PREPARE = 44,
	CPUHP_HRTIMERS_PREPARE = 45,
	CPUHP_PROFILE_PREPARE = 46,
	CPUHP_X2APIC_PREPARE = 47,
	CPUHP_SMPCFD_PREPARE = 48,
	CPUHP_RELAY_PREPARE = 49,
	CPUHP_SLAB_PREPARE = 50,
	CPUHP_MD_RAID5_PREPARE = 51,
	CPUHP_RCUTREE_PREP = 52,
	CPUHP_CPUIDLE_COUPLED_PREPARE = 53,
	CPUHP_POWERPC_PMAC_PREPARE = 54,
	CPUHP_POWERPC_MMU_CTX_PREPARE = 55,
	CPUHP_XEN_PREPARE = 56,
	CPUHP_XEN_EVTCHN_PREPARE = 57,
	CPUHP_ARM_SHMOBILE_SCU_PREPARE = 58,
	CPUHP_SH_SH3X_PREPARE = 59,
	CPUHP_NET_FLOW_PREPARE = 60,
	CPUHP_TOPOLOGY_PREPARE = 61,
	CPUHP_NET_IUCV_PREPARE = 62,
	CPUHP_ARM_BL_PREPARE = 63,
	CPUHP_TRACE_RB_PREPARE = 64,
	CPUHP_MM_ZS_PREPARE = 65,
	CPUHP_MM_ZSWP_MEM_PREPARE = 66,
	CPUHP_MM_ZSWP_POOL_PREPARE = 67,
	CPUHP_KVM_PPC_BOOK3S_PREPARE = 68,
	CPUHP_ZCOMP_PREPARE = 69,
	CPUHP_TIMERS_PREPARE = 70,
	CPUHP_MIPS_SOC_PREPARE = 71,
	CPUHP_BP_PREPARE_DYN = 72,
	CPUHP_BP_PREPARE_DYN_END = 92,
	CPUHP_BP_KICK_AP = 93,
	CPUHP_BRINGUP_CPU = 94,
	CPUHP_AP_IDLE_DEAD = 95,
	CPUHP_AP_OFFLINE = 96,
	CPUHP_AP_CACHECTRL_STARTING = 97,
	CPUHP_AP_SCHED_STARTING = 98,
	CPUHP_AP_RCUTREE_DYING = 99,
	CPUHP_AP_CPU_PM_STARTING = 100,
	CPUHP_AP_IRQ_GIC_STARTING = 101,
	CPUHP_AP_IRQ_HIP04_STARTING = 102,
	CPUHP_AP_IRQ_APPLE_AIC_STARTING = 103,
	CPUHP_AP_IRQ_ARMADA_XP_STARTING = 104,
	CPUHP_AP_IRQ_BCM2836_STARTING = 105,
	CPUHP_AP_IRQ_MIPS_GIC_STARTING = 106,
	CPUHP_AP_IRQ_RISCV_STARTING = 107,
	CPUHP_AP_IRQ_LOONGARCH_STARTING = 108,
	CPUHP_AP_IRQ_SIFIVE_PLIC_STARTING = 109,
	CPUHP_AP_ARM_MVEBU_COHERENCY = 110,
	CPUHP_AP_MICROCODE_LOADER = 111,
	CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING = 112,
	CPUHP_AP_PERF_X86_STARTING = 113,
	CPUHP_AP_PERF_X86_AMD_IBS_STARTING = 114,
	CPUHP_AP_PERF_X86_CQM_STARTING = 115,
	CPUHP_AP_PERF_X86_CSTATE_STARTING = 116,
	CPUHP_AP_PERF_XTENSA_STARTING = 117,
	CPUHP_AP_MIPS_OP_LOONGSON3_STARTING = 118,
	CPUHP_AP_ARM_VFP_STARTING = 119,
	CPUHP_AP_ARM64_DEBUG_MONITORS_STARTING = 120,
	CPUHP_AP_PERF_ARM_HW_BREAKPOINT_STARTING = 121,
	CPUHP_AP_PERF_ARM_ACPI_STARTING = 122,
	CPUHP_AP_PERF_ARM_STARTING = 123,
	CPUHP_AP_PERF_RISCV_STARTING = 124,
	CPUHP_AP_ARM_L2X0_STARTING = 125,
	CPUHP_AP_EXYNOS4_MCT_TIMER_STARTING = 126,
	CPUHP_AP_ARM_ARCH_TIMER_STARTING = 127,
	CPUHP_AP_ARM_GLOBAL_TIMER_STARTING = 128,
	CPUHP_AP_JCORE_TIMER_STARTING = 129,
	CPUHP_AP_ARM_TWD_STARTING = 130,
	CPUHP_AP_QCOM_TIMER_STARTING = 131,
	CPUHP_AP_TEGRA_TIMER_STARTING = 132,
	CPUHP_AP_ARMADA_TIMER_STARTING = 133,
	CPUHP_AP_MARCO_TIMER_STARTING = 134,
	CPUHP_AP_MIPS_GIC_TIMER_STARTING = 135,
	CPUHP_AP_ARC_TIMER_STARTING = 136,
	CPUHP_AP_RISCV_TIMER_STARTING = 137,
	CPUHP_AP_CLINT_TIMER_STARTING = 138,
	CPUHP_AP_CSKY_TIMER_STARTING = 139,
	CPUHP_AP_TI_GP_TIMER_STARTING = 140,
	CPUHP_AP_HYPERV_TIMER_STARTING = 141,
	CPUHP_AP_DUMMY_TIMER_STARTING = 142,
	CPUHP_AP_ARM_XEN_STARTING = 143,
	CPUHP_AP_ARM_CORESIGHT_STARTING = 144,
	CPUHP_AP_ARM_CORESIGHT_CTI_STARTING = 145,
	CPUHP_AP_ARM64_ISNDEP_STARTING = 146,
	CPUHP_AP_SMPCFD_DYING = 147,
	CPUHP_AP_X86_TBOOT_DYING = 148,
	CPUHP_AP_ARM_CACHE_B15_RAC_DYING = 149,
	CPUHP_AP_ONLINE = 150,
	CPUHP_TEARDOWN_CPU = 151,
	CPUHP_AP_ONLINE_IDLE = 152,
	CPUHP_AP_HYPERV_ONLINE = 153,
	CPUHP_AP_KVM_ONLINE = 154,
	CPUHP_AP_SCHED_WAIT_EMPTY = 155,
	CPUHP_AP_SMPBOOT_THREADS = 156,
	CPUHP_AP_X86_VDSO_VMA_ONLINE = 157,
	CPUHP_AP_IRQ_AFFINITY_ONLINE = 158,
	CPUHP_AP_BLK_MQ_ONLINE = 159,
	CPUHP_AP_ARM_MVEBU_SYNC_CLOCKS = 160,
	CPUHP_AP_X86_INTEL_EPB_ONLINE = 161,
	CPUHP_AP_PERF_ONLINE = 162,
	CPUHP_AP_PERF_X86_ONLINE = 163,
	CPUHP_AP_PERF_X86_UNCORE_ONLINE = 164,
	CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE = 165,
	CPUHP_AP_PERF_X86_AMD_POWER_ONLINE = 166,
	CPUHP_AP_PERF_X86_RAPL_ONLINE = 167,
	CPUHP_AP_PERF_X86_CQM_ONLINE = 168,
	CPUHP_AP_PERF_X86_CSTATE_ONLINE = 169,
	CPUHP_AP_PERF_X86_IDXD_ONLINE = 170,
	CPUHP_AP_PERF_S390_CF_ONLINE = 171,
	CPUHP_AP_PERF_S390_SF_ONLINE = 172,
	CPUHP_AP_PERF_ARM_CCI_ONLINE = 173,
	CPUHP_AP_PERF_ARM_CCN_ONLINE = 174,
	CPUHP_AP_PERF_ARM_HISI_CPA_ONLINE = 175,
	CPUHP_AP_PERF_ARM_HISI_DDRC_ONLINE = 176,
	CPUHP_AP_PERF_ARM_HISI_HHA_ONLINE = 177,
	CPUHP_AP_PERF_ARM_HISI_L3_ONLINE = 178,
	CPUHP_AP_PERF_ARM_HISI_PA_ONLINE = 179,
	CPUHP_AP_PERF_ARM_HISI_SLLC_ONLINE = 180,
	CPUHP_AP_PERF_ARM_HISI_PCIE_PMU_ONLINE = 181,
	CPUHP_AP_PERF_ARM_HNS3_PMU_ONLINE = 182,
	CPUHP_AP_PERF_ARM_L2X0_ONLINE = 183,
	CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE = 184,
	CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE = 185,
	CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE = 186,
	CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE = 187,
	CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE = 188,
	CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE = 189,
	CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE = 190,
	CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE = 191,
	CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE = 192,
	CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE = 193,
	CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE = 194,
	CPUHP_AP_PERF_CSKY_ONLINE = 195,
	CPUHP_AP_WATCHDOG_ONLINE = 196,
	CPUHP_AP_WORKQUEUE_ONLINE = 197,
	CPUHP_AP_RANDOM_ONLINE = 198,
	CPUHP_AP_RCUTREE_ONLINE = 199,
	CPUHP_AP_BASE_CACHEINFO_ONLINE = 200,
	CPUHP_AP_ONLINE_DYN = 201,
	CPUHP_AP_ONLINE_DYN_END = 231,
	CPUHP_AP_MM_DEMOTION_ONLINE = 232,
	CPUHP_AP_X86_HPET_ONLINE = 233,
	CPUHP_AP_X86_KVM_CLK_ONLINE = 234,
	CPUHP_AP_ACTIVE = 235,
	CPUHP_ONLINE = 236,
};

struct ring_buffer_per_cpu;

struct buffer_page;

struct ring_buffer_iter {
	struct ring_buffer_per_cpu *cpu_buffer;
	long unsigned int head;
	long unsigned int next_event;
	struct buffer_page *head_page;
	struct buffer_page *cache_reader_page;
	long unsigned int cache_read;
	u64 read_stamp;
	u64 page_stamp;
	struct ring_buffer_event *event;
	int missed_events;
};

struct rb_irq_work {
	struct irq_work work;
	wait_queue_head_t waiters;
	wait_queue_head_t full_waiters;
	long int wait_index;
	bool waiters_pending;
	bool full_waiters_pending;
	bool wakeup_full;
};

struct trace_buffer {
	unsigned int flags;
	int cpus;
	atomic_t record_disabled;
	cpumask_var_t cpumask;
	struct lock_class_key *reader_lock_key;
	struct mutex mutex;
	struct ring_buffer_per_cpu **buffers;
	struct hlist_node node;
	u64 (*clock)();
	struct rb_irq_work irq_work;
	bool time_stamp_abs;
};

enum {
	RB_LEN_TIME_EXTEND = 8,
	RB_LEN_TIME_STAMP = 8,
};

struct buffer_data_page {
	u64 time_stamp;
	local_t commit;
	unsigned char data[0];
};

struct buffer_page {
	struct list_head list;
	local_t write;
	unsigned int read;
	local_t entries;
	long unsigned int real_end;
	struct buffer_data_page *page;
};

struct rb_event_info {
	u64 ts;
	u64 delta;
	u64 before;
	u64 after;
	long unsigned int length;
	struct buffer_page *tail_page;
	int add_timestamp;
};

enum {
	RB_ADD_STAMP_NONE = 0,
	RB_ADD_STAMP_EXTEND = 2,
	RB_ADD_STAMP_ABSOLUTE = 4,
	RB_ADD_STAMP_FORCE = 8,
};

enum {
	RB_CTX_TRANSITION = 0,
	RB_CTX_NMI = 1,
	RB_CTX_IRQ = 2,
	RB_CTX_SOFTIRQ = 3,
	RB_CTX_NORMAL = 4,
	RB_CTX_MAX = 5,
};

struct rb_time_struct {
	local64_t time;
};

typedef struct rb_time_struct rb_time_t;

struct ring_buffer_per_cpu {
	int cpu;
	atomic_t record_disabled;
	atomic_t resize_disabled;
	struct trace_buffer *buffer;
	raw_spinlock_t reader_lock;
	arch_spinlock_t lock;
	struct lock_class_key lock_key;
	struct buffer_data_page *free_page;
	long unsigned int nr_pages;
	unsigned int current_context;
	struct list_head *pages;
	struct buffer_page *head_page;
	struct buffer_page *tail_page;
	struct buffer_page *commit_page;
	struct buffer_page *reader_page;
	long unsigned int lost_events;
	long unsigned int last_overrun;
	long unsigned int nest;
	local_t entries_bytes;
	local_t entries;
	local_t overrun;
	local_t commit_overrun;
	local_t dropped_events;
	local_t committing;
	local_t commits;
	local_t pages_touched;
	local_t pages_lost;
	local_t pages_read;
	long int last_pages_touch;
	size_t shortest_full;
	long unsigned int read;
	long unsigned int read_bytes;
	rb_time_t write_stamp;
	rb_time_t before_stamp;
	u64 event_stamp[5];
	u64 read_stamp;
	long int nr_pages_to_update;
	struct list_head new_pages;
	struct work_struct update_pages_work;
	struct completion update_done;
	struct rb_irq_work irq_work;
};

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u32 __wsum;

typedef unsigned int slab_flags_t;

typedef struct {
	atomic_t refcnt;
} rcuref_t;

struct bpf_insn {
	__u8 code;
	__u8 dst_reg: 4;
	__u8 src_reg: 4;
	__s16 off;
	__s32 imm;
};

enum bpf_cgroup_iter_order {
	BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
	BPF_CGROUP_ITER_SELF_ONLY = 1,
	BPF_CGROUP_ITER_DESCENDANTS_PRE = 2,
	BPF_CGROUP_ITER_DESCENDANTS_POST = 3,
	BPF_CGROUP_ITER_ANCESTORS_UP = 4,
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
	BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED = 19,
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
	BPF_MAP_TYPE_USER_RINGBUF = 31,
	BPF_MAP_TYPE_CGRP_STORAGE = 32,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
	BPF_PROG_TYPE_SOCKET_FILTER = 1,
	BPF_PROG_TYPE_KPROBE = 2,
	BPF_PROG_TYPE_SCHED_CLS = 3,
	BPF_PROG_TYPE_SCHED_ACT = 4,
	BPF_PROG_TYPE_TRACEPOINT = 5,
	BPF_PROG_TYPE_XDP = 6,
	BPF_PROG_TYPE_PERF_EVENT = 7,
	BPF_PROG_TYPE_CGROUP_SKB = 8,
	BPF_PROG_TYPE_CGROUP_SOCK = 9,
	BPF_PROG_TYPE_LWT_IN = 10,
	BPF_PROG_TYPE_LWT_OUT = 11,
	BPF_PROG_TYPE_LWT_XMIT = 12,
	BPF_PROG_TYPE_SOCK_OPS = 13,
	BPF_PROG_TYPE_SK_SKB = 14,
	BPF_PROG_TYPE_CGROUP_DEVICE = 15,
	BPF_PROG_TYPE_SK_MSG = 16,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
	BPF_PROG_TYPE_LIRC_MODE2 = 20,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
	BPF_PROG_TYPE_STRUCT_OPS = 27,
	BPF_PROG_TYPE_EXT = 28,
	BPF_PROG_TYPE_LSM = 29,
	BPF_PROG_TYPE_SK_LOOKUP = 30,
	BPF_PROG_TYPE_SYSCALL = 31,
	BPF_PROG_TYPE_NETFILTER = 32,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_INET_EGRESS = 1,
	BPF_CGROUP_INET_SOCK_CREATE = 2,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_CGROUP_DEVICE = 6,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_BIND = 8,
	BPF_CGROUP_INET6_BIND = 9,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_CGROUP_INET6_CONNECT = 11,
	BPF_CGROUP_INET4_POST_BIND = 12,
	BPF_CGROUP_INET6_POST_BIND = 13,
	BPF_CGROUP_UDP4_SENDMSG = 14,
	BPF_CGROUP_UDP6_SENDMSG = 15,
	BPF_LIRC_MODE2 = 16,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG = 20,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT = 22,
	BPF_TRACE_RAW_TP = 23,
	BPF_TRACE_FENTRY = 24,
	BPF_TRACE_FEXIT = 25,
	BPF_MODIFY_RETURN = 26,
	BPF_LSM_MAC = 27,
	BPF_TRACE_ITER = 28,
	BPF_CGROUP_INET4_GETPEERNAME = 29,
	BPF_CGROUP_INET6_GETPEERNAME = 30,
	BPF_CGROUP_INET4_GETSOCKNAME = 31,
	BPF_CGROUP_INET6_GETSOCKNAME = 32,
	BPF_XDP_DEVMAP = 33,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	BPF_XDP_CPUMAP = 35,
	BPF_SK_LOOKUP = 36,
	BPF_XDP = 37,
	BPF_SK_SKB_VERDICT = 38,
	BPF_SK_REUSEPORT_SELECT = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	BPF_PERF_EVENT = 41,
	BPF_TRACE_KPROBE_MULTI = 42,
	BPF_LSM_CGROUP = 43,
	BPF_STRUCT_OPS = 44,
	BPF_NETFILTER = 45,
	__MAX_BPF_ATTACH_TYPE = 46,
};

union bpf_attr {
	struct {
		__u32 map_type;
		__u32 key_size;
		__u32 value_size;
		__u32 max_entries;
		__u32 map_flags;
		__u32 inner_map_fd;
		__u32 numa_node;
		char map_name[16];
		__u32 map_ifindex;
		__u32 btf_fd;
		__u32 btf_key_type_id;
		__u32 btf_value_type_id;
		__u32 btf_vmlinux_value_type_id;
		__u64 map_extra;
	};
	struct {
		__u32 map_fd;
		__u64 key;
		union {
			__u64 value;
			__u64 next_key;
		};
		__u64 flags;
	};
	struct {
		__u64 in_batch;
		__u64 out_batch;
		__u64 keys;
		__u64 values;
		__u32 count;
		__u32 map_fd;
		__u64 elem_flags;
		__u64 flags;
	} batch;
	struct {
		__u32 prog_type;
		__u32 insn_cnt;
		__u64 insns;
		__u64 license;
		__u32 log_level;
		__u32 log_size;
		__u64 log_buf;
		__u32 kern_version;
		__u32 prog_flags;
		char prog_name[16];
		__u32 prog_ifindex;
		__u32 expected_attach_type;
		__u32 prog_btf_fd;
		__u32 func_info_rec_size;
		__u64 func_info;
		__u32 func_info_cnt;
		__u32 line_info_rec_size;
		__u64 line_info;
		__u32 line_info_cnt;
		__u32 attach_btf_id;
		union {
			__u32 attach_prog_fd;
			__u32 attach_btf_obj_fd;
		};
		__u32 core_relo_cnt;
		__u64 fd_array;
		__u64 core_relos;
		__u32 core_relo_rec_size;
		__u32 log_true_size;
	};
	struct {
		__u64 pathname;
		__u32 bpf_fd;
		__u32 file_flags;
	};
	struct {
		__u32 target_fd;
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
		__u32 replace_bpf_fd;
	};
	struct {
		__u32 prog_fd;
		__u32 retval;
		__u32 data_size_in;
		__u32 data_size_out;
		__u64 data_in;
		__u64 data_out;
		__u32 repeat;
		__u32 duration;
		__u32 ctx_size_in;
		__u32 ctx_size_out;
		__u64 ctx_in;
		__u64 ctx_out;
		__u32 flags;
		__u32 cpu;
		__u32 batch_size;
	} test;
	struct {
		union {
			__u32 start_id;
			__u32 prog_id;
			__u32 map_id;
			__u32 btf_id;
			__u32 link_id;
		};
		__u32 next_id;
		__u32 open_flags;
	};
	struct {
		__u32 bpf_fd;
		__u32 info_len;
		__u64 info;
	} info;
	struct {
		__u32 target_fd;
		__u32 attach_type;
		__u32 query_flags;
		__u32 attach_flags;
		__u64 prog_ids;
		__u32 prog_cnt;
		__u64 prog_attach_flags;
	} query;
	struct {
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;
	struct {
		__u64 btf;
		__u64 btf_log_buf;
		__u32 btf_size;
		__u32 btf_log_size;
		__u32 btf_log_level;
		__u32 btf_log_true_size;
	};
	struct {
		__u32 pid;
		__u32 fd;
		__u32 flags;
		__u32 buf_len;
		__u64 buf;
		__u32 prog_id;
		__u32 fd_type;
		__u64 probe_offset;
		__u64 probe_addr;
	} task_fd_query;
	struct {
		union {
			__u32 prog_fd;
			__u32 map_fd;
		};
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 flags;
		union {
			__u32 target_btf_id;
			struct {
				__u64 iter_info;
				__u32 iter_info_len;
			};
			struct {
				__u64 bpf_cookie;
			} perf_event;
			struct {
				__u32 flags;
				__u32 cnt;
				__u64 syms;
				__u64 addrs;
				__u64 cookies;
			} kprobe_multi;
			struct {
				__u32 target_btf_id;
				__u64 cookie;
			} tracing;
			struct {
				__u32 pf;
				__u32 hooknum;
				__s32 priority;
				__u32 flags;
			} netfilter;
		};
	} link_create;
	struct {
		__u32 link_fd;
		union {
			__u32 new_prog_fd;
			__u32 new_map_fd;
		};
		__u32 flags;
		union {
			__u32 old_prog_fd;
			__u32 old_map_fd;
		};
	} link_update;
	struct {
		__u32 link_fd;
	} link_detach;
	struct {
		__u32 type;
	} enable_stats;
	struct {
		__u32 link_fd;
		__u32 flags;
	} iter_create;
	struct {
		__u32 prog_fd;
		__u32 map_fd;
		__u32 flags;
	} prog_bind_map;
};

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

enum bpf_task_fd_type {
	BPF_FD_TYPE_RAW_TRACEPOINT = 0,
	BPF_FD_TYPE_TRACEPOINT = 1,
	BPF_FD_TYPE_KPROBE = 2,
	BPF_FD_TYPE_KRETPROBE = 3,
	BPF_FD_TYPE_UPROBE = 4,
	BPF_FD_TYPE_URETPROBE = 5,
};

struct bpf_func_info {
	__u32 insn_off;
	__u32 type_id;
};

struct bpf_line_info {
	__u32 insn_off;
	__u32 file_name_off;
	__u32 line_off;
	__u32 line_col;
};

struct sock_filter {
	__u16 code;
	__u8 jt;
	__u8 jf;
	__u32 k;
};

enum uprobe_filter_ctx {
	UPROBE_FILTER_REGISTER = 0,
	UPROBE_FILTER_UNREGISTER = 1,
	UPROBE_FILTER_MMAP = 2,
};

struct uprobe_consumer {
	int (*handler)(struct uprobe_consumer *, struct pt_regs *);
	int (*ret_handler)(struct uprobe_consumer *, long unsigned int, struct pt_regs *);
	bool (*filter)(struct uprobe_consumer *, enum uprobe_filter_ctx, struct mm_struct *);
	struct uprobe_consumer *next;
};

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

struct napi_struct;

struct page_pool_params {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device *dev;
	struct napi_struct *napi;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page *, void *);
	void *init_arg;
};

struct pp_alloc_cache {
	u32 count;
	struct page *cache[128];
};

struct ptr_ring {
	int producer;
	spinlock_t producer_lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	int consumer_head;
	int consumer_tail;
	spinlock_t consumer_lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	int size;
	int batch;
	void **queue;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct page_pool {
	struct page_pool_params p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct pp_alloc_cache alloc;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};

struct notifier_block;

typedef int (*notifier_fn_t)(struct notifier_block *, long unsigned int, void *);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block *next;
	int priority;
};

struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block *head;
};

struct raw_notifier_head {
	struct notifier_block *head;
};

struct ctl_table;

typedef int proc_handler(struct ctl_table *, int, void *, size_t *, loff_t *);

struct ctl_table_poll;

struct ctl_table {
	const char *procname;
	void *data;
	int maxlen;
	umode_t mode;
	struct ctl_table *child;
	proc_handler *proc_handler;
	struct ctl_table_poll *poll;
	void *extra1;
	void *extra2;
};

struct ctl_table_poll {
	atomic_t event;
	wait_queue_head_t wait;
};

struct ctl_table_header;

struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};

struct ctl_table_root;

struct ctl_table_set;

struct ctl_dir;

struct ctl_table_header {
	union {
		struct {
			struct ctl_table *ctl_table;
			int used;
			int count;
			int nreg;
		};
		struct callback_head rcu;
	};
	struct completion *unregistering;
	struct ctl_table *ctl_table_arg;
	struct ctl_table_root *root;
	struct ctl_table_set *set;
	struct ctl_dir *parent;
	struct ctl_node *node;
	struct hlist_head inodes;
};

struct ctl_dir {
	struct ctl_table_header header;
	struct rb_root root;
};

struct ctl_table_set {
	int (*is_seen)(struct ctl_table_set *);
	struct ctl_dir dir;
};

struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, struct ctl_table *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, struct ctl_table *);
};

struct rhashtable;

struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};

typedef u32 (*rht_hashfn_t)(const void *, u32, u32);

typedef u32 (*rht_obj_hashfn_t)(const void *, u32, u32);

typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *, const void *);

struct rhashtable_params {
	u16 nelem_hint;
	u16 key_len;
	u16 key_offset;
	u16 head_offset;
	unsigned int max_size;
	u16 min_size;
	bool automatic_shrinking;
	rht_hashfn_t hashfn;
	rht_obj_hashfn_t obj_hashfn;
	rht_obj_cmpfn_t obj_cmpfn;
};

struct bucket_table;

struct rhashtable {
	struct bucket_table *tbl;
	unsigned int key_len;
	unsigned int max_elems;
	struct rhashtable_params p;
	bool rhlist;
	struct work_struct run_work;
	struct mutex mutex;
	spinlock_t lock;
	atomic_t nelems;
};

struct bpf_run_ctx {};

struct cgroup;

typedef __u64 __addrpair;

typedef __u32 __portpair;

typedef struct {} possible_net_t;

struct proto;

struct inet_timewait_death_row;

struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse: 4;
	unsigned char skc_reuseport: 1;
	unsigned char skc_ipv6only: 1;
	unsigned char skc_net_refcnt: 1;
	int skc_bound_dev_if;
	union {
		struct hlist_node skc_bind_node;
		struct hlist_node skc_portaddr_node;
	};
	struct proto *skc_prot;
	possible_net_t skc_net;
	atomic64_t skc_cookie;
	union {
		long unsigned int skc_flags;
		struct sock *skc_listener;
		struct inet_timewait_death_row *skc_tw_dr;
	};
	int skc_dontcopy_begin[0];
	union {
		struct hlist_node skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	short unsigned int skc_tx_queue_mapping;
	union {
		int skc_incoming_cpu;
		u32 skc_rcv_wnd;
		u32 skc_tw_rcv_nxt;
	};
	refcount_t skc_refcnt;
	int skc_dontcopy_end[0];
	union {
		u32 skc_rxhash;
		u32 skc_window_clamp;
		u32 skc_tw_snd_nxt;
	};
};

typedef struct {
	spinlock_t slock;
	int owned;
	wait_queue_head_t wq;
} socket_lock_t;

struct sk_buff;

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};

struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
	spinlock_t lock;
};

typedef u64 netdev_features_t;

struct sock_cgroup_data {};

typedef struct {} netns_tracker;

struct dst_entry;

struct sk_filter;

struct socket_wq;

struct socket;

struct sock_reuseport;

struct sock {
	struct sock_common __sk_common;
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head sk_error_queue;
	struct sk_buff_head sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	int sk_rcvbuf;
	int sk_wait_pending;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct dst_entry *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u32 sk_tsflags;
	u8 sk_shutdown;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	bool sk_use_task_frag;
	struct socket *sk_socket;
	void *sk_user_data;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup *sk_memcg;
	void (*sk_state_change)(struct sock *);
	void (*sk_data_ready)(struct sock *);
	void (*sk_write_space)(struct sock *);
	void (*sk_error_report)(struct sock *);
	int (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	void (*sk_destruct)(struct sock *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
	struct hlist_node sk_bind2_node;
};

typedef struct {
	union {
		void *kernel;
		void *user;
	};
	bool is_kernel: 1;
} sockptr_t;

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};

enum btf_field_type {
	BPF_SPIN_LOCK = 1,
	BPF_TIMER = 2,
	BPF_KPTR_UNREF = 4,
	BPF_KPTR_REF = 8,
	BPF_KPTR = 12,
	BPF_LIST_HEAD = 16,
	BPF_LIST_NODE = 32,
	BPF_RB_ROOT = 64,
	BPF_RB_NODE = 128,
	BPF_GRAPH_NODE_OR_ROOT = 240,
	BPF_REFCOUNT = 256,
};

typedef void (*btf_dtor_kfunc_t)(void *);

struct btf;

struct btf_field_kptr {
	struct btf *btf;
	struct module *module;
	btf_dtor_kfunc_t dtor;
	u32 btf_id;
};

struct btf_record;

struct btf_field_graph_root {
	struct btf *btf;
	u32 value_btf_id;
	u32 node_offset;
	struct btf_record *value_rec;
};

struct btf_field {
	u32 offset;
	u32 size;
	enum btf_field_type type;
	union {
		struct btf_field_kptr kptr;
		struct btf_field_graph_root graph_root;
	};
};

struct btf_record {
	u32 cnt;
	u32 field_mask;
	int spin_lock_off;
	int timer_off;
	int refcount_off;
	struct btf_field fields[0];
};

struct ref_tracker_dir {};

struct netns_core {
	struct ctl_table_header *sysctl_hdr;
	int sysctl_somaxconn;
	u8 sysctl_txrehash;
};

struct ipstats_mib;

struct tcp_mib;

struct linux_mib;

struct udp_mib;

struct icmp_mib;

struct icmpmsg_mib;

struct netns_mib {
	struct ipstats_mib *ip_statistics;
	struct tcp_mib *tcp_statistics;
	struct linux_mib *net_statistics;
	struct udp_mib *udp_statistics;
	struct udp_mib *udplite_statistics;
	struct icmp_mib *icmp_statistics;
	struct icmpmsg_mib *icmpmsg_statistics;
};

struct netns_packet {
	struct mutex sklist_lock;
	struct hlist_head sklist;
};

struct netns_nexthop {
	struct rb_root rb_root;
	struct hlist_head *devhash;
	unsigned int seq;
	u32 last_id_allocated;
	struct blocking_notifier_head notifier_chain;
};

struct inet_hashinfo;

struct inet_timewait_death_row {
	refcount_t tw_refcount;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct inet_hashinfo *hashinfo;
	int sysctl_max_tw_buckets;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct udp_table;

struct ipv4_devconf;

struct local_ports {
	seqlock_t lock;
	int range[2];
	bool warned;
};

struct ping_group_range {
	seqlock_t lock;
	kgid_t range[2];
};

typedef struct {
	u64 key[2];
} siphash_key_t;

struct ip_ra_chain;

struct inet_peer_base;

struct fqdir;

struct tcp_congestion_ops;

struct tcp_fastopen_context;

struct fib_notifier_ops;

struct netns_ipv4 {
	struct inet_timewait_death_row tcp_death_row;
	struct udp_table *udp_table;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain *ra_chain;
	struct mutex ra_mutex;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	struct hlist_head *fib_table_hash;
	struct sock *fibnl;
	struct sock *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_use_pmtu;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_ip_early_demux;
	u8 sysctl_tcp_early_demux;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_min_snd_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	int sysctl_tcp_reordering;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	unsigned int sysctl_tcp_notsent_lowat;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_moderate_rcvbuf;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_challenge_ack_limit;
	int sysctl_tcp_min_rtt_wlen;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	int sysctl_tcp_wmem[3];
	int sysctl_tcp_rmem[3];
	unsigned int sysctl_tcp_child_ehash_entries;
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	u32 tcp_challenge_timestamp;
	u32 tcp_challenge_count;
	u8 sysctl_tcp_plb_enabled;
	u8 sysctl_tcp_plb_idle_rehash_rounds;
	u8 sysctl_tcp_plb_rehash_rounds;
	u8 sysctl_tcp_plb_suspend_rto_sec;
	int sysctl_tcp_plb_cong_thresh;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	unsigned int sysctl_udp_child_hash_entries;
	struct fib_notifier_ops *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct net_generic;

struct netns_bpf {
	struct bpf_prog_array *run_array[2];
	struct bpf_prog *progs[2];
	struct list_head links[2];
};

struct uevent_sock;

struct net_device;

struct net {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct ref_tracker_dir notrefcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct sock *rtnl;
	struct sock *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_nexthop nexthop;
	long: 64;
	long: 64;
	struct netns_ipv4 ipv4;
	struct net_generic *gen;
	struct netns_bpf bpf;
	u64 net_cookie;
	struct sock *diag_nlsk;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct u64_stats_sync {};

typedef struct {
	local64_t v;
} u64_stats_t;

typedef short unsigned int __kernel_sa_family_t;

typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	union {
		char sa_data_min[14];
		struct {
			struct {} __empty_sa_data;
			char sa_data[0];
		};
	};
};

struct ubuf_info;

struct msghdr {
	void *msg_name;
	int msg_namelen;
	int msg_inq;
	struct iov_iter msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	bool msg_get_inq: 1;
	unsigned int msg_flags;
	__kernel_size_t msg_controllen;
	struct kiocb *msg_iocb;
	struct ubuf_info *msg_ubuf;
	int (*sg_from_iter)(struct sock *, struct sk_buff *, struct iov_iter *, size_t);
};

struct ubuf_info {
	void (*callback)(struct sk_buff *, struct ubuf_info *, bool);
	refcount_t refcnt;
	u8 flags;
};

typedef unsigned int sk_buff_data_t;

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
	};
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 mono_delivery_time: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 redirected: 1;
			__u8 slow_gro: 1;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 dst_pending_confirm: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 __mono_tc_offset[0];
			__u8 mono_delivery_time: 1;
			__u8 remcsum_offload: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 inner_protocol_type: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 redirected: 1;
			__u8 slow_gro: 1;
			u16 alloc_cpu;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			union {
				u32 vlan_all;
				struct {
					__be16 vlan_proto;
					__u16 vlan_tci;
				};
			};
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
};

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
} sync_serial_settings;

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
	unsigned int slot_map;
} te1_settings;

typedef struct {
	short unsigned int encoding;
	short unsigned int parity;
} raw_hdlc_proto;

typedef struct {
	unsigned int t391;
	unsigned int t392;
	unsigned int n391;
	unsigned int n392;
	unsigned int n393;
	short unsigned int lmi;
	short unsigned int dce;
} fr_proto;

typedef struct {
	unsigned int dlci;
} fr_proto_pvc;

typedef struct {
	unsigned int dlci;
	char master[16];
} fr_proto_pvc_info;

typedef struct {
	unsigned int interval;
	unsigned int timeout;
} cisco_proto;

typedef struct {
	short unsigned int dce;
	unsigned int modulo;
	unsigned int window;
	unsigned int t1;
	unsigned int t2;
	unsigned int n2;
} x25_hdlc_proto;

struct ifmap {
	long unsigned int mem_start;
	long unsigned int mem_end;
	short unsigned int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct if_settings {
	unsigned int type;
	unsigned int size;
	union {
		raw_hdlc_proto *raw_hdlc;
		cisco_proto *cisco;
		fr_proto *fr;
		fr_proto_pvc *fr_pvc;
		fr_proto_pvc_info *fr_pvc_info;
		x25_hdlc_proto *x25;
		sync_serial_settings *sync;
		te1_settings *te1;
	} ifs_ifsu;
};

struct ifreq {
	union {
		char ifrn_name[16];
	} ifr_ifrn;
	union {
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short int ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[16];
		char ifru_newname[16];
		void *ifru_data;
		struct if_settings ifru_settings;
	} ifr_ifru;
};

struct ftrace_hash {
	long unsigned int size_bits;
	struct hlist_head *buckets;
	long unsigned int count;
	long unsigned int flags;
	struct callback_head rcu;
};

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

struct bpf_iter_aux_info;

typedef int (*bpf_iter_init_seq_priv_t)(void *, struct bpf_iter_aux_info *);

enum bpf_iter_task_type {
	BPF_TASK_ITER_ALL = 0,
	BPF_TASK_ITER_TID = 1,
	BPF_TASK_ITER_TGID = 2,
};

struct bpf_map;

struct bpf_iter_aux_info {
	struct bpf_map *map;
	struct {
		struct cgroup *start;
		enum bpf_cgroup_iter_order order;
	} cgroup;
	struct {
		enum bpf_iter_task_type type;
		u32 pid;
	} task;
};

typedef void (*bpf_iter_fini_seq_priv_t)(void *);

typedef unsigned int (*bpf_func_t)(const void *, const struct bpf_insn *);

struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};

struct bpf_prog_aux;

struct bpf_local_storage_map;

struct bpf_verifier_env;

struct bpf_func_state;

struct bpf_map_ops {
	int (*map_alloc_check)(union bpf_attr *);
	struct bpf_map * (*map_alloc)(union bpf_attr *);
	void (*map_release)(struct bpf_map *, struct file *);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *, void *, void *);
	void (*map_release_uref)(struct bpf_map *);
	void * (*map_lookup_elem_sys_only)(struct bpf_map *, void *);
	int (*map_lookup_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_lookup_and_delete_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_lookup_and_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_update_batch)(struct bpf_map *, struct file *, const union bpf_attr *, union bpf_attr *);
	int (*map_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	void * (*map_lookup_elem)(struct bpf_map *, void *);
	long int (*map_update_elem)(struct bpf_map *, void *, void *, u64);
	long int (*map_delete_elem)(struct bpf_map *, void *);
	long int (*map_push_elem)(struct bpf_map *, void *, u64);
	long int (*map_pop_elem)(struct bpf_map *, void *);
	long int (*map_peek_elem)(struct bpf_map *, void *);
	void * (*map_lookup_percpu_elem)(struct bpf_map *, void *, u32);
	void * (*map_fd_get_ptr)(struct bpf_map *, struct file *, int);
	void (*map_fd_put_ptr)(void *);
	int (*map_gen_lookup)(struct bpf_map *, struct bpf_insn *);
	u32 (*map_fd_sys_lookup_elem)(void *);
	void (*map_seq_show_elem)(struct bpf_map *, void *, struct seq_file *);
	int (*map_check_btf)(const struct bpf_map *, const struct btf *, const struct btf_type *, const struct btf_type *);
	int (*map_poke_track)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_untrack)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_run)(struct bpf_map *, u32, struct bpf_prog *, struct bpf_prog *);
	int (*map_direct_value_addr)(const struct bpf_map *, u64 *, u32);
	int (*map_direct_value_meta)(const struct bpf_map *, u64, u32 *);
	int (*map_mmap)(struct bpf_map *, struct vm_area_struct *);
	__poll_t (*map_poll)(struct bpf_map *, struct file *, struct poll_table_struct *);
	int (*map_local_storage_charge)(struct bpf_local_storage_map *, void *, u32);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *, void *, u32);
	struct bpf_local_storage ** (*map_owner_storage_ptr)(void *);
	long int (*map_redirect)(struct bpf_map *, u64, u64);
	bool (*map_meta_equal)(const struct bpf_map *, const struct bpf_map *);
	int (*map_set_for_each_callback_args)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *);
	long int (*map_for_each_callback)(struct bpf_map *, bpf_callback_t, void *, u64);
	u64 (*map_mem_usage)(const struct bpf_map *);
	int *map_btf_id;
	const struct bpf_iter_seq_info *iter_seq_info;
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u64 map_extra;
	u32 map_flags;
	u32 id;
	struct btf_record *record;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
	char name[16];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic64_t refcnt;
	atomic64_t usercnt;
	struct work_struct work;
	struct mutex freeze_mutex;
	atomic64_t writecnt;
	struct {
		spinlock_t lock;
		enum bpf_prog_type type;
		bool jited;
		bool xdp_has_frags;
	} owner;
	bool bypass_spec_v1;
	bool frozen;
	long: 64;
	long: 64;
	long: 64;
};

struct btf_header {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};

struct btf_kfunc_set_tab;

struct btf_id_dtor_kfunc_tab;

struct btf_struct_metas;

struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct callback_head rcu;
	struct btf_kfunc_set_tab *kfunc_set_tab;
	struct btf_id_dtor_kfunc_tab *dtor_kfunc_tab;
	struct btf_struct_metas *struct_meta_tab;
	struct btf *base_btf;
	u32 start_id;
	u32 start_str_off;
	char name[56];
	bool kernel_btf;
};

struct bpf_ksym {
	long unsigned int start;
	long unsigned int end;
	char name[512];
	struct list_head lnode;
	struct latch_tree_node tnode;
	bool prog;
};

struct bpf_ctx_arg_aux;

struct bpf_trampoline;

struct bpf_jit_poke_descriptor;

struct bpf_kfunc_desc_tab;

struct bpf_kfunc_btf_tab;

struct bpf_prog_ops;

struct btf_mod_pair;

struct bpf_prog_offload;

struct bpf_func_info_aux;

struct bpf_prog_aux {
	atomic64_t refcnt;
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 max_ctx_offset;
	u32 max_pkt_offset;
	u32 max_tp_access;
	u32 stack_depth;
	u32 id;
	u32 func_cnt;
	u32 func_idx;
	u32 attach_btf_id;
	u32 ctx_arg_info_size;
	u32 max_rdonly_access;
	u32 max_rdwr_access;
	struct btf *attach_btf;
	const struct bpf_ctx_arg_aux *ctx_arg_info;
	struct mutex dst_mutex;
	struct bpf_prog *dst_prog;
	struct bpf_trampoline *dst_trampoline;
	enum bpf_prog_type saved_dst_prog_type;
	enum bpf_attach_type saved_dst_attach_type;
	bool verifier_zext;
	bool dev_bound;
	bool offload_requested;
	bool attach_btf_trace;
	bool func_proto_unreliable;
	bool sleepable;
	bool tail_call_reachable;
	bool xdp_has_frags;
	const struct btf_type *attach_func_proto;
	const char *attach_func_name;
	struct bpf_prog **func;
	void *jit_data;
	struct bpf_jit_poke_descriptor *poke_tab;
	struct bpf_kfunc_desc_tab *kfunc_tab;
	struct bpf_kfunc_btf_tab *kfunc_btf_tab;
	u32 size_poke_tab;
	struct bpf_ksym ksym;
	const struct bpf_prog_ops *ops;
	struct bpf_map **used_maps;
	struct mutex used_maps_mutex;
	struct btf_mod_pair *used_btfs;
	struct bpf_prog *prog;
	struct user_struct *user;
	u64 load_time;
	u32 verified_insns;
	int cgroup_atype;
	struct bpf_map *cgroup_storage[2];
	char name[16];
	struct bpf_prog_offload *offload;
	struct btf *btf;
	struct bpf_func_info *func_info;
	struct bpf_func_info_aux *func_info_aux;
	struct bpf_line_info *linfo;
	void **jited_linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
	u32 linfo_idx;
	struct module *mod;
	u32 num_exentries;
	struct exception_table_entry *extable;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
};

struct bpf_prog_stats;

struct sock_fprog_kern;

struct bpf_prog {
	u16 pages;
	u16 jited: 1;
	u16 jit_requested: 1;
	u16 gpl_compatible: 1;
	u16 cb_access: 1;
	u16 dst_needed: 1;
	u16 blinding_requested: 1;
	u16 blinded: 1;
	u16 is_func: 1;
	u16 kprobe_override: 1;
	u16 has_callchain_buf: 1;
	u16 enforce_expected_attach_type: 1;
	u16 call_get_stack: 1;
	u16 call_get_func_ip: 1;
	u16 tstamp_type_access: 1;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	u32 len;
	u32 jited_len;
	u8 tag[8];
	struct bpf_prog_stats *stats;
	int *active;
	unsigned int (*bpf_func)(const void *, const struct bpf_insn *);
	struct bpf_prog_aux *aux;
	struct sock_fprog_kern *orig_prog;
	union {
		struct {
			struct {} __empty_insns;
			struct sock_filter insns[0];
		};
		struct {
			struct {} __empty_insnsi;
			struct bpf_insn insnsi[0];
		};
	};
};

struct bpf_offloaded_map;

struct bpf_map_dev_ops {
	int (*map_get_next_key)(struct bpf_offloaded_map *, void *, void *);
	int (*map_lookup_elem)(struct bpf_offloaded_map *, void *, void *);
	int (*map_update_elem)(struct bpf_offloaded_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_offloaded_map *, void *);
};

struct bpf_offloaded_map {
	struct bpf_map map;
	struct net_device *netdev;
	const struct bpf_map_dev_ops *dev_ops;
	void *dev_priv;
	struct list_head offloads;
	long: 64;
	long: 64;
	long: 64;
};

struct netdev_name_node;

typedef u32 xdp_features_t;

struct net_device_stats {
	union {
		long unsigned int rx_packets;
		atomic_long_t __rx_packets;
	};
	union {
		long unsigned int tx_packets;
		atomic_long_t __tx_packets;
	};
	union {
		long unsigned int rx_bytes;
		atomic_long_t __rx_bytes;
	};
	union {
		long unsigned int tx_bytes;
		atomic_long_t __tx_bytes;
	};
	union {
		long unsigned int rx_errors;
		atomic_long_t __rx_errors;
	};
	union {
		long unsigned int tx_errors;
		atomic_long_t __tx_errors;
	};
	union {
		long unsigned int rx_dropped;
		atomic_long_t __rx_dropped;
	};
	union {
		long unsigned int tx_dropped;
		atomic_long_t __tx_dropped;
	};
	union {
		long unsigned int multicast;
		atomic_long_t __multicast;
	};
	union {
		long unsigned int collisions;
		atomic_long_t __collisions;
	};
	union {
		long unsigned int rx_length_errors;
		atomic_long_t __rx_length_errors;
	};
	union {
		long unsigned int rx_over_errors;
		atomic_long_t __rx_over_errors;
	};
	union {
		long unsigned int rx_crc_errors;
		atomic_long_t __rx_crc_errors;
	};
	union {
		long unsigned int rx_frame_errors;
		atomic_long_t __rx_frame_errors;
	};
	union {
		long unsigned int rx_fifo_errors;
		atomic_long_t __rx_fifo_errors;
	};
	union {
		long unsigned int rx_missed_errors;
		atomic_long_t __rx_missed_errors;
	};
	union {
		long unsigned int tx_aborted_errors;
		atomic_long_t __tx_aborted_errors;
	};
	union {
		long unsigned int tx_carrier_errors;
		atomic_long_t __tx_carrier_errors;
	};
	union {
		long unsigned int tx_fifo_errors;
		atomic_long_t __tx_fifo_errors;
	};
	union {
		long unsigned int tx_heartbeat_errors;
		atomic_long_t __tx_heartbeat_errors;
	};
	union {
		long unsigned int tx_window_errors;
		atomic_long_t __tx_window_errors;
	};
	union {
		long unsigned int rx_compressed;
		atomic_long_t __rx_compressed;
	};
	union {
		long unsigned int tx_compressed;
		atomic_long_t __tx_compressed;
	};
};

struct ethtool_ops;

struct netdev_hw_addr_list {
	struct list_head list;
	int count;
	struct rb_root tree;
};

struct in_device;

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER = 1,
	RX_HANDLER_EXACT = 2,
	RX_HANDLER_PASS = 3,
};

typedef enum rx_handler_result rx_handler_result_t;

typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **);

struct xdp_dev_bulk_queue;

enum netdev_ml_priv_type {
	ML_PRIV_NONE = 0,
	ML_PRIV_CAN = 1,
};

struct pcpu_dstats;

struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

struct phy_device;

struct sfp_bus;

struct udp_tunnel_nic_info;

struct udp_tunnel_nic;

struct bpf_xdp_link;

struct bpf_xdp_entity {
	struct bpf_prog *prog;
	struct bpf_xdp_link *link;
};

typedef struct {} netdevice_tracker;

struct devlink_port;

struct dev_ifalias;

struct net_device_ops;

struct xdp_metadata_ops;

struct net_device_core_stats;

struct header_ops;

struct inet6_dev;

struct netdev_rx_queue;

struct netdev_queue;

struct Qdisc;

struct pcpu_lstats;

struct pcpu_sw_netstats;

struct rtnl_link_ops;

struct rtnl_hw_stats64;

struct net_device {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	xdp_features_t xdp_features;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	const struct xdp_metadata_ops *xdp_metadata_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct ethtool_ops *ethtool_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	unsigned int gro_ipv4_max_size;
	rx_handler_func_t *rx_handler;
	void *rx_handler_data;
	struct netdev_queue *ingress_queue;
	unsigned char broadcast[32];
	struct hlist_node index_hlist;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	refcount_t dev_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED = 0,
		NETREG_REGISTERED = 1,
		NETREG_UNREGISTERING = 2,
		NETREG_UNREGISTERED = 3,
		NETREG_RELEASED = 4,
		NETREG_DUMMY = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED = 0,
		RTNL_LINK_INITIALIZING = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device *);
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct device dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	unsigned int tso_max_size;
	u16 gso_max_segs;
	u16 tso_max_segs;
	unsigned int gso_ipv4_max_size;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
	struct devlink_port *devlink_port;
	long: 64;
	long: 64;
};

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE = 1,
	PTR_TO_CTX = 2,
	CONST_PTR_TO_MAP = 3,
	PTR_TO_MAP_VALUE = 4,
	PTR_TO_MAP_KEY = 5,
	PTR_TO_STACK = 6,
	PTR_TO_PACKET_META = 7,
	PTR_TO_PACKET = 8,
	PTR_TO_PACKET_END = 9,
	PTR_TO_FLOW_KEYS = 10,
	PTR_TO_SOCKET = 11,
	PTR_TO_SOCK_COMMON = 12,
	PTR_TO_TCP_SOCK = 13,
	PTR_TO_TP_BUFFER = 14,
	PTR_TO_XDP_SOCK = 15,
	PTR_TO_BTF_ID = 16,
	PTR_TO_MEM = 17,
	PTR_TO_BUF = 18,
	PTR_TO_FUNC = 19,
	CONST_PTR_TO_DYNPTR = 20,
	__BPF_REG_TYPE_MAX = 21,
	PTR_TO_MAP_VALUE_OR_NULL = 260,
	PTR_TO_SOCKET_OR_NULL = 267,
	PTR_TO_SOCK_COMMON_OR_NULL = 268,
	PTR_TO_TCP_SOCK_OR_NULL = 269,
	PTR_TO_BTF_ID_OR_NULL = 272,
	__BPF_REG_TYPE_LIMIT = 33554431,
};

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *, const union bpf_attr *, union bpf_attr *);
};

struct bpf_offload_dev;

struct bpf_prog_offload {
	struct bpf_prog *prog;
	struct net_device *netdev;
	struct bpf_offload_dev *offdev;
	void *dev_priv;
	struct list_head offloads;
	bool dev_state;
	bool opt_failed;
	void *jited_image;
	u32 jited_len;
};

struct btf_func_model {
	u8 ret_size;
	u8 ret_flags;
	u8 nr_args;
	u8 arg_size[12];
	u8 arg_flags[12];
};

struct bpf_tramp_image {
	void *image;
	struct bpf_ksym ksym;
	struct percpu_ref pcref;
	void *ip_after_call;
	void *ip_epilogue;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct bpf_trampoline {
	struct hlist_node hlist;
	struct ftrace_ops *fops;
	struct mutex mutex;
	refcount_t refcnt;
	u32 flags;
	u64 key;
	struct {
		struct btf_func_model model;
		void *addr;
		bool ftrace_managed;
	} func;
	struct bpf_prog *extension_prog;
	struct hlist_head progs_hlist[3];
	int progs_cnt[3];
	struct bpf_tramp_image *cur_image;
	u64 selector;
	struct module *mod;
};

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
};

struct bpf_jit_poke_descriptor {
	void *tailcall_target;
	void *tailcall_bypass;
	void *bypass_addr;
	void *aux;
	union {
		struct {
			struct bpf_map *map;
			u32 key;
		} tail_call;
	};
	bool tailcall_target_stable;
	u8 adj_off;
	u16 reason;
	u32 insn_idx;
};

struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	u32 btf_id;
};

struct btf_mod_pair {
	struct btf *btf;
	struct module *module;
};

struct bpf_prog_stats {
	u64_stats_t cnt;
	u64_stats_t nsecs;
	u64_stats_t misses;
	struct u64_stats_sync syncp;
	long: 64;
};

struct sock_fprog_kern {
	u16 len;
	struct sock_filter *filter;
};

struct bpf_cgroup_storage;

struct bpf_prog_array_item {
	struct bpf_prog *prog;
	union {
		struct bpf_cgroup_storage *cgroup_storage[2];
		u64 bpf_cookie;
	};
};

struct bpf_prog_array {
	struct callback_head rcu;
	struct bpf_prog_array_item items[0];
};

struct bpf_trace_run_ctx {
	struct bpf_run_ctx run_ctx;
	u64 bpf_cookie;
};

typedef u32 (*bpf_prog_run_fn)(const struct bpf_prog *, const void *);

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

struct ipstats_mib {
	u64 mibs[37];
	struct u64_stats_sync syncp;
};

struct icmp_mib {
	long unsigned int mibs[30];
};

struct icmpmsg_mib {
	atomic_long_t mibs[512];
};

struct tcp_mib {
	long unsigned int mibs[16];
};

struct udp_mib {
	long unsigned int mibs[10];
};

struct linux_mib {
	long unsigned int mibs[127];
};

struct inet_frags;

struct fqdir {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net *net;
	bool dead;
	long: 64;
	long: 64;
	struct rhashtable rhashtable;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
	long: 64;
	long: 64;
};

struct inet_frag_queue;

struct inet_frags {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue *, const void *);
	void (*destructor)(struct inet_frag_queue *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct frag_v4_compare_key {
	__be32 saddr;
	__be32 daddr;
	u32 user;
	u32 vif;
	__be16 id;
	u16 protocol;
};

struct frag_v6_compare_key {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u32 user;
	__be32 id;
	u32 iif;
};

struct inet_frag_queue {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff *fragments_tail;
	struct sk_buff *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 mono_delivery_time;
	__u8 flags;
	u16 max_size;
	struct fqdir *fqdir;
	struct callback_head rcu;
};

enum tcp_ca_event {
	CA_EVENT_TX_START = 0,
	CA_EVENT_CWND_RESTART = 1,
	CA_EVENT_COMPLETE_CWR = 2,
	CA_EVENT_LOSS = 3,
	CA_EVENT_ECN_NO_CE = 4,
	CA_EVENT_ECN_IS_CE = 5,
};

union tcp_cc_info;

struct ack_sample;

struct rate_sample;

struct tcp_congestion_ops {
	u32 (*ssthresh)(struct sock *);
	void (*cong_avoid)(struct sock *, u32, u32);
	void (*set_state)(struct sock *, u8);
	void (*cwnd_event)(struct sock *, enum tcp_ca_event);
	void (*in_ack_event)(struct sock *, u32);
	void (*pkts_acked)(struct sock *, const struct ack_sample *);
	u32 (*min_tso_segs)(struct sock *);
	void (*cong_control)(struct sock *, const struct rate_sample *);
	u32 (*undo_cwnd)(struct sock *);
	u32 (*sndbuf_expand)(struct sock *);
	size_t (*get_info)(struct sock *, u32, int *, union tcp_cc_info *);
	char name[16];
	struct module *owner;
	struct list_head list;
	u32 key;
	u32 flags;
	void (*init)(struct sock *);
	void (*release)(struct sock *);
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct netlink_ext_ack;

struct fib_notifier_ops {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net *);
	int (*fib_dump)(struct net *, struct notifier_block *, struct netlink_ext_ack *);
	struct module *owner;
	struct callback_head rcu;
};

struct neighbour;

struct dst_ops {
	short unsigned int family;
	unsigned int gc_thresh;
	void (*gc)(struct dst_ops *);
	struct dst_entry * (*check)(struct dst_entry *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry *);
	unsigned int (*mtu)(const struct dst_entry *);
	u32 * (*cow_metrics)(struct dst_entry *, long unsigned int);
	void (*destroy)(struct dst_entry *);
	void (*ifdown)(struct dst_entry *, struct net_device *, int);
	struct dst_entry * (*negative_advice)(struct dst_entry *);
	void (*link_failure)(struct sk_buff *);
	void (*update_pmtu)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool);
	void (*redirect)(struct dst_entry *, struct sock *, struct sk_buff *);
	int (*local_out)(struct net *, struct sock *, struct sk_buff *);
	struct neighbour * (*neigh_lookup)(const struct dst_entry *, struct sk_buff *, const void *);
	void (*confirm_neigh)(const struct dst_entry *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
	long: 64;
	long: 64;
	long: 64;
};

struct uncached_list;

struct lwtunnel_state;

struct dst_entry {
	struct net_device *dev;
	struct dst_ops *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	void *__pad1;
	int (*input)(struct sk_buff *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	rcuref_t __rcuref;
	int __use;
	long unsigned int lastuse;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	netdevice_tracker dev_tracker;
	struct list_head rt_uncached;
	struct uncached_list *rt_uncached_list;
	struct lwtunnel_state *lwtstate;
};

struct hh_cache {
	unsigned int hh_len;
	seqlock_t hh_lock;
	long unsigned int hh_data[4];
};

struct neigh_table;

struct neigh_parms;

struct neigh_ops;

struct neighbour {
	struct neighbour *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	long: 0;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
};

struct gro_list {
	struct list_head list;
	int count;
};

struct napi_struct {
	struct list_head poll_list;
	long unsigned int state;
	int weight;
	int defer_hard_irqs_count;
	long unsigned int gro_bitmask;
	int (*poll)(struct napi_struct *, int);
	int list_owner;
	struct net_device *dev;
	struct gro_list gro_hash[8];
	struct sk_buff *skb;
	struct list_head rx_list;
	int rx_count;
	unsigned int napi_id;
	struct hrtimer timer;
	struct task_struct *thread;
	struct list_head dev_list;
	struct hlist_node napi_hash_node;
};

struct skb_shared_hwtstamps {
	union {
		ktime_t hwtstamp;
		void *netdev_data;
	};
};

struct xdp_mem_info {
	u32 type;
	u32 id;
};

struct xdp_rxq_info {
	struct net_device *dev;
	u32 queue_index;
	u32 reg_state;
	struct xdp_mem_info mem;
	unsigned int napi_id;
	u32 frag_size;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct xdp_txq_info {
	struct net_device *dev;
};

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz;
	u32 flags;
};

struct xdp_frame {
	void *data;
	u16 len;
	u16 headroom;
	u32 metasize;
	struct xdp_mem_info mem;
	struct net_device *dev_rx;
	u32 frame_sz;
	u32 flags;
};

enum xdp_rss_hash_type {
	XDP_RSS_L3_IPV4 = 1,
	XDP_RSS_L3_IPV6 = 2,
	XDP_RSS_L3_DYNHDR = 4,
	XDP_RSS_L4 = 8,
	XDP_RSS_L4_TCP = 16,
	XDP_RSS_L4_UDP = 32,
	XDP_RSS_L4_SCTP = 64,
	XDP_RSS_L4_IPSEC = 128,
	XDP_RSS_TYPE_NONE = 0,
	XDP_RSS_TYPE_L2 = 0,
	XDP_RSS_TYPE_L3_IPV4 = 1,
	XDP_RSS_TYPE_L3_IPV6 = 2,
	XDP_RSS_TYPE_L3_IPV4_OPT = 5,
	XDP_RSS_TYPE_L3_IPV6_EX = 6,
	XDP_RSS_TYPE_L4_ANY = 8,
	XDP_RSS_TYPE_L4_IPV4_TCP = 25,
	XDP_RSS_TYPE_L4_IPV4_UDP = 41,
	XDP_RSS_TYPE_L4_IPV4_SCTP = 73,
	XDP_RSS_TYPE_L4_IPV4_IPSEC = 137,
	XDP_RSS_TYPE_L4_IPV6_TCP = 26,
	XDP_RSS_TYPE_L4_IPV6_UDP = 42,
	XDP_RSS_TYPE_L4_IPV6_SCTP = 74,
	XDP_RSS_TYPE_L4_IPV6_IPSEC = 138,
	XDP_RSS_TYPE_L4_IPV6_TCP_EX = 30,
	XDP_RSS_TYPE_L4_IPV6_UDP_EX = 46,
	XDP_RSS_TYPE_L4_IPV6_SCTP_EX = 78,
};

typedef enum {
	SS_FREE = 0,
	SS_UNCONNECTED = 1,
	SS_CONNECTING = 2,
	SS_CONNECTED = 3,
	SS_DISCONNECTING = 4,
} socket_state;

struct socket_wq {
	wait_queue_head_t wait;
	struct fasync_struct *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
	long: 64;
};

struct proto_ops;

struct socket {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
	long: 64;
	long: 64;
	long: 64;
	struct socket_wq wq;
};

typedef struct {
	size_t written;
	size_t count;
	union {
		char *buf;
		void *data;
	} arg;
	int error;
} read_descriptor_t;

typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *, unsigned int, size_t);

typedef int (*skb_read_actor_t)(struct sock *, struct sk_buff *);

struct proto_ops {
	int family;
	struct module *owner;
	int (*release)(struct socket *);
	int (*bind)(struct socket *, struct sockaddr *, int);
	int (*connect)(struct socket *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket *, struct socket *);
	int (*accept)(struct socket *, struct socket *, int, bool);
	int (*getname)(struct socket *, struct sockaddr *, int);
	__poll_t (*poll)(struct file *, struct socket *, struct poll_table_struct *);
	int (*ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket *, void *, bool, bool);
	int (*listen)(struct socket *, int);
	int (*shutdown)(struct socket *, int);
	int (*setsockopt)(struct socket *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file *, struct socket *);
	int (*sendmsg)(struct socket *, struct msghdr *, size_t);
	int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);
	int (*mmap)(struct file *, struct socket *, struct vm_area_struct *);
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	ssize_t (*splice_read)(struct socket *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*set_peek_off)(struct sock *, int);
	int (*peek_len)(struct socket *);
	int (*read_sock)(struct sock *, read_descriptor_t *, sk_read_actor_t);
	int (*read_skb)(struct sock *, skb_read_actor_t);
	int (*sendpage_locked)(struct sock *, struct page *, int, size_t, int);
	int (*sendmsg_locked)(struct sock *, struct msghdr *, size_t);
	int (*set_rcvlowat)(struct sock *, int);
};

enum lockdown_reason {
	LOCKDOWN_NONE = 0,
	LOCKDOWN_MODULE_SIGNATURE = 1,
	LOCKDOWN_DEV_MEM = 2,
	LOCKDOWN_EFI_TEST = 3,
	LOCKDOWN_KEXEC = 4,
	LOCKDOWN_HIBERNATION = 5,
	LOCKDOWN_PCI_ACCESS = 6,
	LOCKDOWN_IOPORT = 7,
	LOCKDOWN_MSR = 8,
	LOCKDOWN_ACPI_TABLES = 9,
	LOCKDOWN_DEVICE_TREE = 10,
	LOCKDOWN_PCMCIA_CIS = 11,
	LOCKDOWN_TIOCSSERIAL = 12,
	LOCKDOWN_MODULE_PARAMETERS = 13,
	LOCKDOWN_MMIOTRACE = 14,
	LOCKDOWN_DEBUGFS = 15,
	LOCKDOWN_XMON_WR = 16,
	LOCKDOWN_BPF_WRITE_USER = 17,
	LOCKDOWN_DBG_WRITE_KERNEL = 18,
	LOCKDOWN_RTAS_ERROR_INJECTION = 19,
	LOCKDOWN_INTEGRITY_MAX = 20,
	LOCKDOWN_KCORE = 21,
	LOCKDOWN_KPROBES = 22,
	LOCKDOWN_BPF_READ_KERNEL = 23,
	LOCKDOWN_DBG_READ_KERNEL = 24,
	LOCKDOWN_PERF = 25,
	LOCKDOWN_TRACEFS = 26,
	LOCKDOWN_XMON_RW = 27,
	LOCKDOWN_XFRM_SECRET = 28,
	LOCKDOWN_CONFIDENTIALITY_MAX = 29,
};

struct nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

struct nlattr {
	__u16 nla_len;
	__u16 nla_type;
};

struct nla_policy;

struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	const struct nla_policy *policy;
	const struct nlattr *miss_nest;
	u16 miss_type;
	u8 cookie[20];
	u8 cookie_len;
	char _msg_buf[80];
};

struct netlink_range_validation;

struct netlink_range_validation_signed;

struct nla_policy {
	u8 type;
	u8 validation_type;
	u16 len;
	union {
		u16 strict_start_type;
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		struct netlink_range_validation *range;
		struct netlink_range_validation_signed *range_signed;
		struct {
			s16 min;
			s16 max;
		};
		int (*validate)(const struct nlattr *, struct netlink_ext_ack *);
	};
};

struct netlink_callback {
	struct sk_buff *skb;
	const struct nlmsghdr *nlh;
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	void *data;
	struct module *module;
	struct netlink_ext_ack *extack;
	u16 family;
	u16 answer_flags;
	u32 min_dump_alloc;
	unsigned int prev_seq;
	unsigned int seq;
	bool strict_check;
	union {
		u8 ctx[48];
		long int args[6];
	};
};

struct ndmsg {
	__u8 ndm_family;
	__u8 ndm_pad1;
	__u16 ndm_pad2;
	__s32 ndm_ifindex;
	__u16 ndm_state;
	__u8 ndm_flags;
	__u8 ndm_type;
};

struct rtnl_link_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
	__u64 collisions;
	__u64 rx_length_errors;
	__u64 rx_over_errors;
	__u64 rx_crc_errors;
	__u64 rx_frame_errors;
	__u64 rx_fifo_errors;
	__u64 rx_missed_errors;
	__u64 tx_aborted_errors;
	__u64 tx_carrier_errors;
	__u64 tx_fifo_errors;
	__u64 tx_heartbeat_errors;
	__u64 tx_window_errors;
	__u64 rx_compressed;
	__u64 tx_compressed;
	__u64 rx_nohandler;
	__u64 rx_otherhost_dropped;
};

struct rtnl_hw_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
};

struct ifla_vf_guid {
	__u32 vf;
	__u64 guid;
};

struct ifla_vf_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

struct ifla_vf_info {
	__u32 vf;
	__u8 mac[32];
	__u32 vlan;
	__u32 qos;
	__u32 spoofchk;
	__u32 linkstate;
	__u32 min_tx_rate;
	__u32 max_tx_rate;
	__u32 rss_query_en;
	__u32 trusted;
	__be16 vlan_proto;
};

struct tc_stats {
	__u64 bytes;
	__u32 packets;
	__u32 drops;
	__u32 overlimits;
	__u32 bps;
	__u32 pps;
	__u32 qlen;
	__u32 backlog;
};

struct tc_sizespec {
	unsigned char cell_log;
	unsigned char size_log;
	short int cell_align;
	int overhead;
	unsigned int linklayer;
	unsigned int mpu;
	unsigned int mtu;
	unsigned int tsize;
};

enum netdev_tx {
	__NETDEV_TX_MIN = -2147483648,
	NETDEV_TX_OK = 0,
	NETDEV_TX_BUSY = 16,
};

typedef enum netdev_tx netdev_tx_t;

struct net_device_core_stats {
	long unsigned int rx_dropped;
	long unsigned int tx_dropped;
	long unsigned int rx_nohandler;
	long unsigned int rx_otherhost_dropped;
};

struct header_ops {
	int (*create)(struct sk_buff *, struct net_device *, short unsigned int, const void *, const void *, unsigned int);
	int (*parse)(const struct sk_buff *, unsigned char *);
	int (*cache)(const struct neighbour *, struct hh_cache *, __be16);
	void (*cache_update)(struct hh_cache *, const struct net_device *, const unsigned char *);
	bool (*validate)(const char *, unsigned int);
	__be16 (*parse_protocol)(const struct sk_buff *);
};

struct netdev_queue {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct Qdisc *qdisc;
	struct Qdisc *qdisc_sleeping;
	long unsigned int tx_maxrate;
	atomic_long_t trans_timeout;
	struct net_device *sb_dev;
	long: 64;
	long: 64;
	spinlock_t _xmit_lock;
	int xmit_lock_owner;
	long unsigned int trans_start;
	long unsigned int state;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct net_rate_estimator;

struct qdisc_skb_head {
	struct sk_buff *head;
	struct sk_buff *tail;
	__u32 qlen;
	spinlock_t lock;
};

struct gnet_stats_basic_sync {
	u64_stats_t bytes;
	u64_stats_t packets;
	struct u64_stats_sync syncp;
};

struct gnet_stats_queue {
	__u32 qlen;
	__u32 backlog;
	__u32 drops;
	__u32 requeues;
	__u32 overlimits;
};

struct Qdisc_ops;

struct qdisc_size_table;

struct Qdisc {
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	unsigned int flags;
	u32 limit;
	const struct Qdisc_ops *ops;
	struct qdisc_size_table *stab;
	struct hlist_node hash;
	u32 handle;
	u32 parent;
	struct netdev_queue *dev_queue;
	struct net_rate_estimator *rate_est;
	struct gnet_stats_basic_sync *cpu_bstats;
	struct gnet_stats_queue *cpu_qstats;
	int pad;
	refcount_t refcnt;
	long: 64;
	long: 64;
	long: 64;
	struct sk_buff_head gso_skb;
	struct qdisc_skb_head q;
	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue qstats;
	long unsigned int state;
	long unsigned int state2;
	struct Qdisc *next_sched;
	struct sk_buff_head skb_bad_txq;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t busylock;
	spinlock_t seqlock;
	struct callback_head rcu;
	netdevice_tracker dev_tracker;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long int privdata[0];
};

struct netdev_rx_queue {
	struct xdp_rxq_info xdp_rxq;
	struct kobject kobj;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct netdev_phys_item_id {
	unsigned char id[32];
	unsigned char id_len;
};

enum net_device_path_type {
	DEV_PATH_ETHERNET = 0,
	DEV_PATH_VLAN = 1,
	DEV_PATH_BRIDGE = 2,
	DEV_PATH_PPPOE = 3,
	DEV_PATH_DSA = 4,
	DEV_PATH_MTK_WDMA = 5,
};

struct net_device_path {
	enum net_device_path_type type;
	const struct net_device *dev;
	union {
		struct {
			u16 id;
			__be16 proto;
			u8 h_dest[6];
		} encap;
		struct {
			enum {
				DEV_PATH_BR_VLAN_KEEP = 0,
				DEV_PATH_BR_VLAN_TAG = 1,
				DEV_PATH_BR_VLAN_UNTAG = 2,
				DEV_PATH_BR_VLAN_UNTAG_HW = 3,
			} vlan_mode;
			u16 vlan_id;
			__be16 vlan_proto;
		} bridge;
		struct {
			int port;
			u16 proto;
		} dsa;
		struct {
			u8 wdma_idx;
			u8 queue;
			u16 wcid;
			u8 bss;
		} mtk_wdma;
	};
};

struct net_device_path_ctx {
	const struct net_device *dev;
	u8 daddr[6];
	int num_vlans;
	struct {
		u16 id;
		__be16 proto;
	} vlan[2];
};

enum tc_setup_type {
	TC_QUERY_CAPS = 0,
	TC_SETUP_QDISC_MQPRIO = 1,
	TC_SETUP_CLSU32 = 2,
	TC_SETUP_CLSFLOWER = 3,
	TC_SETUP_CLSMATCHALL = 4,
	TC_SETUP_CLSBPF = 5,
	TC_SETUP_BLOCK = 6,
	TC_SETUP_QDISC_CBS = 7,
	TC_SETUP_QDISC_RED = 8,
	TC_SETUP_QDISC_PRIO = 9,
	TC_SETUP_QDISC_MQ = 10,
	TC_SETUP_QDISC_ETF = 11,
	TC_SETUP_ROOT_QDISC = 12,
	TC_SETUP_QDISC_GRED = 13,
	TC_SETUP_QDISC_TAPRIO = 14,
	TC_SETUP_FT = 15,
	TC_SETUP_QDISC_ETS = 16,
	TC_SETUP_QDISC_TBF = 17,
	TC_SETUP_QDISC_FIFO = 18,
	TC_SETUP_QDISC_HTB = 19,
	TC_SETUP_ACT = 20,
};

enum bpf_netdev_command {
	XDP_SETUP_PROG = 0,
	XDP_SETUP_PROG_HW = 1,
	BPF_OFFLOAD_MAP_ALLOC = 2,
	BPF_OFFLOAD_MAP_FREE = 3,
	XDP_SETUP_XSK_POOL = 4,
};

struct xsk_buff_pool;

struct netdev_bpf {
	enum bpf_netdev_command command;
	union {
		struct {
			u32 flags;
			struct bpf_prog *prog;
			struct netlink_ext_ack *extack;
		};
		struct {
			struct bpf_offloaded_map *offmap;
		};
		struct {
			struct xsk_buff_pool *pool;
			u16 queue_id;
		} xsk;
	};
};

struct dev_ifalias {
	struct callback_head rcuhead;
	char ifalias[0];
};

struct ip_tunnel_parm;

struct net_device_ops {
	int (*ndo_init)(struct net_device *);
	void (*ndo_uninit)(struct net_device *);
	int (*ndo_open)(struct net_device *);
	int (*ndo_stop)(struct net_device *);
	netdev_tx_t (*ndo_start_xmit)(struct sk_buff *, struct net_device *);
	netdev_features_t (*ndo_features_check)(struct sk_buff *, struct net_device *, netdev_features_t);
	u16 (*ndo_select_queue)(struct net_device *, struct sk_buff *, struct net_device *);
	void (*ndo_change_rx_flags)(struct net_device *, int);
	void (*ndo_set_rx_mode)(struct net_device *);
	int (*ndo_set_mac_address)(struct net_device *, void *);
	int (*ndo_validate_addr)(struct net_device *);
	int (*ndo_do_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_eth_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocbond)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocwandev)(struct net_device *, struct if_settings *);
	int (*ndo_siocdevprivate)(struct net_device *, struct ifreq *, void *, int);
	int (*ndo_set_config)(struct net_device *, struct ifmap *);
	int (*ndo_change_mtu)(struct net_device *, int);
	int (*ndo_neigh_setup)(struct net_device *, struct neigh_parms *);
	void (*ndo_tx_timeout)(struct net_device *, unsigned int);
	void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *);
	bool (*ndo_has_offload_stats)(const struct net_device *, int);
	int (*ndo_get_offload_stats)(int, const struct net_device *, void *);
	struct net_device_stats * (*ndo_get_stats)(struct net_device *);
	int (*ndo_vlan_rx_add_vid)(struct net_device *, __be16, u16);
	int (*ndo_vlan_rx_kill_vid)(struct net_device *, __be16, u16);
	int (*ndo_set_vf_mac)(struct net_device *, int, u8 *);
	int (*ndo_set_vf_vlan)(struct net_device *, int, u16, u8, __be16);
	int (*ndo_set_vf_rate)(struct net_device *, int, int, int);
	int (*ndo_set_vf_spoofchk)(struct net_device *, int, bool);
	int (*ndo_set_vf_trust)(struct net_device *, int, bool);
	int (*ndo_get_vf_config)(struct net_device *, int, struct ifla_vf_info *);
	int (*ndo_set_vf_link_state)(struct net_device *, int, int);
	int (*ndo_get_vf_stats)(struct net_device *, int, struct ifla_vf_stats *);
	int (*ndo_set_vf_port)(struct net_device *, int, struct nlattr **);
	int (*ndo_get_vf_port)(struct net_device *, int, struct sk_buff *);
	int (*ndo_get_vf_guid)(struct net_device *, int, struct ifla_vf_guid *, struct ifla_vf_guid *);
	int (*ndo_set_vf_guid)(struct net_device *, int, u64, int);
	int (*ndo_set_vf_rss_query_en)(struct net_device *, int, bool);
	int (*ndo_setup_tc)(struct net_device *, enum tc_setup_type, void *);
	int (*ndo_add_slave)(struct net_device *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_del_slave)(struct net_device *, struct net_device *);
	struct net_device * (*ndo_get_xmit_slave)(struct net_device *, struct sk_buff *, bool);
	struct net_device * (*ndo_sk_get_lower_dev)(struct net_device *, struct sock *);
	netdev_features_t (*ndo_fix_features)(struct net_device *, netdev_features_t);
	int (*ndo_set_features)(struct net_device *, netdev_features_t);
	int (*ndo_neigh_construct)(struct net_device *, struct neighbour *);
	void (*ndo_neigh_destroy)(struct net_device *, struct neighbour *);
	int (*ndo_fdb_add)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del_bulk)(struct ndmsg *, struct nlattr **, struct net_device *, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_dump)(struct sk_buff *, struct netlink_callback *, struct net_device *, struct net_device *, int *);
	int (*ndo_fdb_get)(struct sk_buff *, struct nlattr **, struct net_device *, const unsigned char *, u16, u32, u32, struct netlink_ext_ack *);
	int (*ndo_mdb_add)(struct net_device *, struct nlattr **, u16, struct netlink_ext_ack *);
	int (*ndo_mdb_del)(struct net_device *, struct nlattr **, struct netlink_ext_ack *);
	int (*ndo_mdb_dump)(struct net_device *, struct sk_buff *, struct netlink_callback *);
	int (*ndo_bridge_setlink)(struct net_device *, struct nlmsghdr *, u16, struct netlink_ext_ack *);
	int (*ndo_bridge_getlink)(struct sk_buff *, u32, u32, struct net_device *, u32, int);
	int (*ndo_bridge_dellink)(struct net_device *, struct nlmsghdr *, u16);
	int (*ndo_change_carrier)(struct net_device *, bool);
	int (*ndo_get_phys_port_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_port_parent_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_phys_port_name)(struct net_device *, char *, size_t);
	void * (*ndo_dfwd_add_station)(struct net_device *, struct net_device *);
	void (*ndo_dfwd_del_station)(struct net_device *, void *);
	int (*ndo_set_tx_maxrate)(struct net_device *, int, u32);
	int (*ndo_get_iflink)(const struct net_device *);
	int (*ndo_fill_metadata_dst)(struct net_device *, struct sk_buff *);
	void (*ndo_set_rx_headroom)(struct net_device *, int);
	int (*ndo_bpf)(struct net_device *, struct netdev_bpf *);
	int (*ndo_xdp_xmit)(struct net_device *, int, struct xdp_frame **, u32);
	struct net_device * (*ndo_xdp_get_xmit_slave)(struct net_device *, struct xdp_buff *);
	int (*ndo_xsk_wakeup)(struct net_device *, u32, u32);
	int (*ndo_tunnel_ctl)(struct net_device *, struct ip_tunnel_parm *, int);
	struct net_device * (*ndo_get_peer_dev)(struct net_device *);
	int (*ndo_fill_forward_path)(struct net_device_path_ctx *, struct net_device_path *);
	ktime_t (*ndo_get_tstamp)(struct net_device *, const struct skb_shared_hwtstamps *, bool);
};

struct neigh_parms {
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head list;
	int (*neigh_setup)(struct neighbour *);
	struct neigh_table *tbl;
	void *sysctl_table;
	int dead;
	refcount_t refcnt;
	struct callback_head callback_head;
	int reachable_time;
	u32 qlen;
	int data[14];
	long unsigned int data_state[1];
};

struct xdp_metadata_ops {
	int (*xmo_rx_timestamp)(const struct xdp_md *, u64 *);
	int (*xmo_rx_hash)(const struct xdp_md *, u32 *, enum xdp_rss_hash_type *);
};

struct pcpu_lstats {
	u64_stats_t packets;
	u64_stats_t bytes;
	struct u64_stats_sync syncp;
};

struct pcpu_sw_netstats {
	u64_stats_t rx_packets;
	u64_stats_t rx_bytes;
	u64_stats_t tx_packets;
	u64_stats_t tx_bytes;
	struct u64_stats_sync syncp;
};

struct rtnl_link_ops {
	struct list_head list;
	const char *kind;
	size_t priv_size;
	struct net_device * (*alloc)(struct nlattr **, const char *, unsigned char, unsigned int, unsigned int);
	void (*setup)(struct net_device *);
	bool netns_refund;
	unsigned int maxtype;
	const struct nla_policy *policy;
	int (*validate)(struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*newlink)(struct net *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*changelink)(struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	void (*dellink)(struct net_device *, struct list_head *);
	size_t (*get_size)(const struct net_device *);
	int (*fill_info)(struct sk_buff *, const struct net_device *);
	size_t (*get_xstats_size)(const struct net_device *);
	int (*fill_xstats)(struct sk_buff *, const struct net_device *);
	unsigned int (*get_num_tx_queues)();
	unsigned int (*get_num_rx_queues)();
	unsigned int slave_maxtype;
	const struct nla_policy *slave_policy;
	int (*slave_changelink)(struct net_device *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	size_t (*get_slave_size)(const struct net_device *, const struct net_device *);
	int (*fill_slave_info)(struct sk_buff *, const struct net_device *, const struct net_device *);
	struct net * (*get_link_net)(const struct net_device *);
	size_t (*get_linkxstats_size)(const struct net_device *, int);
	int (*fill_linkxstats)(struct sk_buff *, const struct net_device *, int *, int);
};

struct tcmsg {
	unsigned char tcm_family;
	unsigned char tcm__pad1;
	short unsigned int tcm__pad2;
	int tcm_ifindex;
	__u32 tcm_handle;
	__u32 tcm_parent;
	__u32 tcm_info;
};

struct netlink_range_validation {
	u64 min;
	u64 max;
};

struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};

struct pneigh_entry;

struct neigh_statistics;

struct neigh_hash_table;

struct neigh_table {
	int family;
	unsigned int entry_size;
	unsigned int key_len;
	__be16 protocol;
	__u32 (*hash)(const void *, const struct net_device *, __u32 *);
	bool (*key_eq)(const struct neighbour *, const void *);
	int (*constructor)(struct neighbour *);
	int (*pconstructor)(struct pneigh_entry *);
	void (*pdestructor)(struct pneigh_entry *);
	void (*proxy_redo)(struct sk_buff *);
	int (*is_multicast)(const void *);
	bool (*allow_add)(const struct net_device *, struct netlink_ext_ack *);
	char *id;
	struct neigh_parms parms;
	struct list_head parms_list;
	int gc_interval;
	int gc_thresh1;
	int gc_thresh2;
	int gc_thresh3;
	long unsigned int last_flush;
	struct delayed_work gc_work;
	struct delayed_work managed_work;
	struct timer_list proxy_timer;
	struct sk_buff_head proxy_queue;
	atomic_t entries;
	atomic_t gc_entries;
	struct list_head gc_list;
	struct list_head managed_list;
	rwlock_t lock;
	long unsigned int last_rand;
	struct neigh_statistics *stats;
	struct neigh_hash_table *nht;
	struct pneigh_entry **phash_buckets;
};

struct neigh_statistics {
	long unsigned int allocs;
	long unsigned int destroys;
	long unsigned int hash_grows;
	long unsigned int res_failed;
	long unsigned int lookups;
	long unsigned int hits;
	long unsigned int rcv_probes_mcast;
	long unsigned int rcv_probes_ucast;
	long unsigned int periodic_gc_runs;
	long unsigned int forced_gc_runs;
	long unsigned int unres_discards;
	long unsigned int table_fulls;
};

struct neigh_ops {
	int family;
	void (*solicit)(struct neighbour *, struct sk_buff *);
	void (*error_report)(struct neighbour *, struct sk_buff *);
	int (*output)(struct neighbour *, struct sk_buff *);
	int (*connected_output)(struct neighbour *, struct sk_buff *);
};

struct pneigh_entry {
	struct pneigh_entry *next;
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
	u8 protocol;
	u32 key[0];
};

struct neigh_hash_table {
	struct neighbour **hash_buckets;
	unsigned int hash_shift;
	__u32 hash_rnd[4];
	struct callback_head rcu;
};

struct raw_hashinfo;

struct smc_hashinfo;

struct sk_psock;

struct request_sock_ops;

struct timewait_sock_ops;

struct proto {
	void (*close)(struct sock *, long int);
	int (*pre_connect)(struct sock *, struct sockaddr *, int);
	int (*connect)(struct sock *, struct sockaddr *, int);
	int (*disconnect)(struct sock *, int);
	struct sock * (*accept)(struct sock *, int, int *, bool);
	int (*ioctl)(struct sock *, int, long unsigned int);
	int (*init)(struct sock *);
	void (*destroy)(struct sock *);
	void (*shutdown)(struct sock *, int);
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*keepalive)(struct sock *, int);
	int (*sendmsg)(struct sock *, struct msghdr *, size_t);
	int (*recvmsg)(struct sock *, struct msghdr *, size_t, int, int *);
	int (*sendpage)(struct sock *, struct page *, int, size_t, int);
	int (*bind)(struct sock *, struct sockaddr *, int);
	int (*bind_add)(struct sock *, struct sockaddr *, int);
	int (*backlog_rcv)(struct sock *, struct sk_buff *);
	bool (*bpf_bypass_getsockopt)(int, int);
	void (*release_cb)(struct sock *);
	int (*hash)(struct sock *);
	void (*unhash)(struct sock *);
	void (*rehash)(struct sock *);
	int (*get_port)(struct sock *, short unsigned int);
	void (*put_port)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	bool (*stream_memory_free)(const struct sock *, int);
	bool (*sock_is_readable)(struct sock *);
	void (*enter_memory_pressure)(struct sock *);
	void (*leave_memory_pressure)(struct sock *);
	atomic_long_t *memory_allocated;
	int *per_cpu_fw_alloc;
	struct percpu_counter *sockets_allocated;
	long unsigned int *memory_pressure;
	long int *sysctl_mem;
	int *sysctl_wmem;
	int *sysctl_rmem;
	u32 sysctl_wmem_offset;
	u32 sysctl_rmem_offset;
	int max_header;
	bool no_autobind;
	struct kmem_cache *slab;
	unsigned int obj_size;
	slab_flags_t slab_flags;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int *orphan_count;
	struct request_sock_ops *rsk_prot;
	struct timewait_sock_ops *twsk_prot;
	union {
		struct inet_hashinfo *hashinfo;
		struct udp_table *udp_table;
		struct raw_hashinfo *raw_hash;
		struct smc_hashinfo *smc_hash;
	} h;
	struct module *owner;
	char name[32];
	struct list_head node;
	int (*diag_destroy)(struct sock *, int);
};

struct sk_filter {
	refcount_t refcnt;
	struct callback_head rcu;
	struct bpf_prog *prog;
};

struct gnet_dump {
	spinlock_t *lock;
	struct sk_buff *skb;
	struct nlattr *tail;
	int compat_tc_stats;
	int compat_xstats;
	int padattr;
	void *xstats;
	int xstats_len;
	struct tc_stats tc_stats;
};

enum flow_action_hw_stats_bit {
	FLOW_ACTION_HW_STATS_IMMEDIATE_BIT = 0,
	FLOW_ACTION_HW_STATS_DELAYED_BIT = 1,
	FLOW_ACTION_HW_STATS_DISABLED_BIT = 2,
	FLOW_ACTION_HW_STATS_NUM_BITS = 3,
};

struct flow_block {
	struct list_head cb_list;
};

typedef int flow_setup_cb_t(enum tc_setup_type, void *, void *);

struct qdisc_size_table {
	struct callback_head rcu;
	struct list_head list;
	struct tc_sizespec szopts;
	int refcnt;
	u16 data[0];
};

struct Qdisc_class_ops;

struct Qdisc_ops {
	struct Qdisc_ops *next;
	const struct Qdisc_class_ops *cl_ops;
	char id[16];
	int priv_size;
	unsigned int static_flags;
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	struct sk_buff * (*peek)(struct Qdisc *);
	int (*init)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*reset)(struct Qdisc *);
	void (*destroy)(struct Qdisc *);
	int (*change)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*attach)(struct Qdisc *);
	int (*change_tx_queue_len)(struct Qdisc *, unsigned int);
	void (*change_real_num_tx)(struct Qdisc *, unsigned int);
	int (*dump)(struct Qdisc *, struct sk_buff *);
	int (*dump_stats)(struct Qdisc *, struct gnet_dump *);
	void (*ingress_block_set)(struct Qdisc *, u32);
	void (*egress_block_set)(struct Qdisc *, u32);
	u32 (*ingress_block_get)(struct Qdisc *);
	u32 (*egress_block_get)(struct Qdisc *);
	struct module *owner;
};

struct qdisc_walker;

struct tcf_block;

struct Qdisc_class_ops {
	unsigned int flags;
	struct netdev_queue * (*select_queue)(struct Qdisc *, struct tcmsg *);
	int (*graft)(struct Qdisc *, long unsigned int, struct Qdisc *, struct Qdisc **, struct netlink_ext_ack *);
	struct Qdisc * (*leaf)(struct Qdisc *, long unsigned int);
	void (*qlen_notify)(struct Qdisc *, long unsigned int);
	long unsigned int (*find)(struct Qdisc *, u32);
	int (*change)(struct Qdisc *, u32, u32, struct nlattr **, long unsigned int *, struct netlink_ext_ack *);
	int (*delete)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	void (*walk)(struct Qdisc *, struct qdisc_walker *);
	struct tcf_block * (*tcf_block)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	long unsigned int (*bind_tcf)(struct Qdisc *, long unsigned int, u32);
	void (*unbind_tcf)(struct Qdisc *, long unsigned int);
	int (*dump)(struct Qdisc *, long unsigned int, struct sk_buff *, struct tcmsg *);
	int (*dump_stats)(struct Qdisc *, long unsigned int, struct gnet_dump *);
};

struct tcf_chain;

struct tcf_block {
	struct mutex lock;
	struct list_head chain_list;
	u32 index;
	u32 classid;
	refcount_t refcnt;
	struct net *net;
	struct Qdisc *q;
	struct rw_semaphore cb_lock;
	struct flow_block flow_block;
	struct list_head owner_list;
	bool keep_dst;
	atomic_t offloadcnt;
	unsigned int nooffloaddevcnt;
	unsigned int lockeddevcnt;
	struct {
		struct tcf_chain *chain;
		struct list_head filter_chain_list;
	} chain0;
	struct callback_head rcu;
	struct hlist_head proto_destroy_ht[128];
	struct mutex proto_destroy_lock;
};

struct tcf_result;

struct tcf_proto_ops;

struct tcf_proto {
	struct tcf_proto *next;
	void *root;
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	__be16 protocol;
	u32 prio;
	void *data;
	const struct tcf_proto_ops *ops;
	struct tcf_chain *chain;
	spinlock_t lock;
	bool deleting;
	refcount_t refcnt;
	struct callback_head rcu;
	struct hlist_node destroy_ht_node;
};

struct tcf_result {
	union {
		struct {
			long unsigned int class;
			u32 classid;
		};
		const struct tcf_proto *goto_tp;
	};
};

struct tcf_walker;

struct tcf_exts;

struct tcf_proto_ops {
	struct list_head head;
	char kind[16];
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	int (*init)(struct tcf_proto *);
	void (*destroy)(struct tcf_proto *, bool, struct netlink_ext_ack *);
	void * (*get)(struct tcf_proto *, u32);
	void (*put)(struct tcf_proto *, void *);
	int (*change)(struct net *, struct sk_buff *, struct tcf_proto *, long unsigned int, u32, struct nlattr **, void **, u32, struct netlink_ext_ack *);
	int (*delete)(struct tcf_proto *, void *, bool *, bool, struct netlink_ext_ack *);
	bool (*delete_empty)(struct tcf_proto *);
	void (*walk)(struct tcf_proto *, struct tcf_walker *, bool);
	int (*reoffload)(struct tcf_proto *, bool, flow_setup_cb_t *, void *, struct netlink_ext_ack *);
	void (*hw_add)(struct tcf_proto *, void *);
	void (*hw_del)(struct tcf_proto *, void *);
	void (*bind_class)(void *, u32, long unsigned int, void *, long unsigned int);
	void * (*tmplt_create)(struct net *, struct tcf_chain *, struct nlattr **, struct netlink_ext_ack *);
	void (*tmplt_destroy)(void *);
	struct tcf_exts * (*get_exts)(const struct tcf_proto *, u32);
	int (*dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*terse_dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*tmplt_dump)(struct sk_buff *, struct net *, void *);
	struct module *owner;
	int flags;
};

struct tcf_chain {
	struct mutex filter_chain_lock;
	struct tcf_proto *filter_chain;
	struct list_head list;
	struct tcf_block *block;
	u32 index;
	unsigned int refcnt;
	unsigned int action_refcnt;
	bool explicitly_created;
	bool flushing;
	const struct tcf_proto_ops *tmplt_ops;
	void *tmplt_priv;
	struct callback_head rcu;
};

typedef unsigned int (*bpf_dispatcher_fn)(const void *, const struct bpf_insn *, unsigned int (*)(const void *, const struct bpf_insn *));

struct prog_entry;

struct event_filter {
	struct prog_entry *prog;
	char *filter_string;
};

struct trace_array_cpu;

struct array_buffer {
	struct trace_array *tr;
	struct trace_buffer *buffer;
	struct trace_array_cpu *data;
	u64 time_start;
	int cpu;
};

struct trace_pid_list;

struct trace_options;

struct trace_func_repeats;

struct trace_array {
	struct list_head list;
	char *name;
	struct array_buffer array_buffer;
	struct trace_pid_list *filtered_pids;
	struct trace_pid_list *filtered_no_pids;
	arch_spinlock_t max_lock;
	int buffer_disabled;
	int stop_count;
	int clock_id;
	int nr_topts;
	bool clear_trace;
	int buffer_percent;
	unsigned int n_err_log_entries;
	struct tracer *current_trace;
	unsigned int trace_flags;
	unsigned char trace_flags_index[32];
	unsigned int flags;
	raw_spinlock_t start_lock;
	struct list_head err_log;
	struct dentry *dir;
	struct dentry *options;
	struct dentry *percpu_dir;
	struct dentry *event_dir;
	struct trace_options *topts;
	struct list_head systems;
	struct list_head events;
	struct trace_event_file *trace_marker_file;
	cpumask_var_t tracing_cpumask;
	int ref;
	int trace_ref;
	struct ftrace_ops *ops;
	struct trace_pid_list *function_pids;
	struct trace_pid_list *function_no_pids;
	struct list_head func_probes;
	struct list_head mod_trace;
	struct list_head mod_notrace;
	int function_enabled;
	int no_filter_buffering_ref;
	struct list_head hist_vars;
	struct trace_func_repeats *last_func_repeats;
};

struct tracer_flags;

struct tracer {
	const char *name;
	int (*init)(struct trace_array *);
	void (*reset)(struct trace_array *);
	void (*start)(struct trace_array *);
	void (*stop)(struct trace_array *);
	int (*update_thresh)(struct trace_array *);
	void (*open)(struct trace_iterator *);
	void (*pipe_open)(struct trace_iterator *);
	void (*close)(struct trace_iterator *);
	void (*pipe_close)(struct trace_iterator *);
	ssize_t (*read)(struct trace_iterator *, struct file *, char *, size_t, loff_t *);
	ssize_t (*splice_read)(struct trace_iterator *, struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*print_header)(struct seq_file *);
	enum print_line_t (*print_line)(struct trace_iterator *);
	int (*set_flag)(struct trace_array *, u32, u32, int);
	int (*flag_changed)(struct trace_array *, u32, int);
	struct tracer *next;
	struct tracer_flags *flags;
	int enabled;
	bool print_max;
	bool allow_instances;
	bool noboot;
};

struct event_subsystem;

struct trace_subsystem_dir {
	struct list_head list;
	struct event_subsystem *subsystem;
	struct trace_array *tr;
	struct dentry *entry;
	int ref_count;
	int nr_events;
};

union lower_chunk {
	union lower_chunk *next;
	long unsigned int data[256];
};

union upper_chunk {
	union upper_chunk *next;
	union lower_chunk *data[256];
};

struct trace_pid_list {
	raw_spinlock_t lock;
	struct irq_work refill_irqwork;
	union upper_chunk *upper[256];
	union upper_chunk *upper_list;
	union lower_chunk *lower_list;
	int free_upper_chunks;
	int free_lower_chunks;
};

struct trace_array_cpu {
	atomic_t disabled;
	void *buffer_page;
	long unsigned int entries;
	long unsigned int saved_latency;
	long unsigned int critical_start;
	long unsigned int critical_end;
	long unsigned int critical_sequence;
	long unsigned int nice;
	long unsigned int policy;
	long unsigned int rt_priority;
	long unsigned int skipped_entries;
	u64 preempt_timestamp;
	pid_t pid;
	kuid_t uid;
	char comm[16];
	int ftrace_ignore_pid;
	bool ignore_pid;
};

struct trace_option_dentry;

struct trace_options {
	struct tracer *tracer;
	struct trace_option_dentry *topts;
};

struct tracer_opt;

struct trace_option_dentry {
	struct tracer_opt *opt;
	struct tracer_flags *flags;
	struct trace_array *tr;
	struct dentry *entry;
};

struct trace_func_repeats {
	long unsigned int ip;
	long unsigned int parent_ip;
	long unsigned int count;
	u64 ts_last_call;
};

struct tracer_opt {
	const char *name;
	u32 bit;
};

struct tracer_flags {
	u32 val;
	struct tracer_opt *opts;
	struct tracer *trace;
};

enum trace_iterator_bits {
	TRACE_ITER_PRINT_PARENT_BIT = 0,
	TRACE_ITER_SYM_OFFSET_BIT = 1,
	TRACE_ITER_SYM_ADDR_BIT = 2,
	TRACE_ITER_VERBOSE_BIT = 3,
	TRACE_ITER_RAW_BIT = 4,
	TRACE_ITER_HEX_BIT = 5,
	TRACE_ITER_BIN_BIT = 6,
	TRACE_ITER_BLOCK_BIT = 7,
	TRACE_ITER_FIELDS_BIT = 8,
	TRACE_ITER_PRINTK_BIT = 9,
	TRACE_ITER_ANNOTATE_BIT = 10,
	TRACE_ITER_USERSTACKTRACE_BIT = 11,
	TRACE_ITER_SYM_USEROBJ_BIT = 12,
	TRACE_ITER_PRINTK_MSGONLY_BIT = 13,
	TRACE_ITER_CONTEXT_INFO_BIT = 14,
	TRACE_ITER_LATENCY_FMT_BIT = 15,
	TRACE_ITER_RECORD_CMD_BIT = 16,
	TRACE_ITER_RECORD_TGID_BIT = 17,
	TRACE_ITER_OVERWRITE_BIT = 18,
	TRACE_ITER_STOP_ON_FREE_BIT = 19,
	TRACE_ITER_IRQ_INFO_BIT = 20,
	TRACE_ITER_MARKERS_BIT = 21,
	TRACE_ITER_EVENT_FORK_BIT = 22,
	TRACE_ITER_PAUSE_ON_TRACE_BIT = 23,
	TRACE_ITER_HASH_PTR_BIT = 24,
	TRACE_ITER_FUNCTION_BIT = 25,
	TRACE_ITER_FUNC_FORK_BIT = 26,
	TRACE_ITER_DISPLAY_GRAPH_BIT = 27,
	TRACE_ITER_STACKTRACE_BIT = 28,
	TRACE_ITER_LAST_BIT = 29,
};

struct event_subsystem {
	struct list_head list;
	const char *name;
	struct event_filter *filter;
	int ref_count;
};

struct dyn_event;

struct dyn_event_operations {
	struct list_head list;
	int (*create)(const char *);
	int (*show)(struct seq_file *, struct dyn_event *);
	bool (*is_busy)(struct dyn_event *);
	int (*free)(struct dyn_event *);
	bool (*match)(const char *, const char *, int, const char **, struct dyn_event *);
};

struct dyn_event {
	struct list_head list;
	struct dyn_event_operations *ops;
};

typedef int (*print_type_func_t)(struct trace_seq *, void *, void *);

enum fetch_op {
	FETCH_OP_NOP = 0,
	FETCH_OP_REG = 1,
	FETCH_OP_STACK = 2,
	FETCH_OP_STACKP = 3,
	FETCH_OP_RETVAL = 4,
	FETCH_OP_IMM = 5,
	FETCH_OP_COMM = 6,
	FETCH_OP_ARG = 7,
	FETCH_OP_FOFFS = 8,
	FETCH_OP_DATA = 9,
	FETCH_OP_DEREF = 10,
	FETCH_OP_UDEREF = 11,
	FETCH_OP_ST_RAW = 12,
	FETCH_OP_ST_MEM = 13,
	FETCH_OP_ST_UMEM = 14,
	FETCH_OP_ST_STRING = 15,
	FETCH_OP_ST_USTRING = 16,
	FETCH_OP_ST_SYMSTR = 17,
	FETCH_OP_MOD_BF = 18,
	FETCH_OP_LP_ARRAY = 19,
	FETCH_OP_TP_ARG = 20,
	FETCH_OP_END = 21,
	FETCH_NOP_SYMBOL = 22,
};

struct fetch_insn {
	enum fetch_op op;
	union {
		unsigned int param;
		struct {
			unsigned int size;
			int offset;
		};
		struct {
			unsigned char basesize;
			unsigned char lshift;
			unsigned char rshift;
		};
		long unsigned int immediate;
		void *data;
	};
};

struct fetch_type {
	const char *name;
	size_t size;
	bool is_signed;
	bool is_string;
	print_type_func_t print;
	const char *fmt;
	const char *fmttype;
};

struct probe_arg {
	struct fetch_insn *code;
	bool dynamic;
	unsigned int offset;
	unsigned int count;
	const char *name;
	const char *comm;
	char *fmt;
	const struct fetch_type *type;
};

struct trace_uprobe_filter {
	rwlock_t rwlock;
	int nr_systemwide;
	struct list_head perf_events;
};

struct trace_probe_event {
	unsigned int flags;
	struct trace_event_class class;
	struct trace_event_call call;
	struct list_head files;
	struct list_head probes;
	struct trace_uprobe_filter filter[0];
};

struct trace_probe {
	struct list_head list;
	struct trace_probe_event *event;
	ssize_t size;
	unsigned int nr_args;
	struct probe_arg args[0];
};

struct event_file_link {
	struct trace_event_file *file;
	struct list_head list;
};

enum probe_print_type {
	PROBE_PRINT_NORMAL = 0,
	PROBE_PRINT_RETURN = 1,
	PROBE_PRINT_EVENT = 2,
};

enum {
	TP_ERR_FILE_NOT_FOUND = 0,
	TP_ERR_NO_REGULAR_FILE = 1,
	TP_ERR_BAD_REFCNT = 2,
	TP_ERR_REFCNT_OPEN_BRACE = 3,
	TP_ERR_BAD_REFCNT_SUFFIX = 4,
	TP_ERR_BAD_UPROBE_OFFS = 5,
	TP_ERR_MAXACT_NO_KPROBE = 6,
	TP_ERR_BAD_MAXACT = 7,
	TP_ERR_MAXACT_TOO_BIG = 8,
	TP_ERR_BAD_PROBE_ADDR = 9,
	TP_ERR_BAD_RETPROBE = 10,
	TP_ERR_BAD_ADDR_SUFFIX = 11,
	TP_ERR_NO_GROUP_NAME = 12,
	TP_ERR_GROUP_TOO_LONG = 13,
	TP_ERR_BAD_GROUP_NAME = 14,
	TP_ERR_NO_EVENT_NAME = 15,
	TP_ERR_EVENT_TOO_LONG = 16,
	TP_ERR_BAD_EVENT_NAME = 17,
	TP_ERR_EVENT_EXIST = 18,
	TP_ERR_RETVAL_ON_PROBE = 19,
	TP_ERR_BAD_STACK_NUM = 20,
	TP_ERR_BAD_ARG_NUM = 21,
	TP_ERR_BAD_VAR = 22,
	TP_ERR_BAD_REG_NAME = 23,
	TP_ERR_BAD_MEM_ADDR = 24,
	TP_ERR_BAD_IMM = 25,
	TP_ERR_IMMSTR_NO_CLOSE = 26,
	TP_ERR_FILE_ON_KPROBE = 27,
	TP_ERR_BAD_FILE_OFFS = 28,
	TP_ERR_SYM_ON_UPROBE = 29,
	TP_ERR_TOO_MANY_OPS = 30,
	TP_ERR_DEREF_NEED_BRACE = 31,
	TP_ERR_BAD_DEREF_OFFS = 32,
	TP_ERR_DEREF_OPEN_BRACE = 33,
	TP_ERR_COMM_CANT_DEREF = 34,
	TP_ERR_BAD_FETCH_ARG = 35,
	TP_ERR_ARRAY_NO_CLOSE = 36,
	TP_ERR_BAD_ARRAY_SUFFIX = 37,
	TP_ERR_BAD_ARRAY_NUM = 38,
	TP_ERR_ARRAY_TOO_BIG = 39,
	TP_ERR_BAD_TYPE = 40,
	TP_ERR_BAD_STRING = 41,
	TP_ERR_BAD_SYMSTRING = 42,
	TP_ERR_BAD_BITFIELD = 43,
	TP_ERR_ARG_NAME_TOO_LONG = 44,
	TP_ERR_NO_ARG_NAME = 45,
	TP_ERR_BAD_ARG_NAME = 46,
	TP_ERR_USED_ARG_NAME = 47,
	TP_ERR_ARG_TOO_LONG = 48,
	TP_ERR_NO_ARG_BODY = 49,
	TP_ERR_BAD_INSN_BNDRY = 50,
	TP_ERR_FAIL_REG_PROBE = 51,
	TP_ERR_DIFF_PROBE_TYPE = 52,
	TP_ERR_DIFF_ARG_TYPE = 53,
	TP_ERR_SAME_PROBE = 54,
	TP_ERR_NO_EVENT_INFO = 55,
	TP_ERR_BAD_ATTACH_EVENT = 56,
	TP_ERR_BAD_ATTACH_ARG = 57,
	TP_ERR_NO_EP_FILTER = 58,
};

struct uprobe_trace_entry_head {
	struct trace_entry ent;
	long unsigned int vaddr[0];
};

struct trace_uprobe {
	struct dyn_event devent;
	struct uprobe_consumer consumer;
	struct path path;
	struct inode *inode;
	char *filename;
	long unsigned int offset;
	long unsigned int ref_ctr_offset;
	long unsigned int nhit;
	struct trace_probe tp;
};

struct uprobe_dispatch_data {
	struct trace_uprobe *tu;
	long unsigned int bp_addr;
};

struct uprobe_cpu_buffer {
	struct mutex mutex;
	void *buf;
};

typedef bool (*filter_func_t)(struct uprobe_consumer *, enum uprobe_filter_ctx, struct mm_struct *);

struct bpf_array_aux {
	struct list_head poke_progs;
	struct bpf_map *map;
	struct mutex poke_mutex;
	struct work_struct work;
};

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	u32 index_mask;
	struct bpf_array_aux *aux;
	union {
		struct {
			struct {} __empty_value;
			char value[0];
		};
		struct {
			struct {} __empty_ptrs;
			void *ptrs[0];
		};
		struct {
			struct {} __empty_pptrs;
			void *pptrs[0];
		};
	};
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef void (*rcu_callback_t)(struct callback_head *);

enum {
	BPF_REG_0 = 0,
	BPF_REG_1 = 1,
	BPF_REG_2 = 2,
	BPF_REG_3 = 3,
	BPF_REG_4 = 4,
	BPF_REG_5 = 5,
	BPF_REG_6 = 6,
	BPF_REG_7 = 7,
	BPF_REG_8 = 8,
	BPF_REG_9 = 9,
	BPF_REG_10 = 10,
	__MAX_BPF_REG = 11,
};

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	BPF_LINK_TYPE_STRUCT_OPS = 9,
	BPF_LINK_TYPE_NETFILTER = 10,
	MAX_BPF_LINK_TYPE = 11,
};

enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_probe_read = 4,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_skb_store_bytes = 9,
	BPF_FUNC_l3_csum_replace = 10,
	BPF_FUNC_l4_csum_replace = 11,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_clone_redirect = 13,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_get_cgroup_classid = 17,
	BPF_FUNC_skb_vlan_push = 18,
	BPF_FUNC_skb_vlan_pop = 19,
	BPF_FUNC_skb_get_tunnel_key = 20,
	BPF_FUNC_skb_set_tunnel_key = 21,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_redirect = 23,
	BPF_FUNC_get_route_realm = 24,
	BPF_FUNC_perf_event_output = 25,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_stackid = 27,
	BPF_FUNC_csum_diff = 28,
	BPF_FUNC_skb_get_tunnel_opt = 29,
	BPF_FUNC_skb_set_tunnel_opt = 30,
	BPF_FUNC_skb_change_proto = 31,
	BPF_FUNC_skb_change_type = 32,
	BPF_FUNC_skb_under_cgroup = 33,
	BPF_FUNC_get_hash_recalc = 34,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_probe_write_user = 36,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_skb_change_tail = 38,
	BPF_FUNC_skb_pull_data = 39,
	BPF_FUNC_csum_update = 40,
	BPF_FUNC_set_hash_invalid = 41,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_skb_change_head = 43,
	BPF_FUNC_xdp_adjust_head = 44,
	BPF_FUNC_probe_read_str = 45,
	BPF_FUNC_get_socket_cookie = 46,
	BPF_FUNC_get_socket_uid = 47,
	BPF_FUNC_set_hash = 48,
	BPF_FUNC_setsockopt = 49,
	BPF_FUNC_skb_adjust_room = 50,
	BPF_FUNC_redirect_map = 51,
	BPF_FUNC_sk_redirect_map = 52,
	BPF_FUNC_sock_map_update = 53,
	BPF_FUNC_xdp_adjust_meta = 54,
	BPF_FUNC_perf_event_read_value = 55,
	BPF_FUNC_perf_prog_read_value = 56,
	BPF_FUNC_getsockopt = 57,
	BPF_FUNC_override_return = 58,
	BPF_FUNC_sock_ops_cb_flags_set = 59,
	BPF_FUNC_msg_redirect_map = 60,
	BPF_FUNC_msg_apply_bytes = 61,
	BPF_FUNC_msg_cork_bytes = 62,
	BPF_FUNC_msg_pull_data = 63,
	BPF_FUNC_bind = 64,
	BPF_FUNC_xdp_adjust_tail = 65,
	BPF_FUNC_skb_get_xfrm_state = 66,
	BPF_FUNC_get_stack = 67,
	BPF_FUNC_skb_load_bytes_relative = 68,
	BPF_FUNC_fib_lookup = 69,
	BPF_FUNC_sock_hash_update = 70,
	BPF_FUNC_msg_redirect_hash = 71,
	BPF_FUNC_sk_redirect_hash = 72,
	BPF_FUNC_lwt_push_encap = 73,
	BPF_FUNC_lwt_seg6_store_bytes = 74,
	BPF_FUNC_lwt_seg6_adjust_srh = 75,
	BPF_FUNC_lwt_seg6_action = 76,
	BPF_FUNC_rc_repeat = 77,
	BPF_FUNC_rc_keydown = 78,
	BPF_FUNC_skb_cgroup_id = 79,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_get_local_storage = 81,
	BPF_FUNC_sk_select_reuseport = 82,
	BPF_FUNC_skb_ancestor_cgroup_id = 83,
	BPF_FUNC_sk_lookup_tcp = 84,
	BPF_FUNC_sk_lookup_udp = 85,
	BPF_FUNC_sk_release = 86,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_msg_push_data = 90,
	BPF_FUNC_msg_pop_data = 91,
	BPF_FUNC_rc_pointer_rel = 92,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_sk_fullsock = 95,
	BPF_FUNC_tcp_sock = 96,
	BPF_FUNC_skb_ecn_set_ce = 97,
	BPF_FUNC_get_listener_sock = 98,
	BPF_FUNC_skc_lookup_tcp = 99,
	BPF_FUNC_tcp_check_syncookie = 100,
	BPF_FUNC_sysctl_get_name = 101,
	BPF_FUNC_sysctl_get_current_value = 102,
	BPF_FUNC_sysctl_get_new_value = 103,
	BPF_FUNC_sysctl_set_new_value = 104,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_sk_storage_get = 107,
	BPF_FUNC_sk_storage_delete = 108,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_tcp_gen_syncookie = 110,
	BPF_FUNC_skb_output = 111,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_tcp_send_ack = 116,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_read_branch_records = 119,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_xdp_output = 121,
	BPF_FUNC_get_netns_cookie = 122,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_sk_assign = 124,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_seq_printf = 126,
	BPF_FUNC_seq_write = 127,
	BPF_FUNC_sk_cgroup_id = 128,
	BPF_FUNC_sk_ancestor_cgroup_id = 129,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_csum_level = 135,
	BPF_FUNC_skc_to_tcp6_sock = 136,
	BPF_FUNC_skc_to_tcp_sock = 137,
	BPF_FUNC_skc_to_tcp_timewait_sock = 138,
	BPF_FUNC_skc_to_tcp_request_sock = 139,
	BPF_FUNC_skc_to_udp6_sock = 140,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_load_hdr_opt = 142,
	BPF_FUNC_store_hdr_opt = 143,
	BPF_FUNC_reserve_hdr_opt = 144,
	BPF_FUNC_inode_storage_get = 145,
	BPF_FUNC_inode_storage_delete = 146,
	BPF_FUNC_d_path = 147,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_seq_printf_btf = 150,
	BPF_FUNC_skb_cgroup_classid = 151,
	BPF_FUNC_redirect_neigh = 152,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_redirect_peer = 155,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_bprm_opts_set = 159,
	BPF_FUNC_ktime_get_coarse_ns = 160,
	BPF_FUNC_ima_inode_hash = 161,
	BPF_FUNC_sock_from_file = 162,
	BPF_FUNC_check_mtu = 163,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_sys_bpf = 166,
	BPF_FUNC_btf_find_by_name_kind = 167,
	BPF_FUNC_sys_close = 168,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_get_func_ip = 173,
	BPF_FUNC_get_attach_cookie = 174,
	BPF_FUNC_task_pt_regs = 175,
	BPF_FUNC_get_branch_snapshot = 176,
	BPF_FUNC_trace_vprintk = 177,
	BPF_FUNC_skc_to_unix_sock = 178,
	BPF_FUNC_kallsyms_lookup_name = 179,
	BPF_FUNC_find_vma = 180,
	BPF_FUNC_loop = 181,
	BPF_FUNC_strncmp = 182,
	BPF_FUNC_get_func_arg = 183,
	BPF_FUNC_get_func_ret = 184,
	BPF_FUNC_get_func_arg_cnt = 185,
	BPF_FUNC_get_retval = 186,
	BPF_FUNC_set_retval = 187,
	BPF_FUNC_xdp_get_buff_len = 188,
	BPF_FUNC_xdp_load_bytes = 189,
	BPF_FUNC_xdp_store_bytes = 190,
	BPF_FUNC_copy_from_user_task = 191,
	BPF_FUNC_skb_set_tstamp = 192,
	BPF_FUNC_ima_file_hash = 193,
	BPF_FUNC_kptr_xchg = 194,
	BPF_FUNC_map_lookup_percpu_elem = 195,
	BPF_FUNC_skc_to_mptcp_sock = 196,
	BPF_FUNC_dynptr_from_mem = 197,
	BPF_FUNC_ringbuf_reserve_dynptr = 198,
	BPF_FUNC_ringbuf_submit_dynptr = 199,
	BPF_FUNC_ringbuf_discard_dynptr = 200,
	BPF_FUNC_dynptr_read = 201,
	BPF_FUNC_dynptr_write = 202,
	BPF_FUNC_dynptr_data = 203,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204,
	BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205,
	BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206,
	BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207,
	BPF_FUNC_ktime_get_tai_ns = 208,
	BPF_FUNC_user_ringbuf_drain = 209,
	BPF_FUNC_cgrp_storage_get = 210,
	BPF_FUNC_cgrp_storage_delete = 211,
	__BPF_FUNC_MAX_ID = 212,
};

struct bpf_link_info {
	__u32 type;
	__u32 id;
	__u32 prog_id;
	union {
		struct {
			__u64 tp_name;
			__u32 tp_name_len;
		} raw_tracepoint;
		struct {
			__u32 attach_type;
			__u32 target_obj_id;
			__u32 target_btf_id;
		} tracing;
		struct {
			__u64 cgroup_id;
			__u32 attach_type;
		} cgroup;
		struct {
			__u64 target_name;
			__u32 target_name_len;
			union {
				struct {
					__u32 map_id;
				} map;
			};
			union {
				struct {
					__u64 cgroup_id;
					__u32 order;
				} cgroup;
				struct {
					__u32 tid;
					__u32 pid;
				} task;
			};
		} iter;
		struct {
			__u32 netns_ino;
			__u32 attach_type;
		} netns;
		struct {
			__u32 ifindex;
		} xdp;
		struct {
			__u32 map_id;
		} struct_ops;
		struct {
			__u32 pf;
			__u32 hooknum;
			__s32 priority;
			__u32 flags;
		} netfilter;
	};
};

enum {
	__PERCPU_REF_ATOMIC = 1,
	__PERCPU_REF_DEAD = 2,
	__PERCPU_REF_ATOMIC_DEAD = 3,
	__PERCPU_REF_FLAG_BITS = 2,
};

typedef sockptr_t bpfptr_t;

struct btf_struct_meta {
	u32 btf_id;
	struct btf_record *record;
};

struct bpf_verifier_log {
	u64 start_pos;
	u64 end_pos;
	char *ubuf;
	u32 level;
	u32 len_total;
	u32 len_max;
	char kbuf[1024];
};

struct bpf_subprog_info {
	u32 start;
	u32 linfo_idx;
	u16 stack_depth;
	bool has_tail_call;
	bool tail_call_reachable;
	bool has_ld_abs;
	bool is_async_cb;
};

struct bpf_id_pair {
	u32 old;
	u32 cur;
};

struct bpf_verifier_ops;

struct bpf_verifier_stack_elem;

struct bpf_verifier_state;

struct bpf_verifier_state_list;

struct bpf_insn_aux_data;

struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;
	const struct bpf_verifier_ops *ops;
	struct bpf_verifier_stack_elem *head;
	int stack_size;
	bool strict_alignment;
	bool test_state_freq;
	struct bpf_verifier_state *cur_state;
	struct bpf_verifier_state_list **explored_states;
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[64];
	struct btf_mod_pair used_btfs[64];
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 id_gen;
	bool explore_alu_limits;
	bool allow_ptr_leaks;
	bool allow_uninit_stack;
	bool bpf_capable;
	bool bypass_spec_v1;
	bool bypass_spec_v4;
	bool seen_direct_write;
	struct bpf_insn_aux_data *insn_aux_data;
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[257];
	struct bpf_id_pair idmap_scratch[600];
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	u32 pass_cnt;
	u32 subprog_cnt;
	u32 prev_insn_processed;
	u32 insn_processed;
	u32 prev_jmps_processed;
	u32 jmps_processed;
	u64 verification_time;
	u32 max_states_per_insn;
	u32 total_states;
	u32 peak_states;
	u32 longest_mark_read_walk;
	bpfptr_t fd_array;
	u32 scratched_regs;
	u64 scratched_stack_slots;
	u64 prev_log_pos;
	u64 prev_insn_print_pos;
	char type_str_buf[128];
};

enum bpf_dynptr_type {
	BPF_DYNPTR_TYPE_INVALID = 0,
	BPF_DYNPTR_TYPE_LOCAL = 1,
	BPF_DYNPTR_TYPE_RINGBUF = 2,
	BPF_DYNPTR_TYPE_SKB = 3,
	BPF_DYNPTR_TYPE_XDP = 4,
};

enum bpf_iter_state {
	BPF_ITER_STATE_INVALID = 0,
	BPF_ITER_STATE_ACTIVE = 1,
	BPF_ITER_STATE_DRAINED = 2,
};

struct tnum {
	u64 value;
	u64 mask;
};

enum bpf_reg_liveness {
	REG_LIVE_NONE = 0,
	REG_LIVE_READ32 = 1,
	REG_LIVE_READ64 = 2,
	REG_LIVE_READ = 3,
	REG_LIVE_WRITTEN = 4,
	REG_LIVE_DONE = 8,
};

struct bpf_reg_state {
	enum bpf_reg_type type;
	s32 off;
	union {
		int range;
		struct {
			struct bpf_map *map_ptr;
			u32 map_uid;
		};
		struct {
			struct btf *btf;
			u32 btf_id;
		};
		struct {
			u32 mem_size;
			u32 dynptr_id;
		};
		struct {
			enum bpf_dynptr_type type;
			bool first_slot;
		} dynptr;
		struct {
			struct btf *btf;
			u32 btf_id;
			enum bpf_iter_state state: 2;
			int depth: 30;
		} iter;
		struct {
			long unsigned int raw1;
			long unsigned int raw2;
		} raw;
		u32 subprogno;
	};
	struct tnum var_off;
	s64 smin_value;
	s64 smax_value;
	u64 umin_value;
	u64 umax_value;
	s32 s32_min_value;
	s32 s32_max_value;
	u32 u32_min_value;
	u32 u32_max_value;
	u32 id;
	u32 ref_obj_id;
	struct bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
};

struct bpf_reference_state;

struct bpf_stack_state;

struct bpf_func_state {
	struct bpf_reg_state regs[11];
	int callsite;
	u32 frameno;
	u32 subprogno;
	u32 async_entry_cnt;
	bool in_callback_fn;
	struct tnum callback_ret_range;
	bool in_async_callback_fn;
	int acquired_refs;
	struct bpf_reference_state *refs;
	int allocated_stack;
	struct bpf_stack_state *stack;
};

enum bpf_arg_type {
	ARG_DONTCARE = 0,
	ARG_CONST_MAP_PTR = 1,
	ARG_PTR_TO_MAP_KEY = 2,
	ARG_PTR_TO_MAP_VALUE = 3,
	ARG_PTR_TO_MEM = 4,
	ARG_CONST_SIZE = 5,
	ARG_CONST_SIZE_OR_ZERO = 6,
	ARG_PTR_TO_CTX = 7,
	ARG_ANYTHING = 8,
	ARG_PTR_TO_SPIN_LOCK = 9,
	ARG_PTR_TO_SOCK_COMMON = 10,
	ARG_PTR_TO_INT = 11,
	ARG_PTR_TO_LONG = 12,
	ARG_PTR_TO_SOCKET = 13,
	ARG_PTR_TO_BTF_ID = 14,
	ARG_PTR_TO_RINGBUF_MEM = 15,
	ARG_CONST_ALLOC_SIZE_OR_ZERO = 16,
	ARG_PTR_TO_BTF_ID_SOCK_COMMON = 17,
	ARG_PTR_TO_PERCPU_BTF_ID = 18,
	ARG_PTR_TO_FUNC = 19,
	ARG_PTR_TO_STACK = 20,
	ARG_PTR_TO_CONST_STR = 21,
	ARG_PTR_TO_TIMER = 22,
	ARG_PTR_TO_KPTR = 23,
	ARG_PTR_TO_DYNPTR = 24,
	__BPF_ARG_TYPE_MAX = 25,
	ARG_PTR_TO_MAP_VALUE_OR_NULL = 259,
	ARG_PTR_TO_MEM_OR_NULL = 260,
	ARG_PTR_TO_CTX_OR_NULL = 263,
	ARG_PTR_TO_SOCKET_OR_NULL = 269,
	ARG_PTR_TO_STACK_OR_NULL = 276,
	ARG_PTR_TO_BTF_ID_OR_NULL = 270,
	ARG_PTR_TO_UNINIT_MEM = 32772,
	ARG_PTR_TO_FIXED_SIZE_MEM = 262148,
	__BPF_ARG_TYPE_LIMIT = 33554431,
};

enum bpf_return_type {
	RET_INTEGER = 0,
	RET_VOID = 1,
	RET_PTR_TO_MAP_VALUE = 2,
	RET_PTR_TO_SOCKET = 3,
	RET_PTR_TO_TCP_SOCK = 4,
	RET_PTR_TO_SOCK_COMMON = 5,
	RET_PTR_TO_MEM = 6,
	RET_PTR_TO_MEM_OR_BTF_ID = 7,
	RET_PTR_TO_BTF_ID = 8,
	__BPF_RET_TYPE_MAX = 9,
	RET_PTR_TO_MAP_VALUE_OR_NULL = 258,
	RET_PTR_TO_SOCKET_OR_NULL = 259,
	RET_PTR_TO_TCP_SOCK_OR_NULL = 260,
	RET_PTR_TO_SOCK_COMMON_OR_NULL = 261,
	RET_PTR_TO_RINGBUF_MEM_OR_NULL = 1286,
	RET_PTR_TO_DYNPTR_MEM_OR_NULL = 262,
	RET_PTR_TO_BTF_ID_OR_NULL = 264,
	RET_PTR_TO_BTF_ID_TRUSTED = 1048584,
	__BPF_RET_TYPE_LIMIT = 33554431,
};

struct bpf_func_proto {
	u64 (*func)(u64, u64, u64, u64, u64);
	bool gpl_only;
	bool pkt_access;
	bool might_sleep;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
		struct {
			size_t arg1_size;
			size_t arg2_size;
			size_t arg3_size;
			size_t arg4_size;
			size_t arg5_size;
		};
		size_t arg_size[5];
	};
	int *ret_btf_id;
	bool (*allowed)(const struct bpf_prog *);
};

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2,
};

struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	union {
		int ctx_field_size;
		struct {
			struct btf *btf;
			u32 btf_id;
		};
	};
	struct bpf_verifier_log *log;
};

struct bpf_verifier_ops {
	const struct bpf_func_proto * (*get_func_proto)(enum bpf_func_id, const struct bpf_prog *);
	bool (*is_valid_access)(int, int, enum bpf_access_type, const struct bpf_prog *, struct bpf_insn_access_aux *);
	int (*gen_prologue)(struct bpf_insn *, bool, const struct bpf_prog *);
	int (*gen_ld_abs)(const struct bpf_insn *, struct bpf_insn *);
	u32 (*convert_ctx_access)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);
	int (*btf_struct_access)(struct bpf_verifier_log *, const struct bpf_reg_state *, int, int);
};

enum {
	BPF_MAX_TRAMP_LINKS = 38,
};

struct bpf_tramp_link;

struct bpf_tramp_links {
	struct bpf_tramp_link *links[38];
	int nr_links;
};

struct bpf_link_ops;

struct bpf_link {
	atomic64_t refcnt;
	u32 id;
	enum bpf_link_type type;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	struct work_struct work;
};

struct bpf_tramp_link {
	struct bpf_link link;
	struct hlist_node tramp_hlist;
	u64 cookie;
};

struct bpf_tramp_run_ctx;

typedef u64 (*bpf_trampoline_enter_t)(struct bpf_prog *, struct bpf_tramp_run_ctx *);

struct bpf_tramp_run_ctx {
	struct bpf_run_ctx run_ctx;
	u64 bpf_cookie;
	struct bpf_run_ctx *saved_run_ctx;
};

typedef void (*bpf_trampoline_exit_t)(struct bpf_prog *, u64, struct bpf_tramp_run_ctx *);

enum bpf_tramp_prog_type {
	BPF_TRAMP_FENTRY = 0,
	BPF_TRAMP_FEXIT = 1,
	BPF_TRAMP_MODIFY_RETURN = 2,
	BPF_TRAMP_MAX = 3,
	BPF_TRAMP_REPLACE = 4,
};

struct bpf_attach_target_info {
	struct btf_func_model fmodel;
	long int tgt_addr;
	struct module *tgt_mod;
	const char *tgt_name;
	const struct btf_type *tgt_type;
};

struct bpf_link_ops {
	void (*release)(struct bpf_link *);
	void (*dealloc)(struct bpf_link *);
	int (*detach)(struct bpf_link *);
	int (*update_prog)(struct bpf_link *, struct bpf_prog *, struct bpf_prog *);
	void (*show_fdinfo)(const struct bpf_link *, struct seq_file *);
	int (*fill_link_info)(const struct bpf_link *, struct bpf_link_info *);
	int (*update_map)(struct bpf_link *, struct bpf_map *, struct bpf_map *);
};

enum bpf_text_poke_type {
	BPF_MOD_CALL = 0,
	BPF_MOD_JUMP = 1,
};

enum perf_record_ksymbol_type {
	PERF_RECORD_KSYMBOL_TYPE_UNKNOWN = 0,
	PERF_RECORD_KSYMBOL_TYPE_BPF = 1,
	PERF_RECORD_KSYMBOL_TYPE_OOL = 2,
	PERF_RECORD_KSYMBOL_TYPE_MAX = 3,
};

struct bpf_active_lock {
	void *ptr;
	u32 id;
};

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[8];
};

struct bpf_reference_state {
	int id;
	int insn_idx;
	int callback_ref;
};

struct bpf_idx_pair {
	u32 prev_idx;
	u32 idx;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[8];
	struct bpf_verifier_state *parent;
	u32 branches;
	u32 insn_idx;
	u32 curframe;
	struct bpf_active_lock active_lock;
	bool speculative;
	bool active_rcu_lock;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_idx_pair *jmp_history;
	u32 jmp_history_cnt;
};

struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
	int miss_cnt;
	int hit_cnt;
};

struct bpf_loop_inline_state {
	unsigned int initialized: 1;
	unsigned int fit_for_inline: 1;
	u32 callback_subprogno;
};

struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;
		long unsigned int map_ptr_state;
		s32 call_imm;
		u32 alu_limit;
		struct {
			u32 map_index;
			u32 map_off;
		};
		struct {
			enum bpf_reg_type reg_type;
			union {
				struct {
					struct btf *btf;
					u32 btf_id;
				};
				u32 mem_size;
			};
		} btf_var;
		struct bpf_loop_inline_state loop_inline_state;
	};
	union {
		u64 obj_new_size;
		u64 insert_off;
	};
	struct btf_struct_meta *kptr_struct_meta;
	u64 map_key_state;
	int ctx_field_size;
	u32 seen;
	bool sanitize_stack_spill;
	bool zext_dst;
	bool storage_get_func_atomic;
	bool is_iter_next;
	u8 alu_state;
	unsigned int orig_idx;
	bool jmp_point;
	bool prune_point;
	bool force_checkpoint;
};

enum ctx_state {
	CONTEXT_DISABLED = -1,
	CONTEXT_KERNEL = 0,
	CONTEXT_IDLE = 1,
	CONTEXT_USER = 2,
	CONTEXT_GUEST = 3,
	CONTEXT_MAX = 4,
};

struct context_tracking {
	atomic_t state;
	long int dynticks_nesting;
	long int dynticks_nmi_nesting;
};

struct cacheline_padding {
	char x[0];
};

struct free_area {
	struct list_head free_list[4];
	long unsigned int nr_free;
};

struct lruvec {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
};

struct per_cpu_pages {
	spinlock_t lock;
	int count;
	int high;
	int batch;
	short int free_factor;
	struct list_head lists[12];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct per_cpu_zonestat {
	s8 vm_stat_diff[10];
	s8 stat_threshold;
};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[40];
};

enum zone_type {
	ZONE_DMA = 0,
	ZONE_DMA32 = 1,
	ZONE_NORMAL = 2,
	ZONE_MOVABLE = 3,
	__MAX_NR_ZONES = 4,
};

struct pglist_data;

struct zone {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[4];
	struct pglist_data *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	const char *name;
	int initialized;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad1_;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	long unsigned int percpu_drift_mark;
	bool contiguous;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad3_;
	atomic_long_t vm_stat[10];
	atomic_long_t vm_numa_event[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct zoneref {
	struct zone *zone;
	int zone_idx;
};

struct zonelist {
	struct zoneref _zonerefs[5];
};

struct pglist_data {
	struct zone node_zones[4];
	struct zonelist node_zonelists[1];
	int nr_zones;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct task_struct *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	long unsigned int totalreserve_pages;
	long: 64;
	struct cacheline_padding _pad1_;
	struct lruvec __lruvec;
	long unsigned int flags;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cacheline_padding _pad2_;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[40];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef struct pglist_data pg_data_t;

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct blk_plug {};

typedef unsigned int xa_mark_t;

enum {
	XA_CHECK_SCHED = 4096,
};

struct request;

struct elevator_queue;

struct blk_queue_stats;

struct rq_qos;

struct blk_mq_ops;

struct blk_mq_ctx;

struct blk_mq_tags;

enum blk_bounce {
	BLK_BOUNCE_NONE = 0,
	BLK_BOUNCE_HIGH = 1,
};

enum blk_zoned_model {
	BLK_ZONED_NONE = 0,
	BLK_ZONED_HA = 1,
	BLK_ZONED_HM = 2,
};

struct queue_limits {
	enum blk_bounce bounce;
	long unsigned int seg_boundary_mask;
	long unsigned int virt_boundary_mask;
	unsigned int max_hw_sectors;
	unsigned int max_dev_sectors;
	unsigned int chunk_sectors;
	unsigned int max_sectors;
	unsigned int max_user_sectors;
	unsigned int max_segment_size;
	unsigned int physical_block_size;
	unsigned int logical_block_size;
	unsigned int alignment_offset;
	unsigned int io_min;
	unsigned int io_opt;
	unsigned int max_discard_sectors;
	unsigned int max_hw_discard_sectors;
	unsigned int max_secure_erase_sectors;
	unsigned int max_write_zeroes_sectors;
	unsigned int max_zone_append_sectors;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int zone_write_granularity;
	short unsigned int max_segments;
	short unsigned int max_integrity_segments;
	short unsigned int max_discard_segments;
	unsigned char misaligned;
	unsigned char discard_misaligned;
	unsigned char raid_partial_stripes_expensive;
	enum blk_zoned_model zoned;
	unsigned int dma_alignment;
};

struct blk_flush_queue;

struct blk_mq_tag_set;

struct request_queue {
	struct request *last_merge;
	struct elevator_queue *elevator;
	struct percpu_ref q_usage_counter;
	struct blk_queue_stats *stats;
	struct rq_qos *rq_qos;
	struct mutex rq_qos_mutex;
	const struct blk_mq_ops *mq_ops;
	struct blk_mq_ctx *queue_ctx;
	unsigned int queue_depth;
	struct xarray hctx_table;
	unsigned int nr_hw_queues;
	void *queuedata;
	long unsigned int queue_flags;
	atomic_t pm_only;
	int id;
	spinlock_t queue_lock;
	struct gendisk *disk;
	refcount_t refs;
	struct kobject *mq_kobj;
	long unsigned int nr_requests;
	unsigned int dma_pad_mask;
	unsigned int rq_timeout;
	struct timer_list timeout;
	struct work_struct timeout_work;
	atomic_t nr_active_requests_shared_tags;
	struct blk_mq_tags *sched_shared_tags;
	struct list_head icq_list;
	struct queue_limits limits;
	unsigned int required_elevator_features;
	int node;
	struct blk_flush_queue *fq;
	struct list_head flush_list;
	struct list_head requeue_list;
	spinlock_t requeue_lock;
	struct delayed_work requeue_work;
	struct mutex sysfs_lock;
	struct mutex sysfs_dir_lock;
	struct list_head unused_hctx_list;
	spinlock_t unused_hctx_lock;
	int mq_freeze_depth;
	struct callback_head callback_head;
	wait_queue_head_t mq_freeze_wq;
	struct mutex mq_freeze_lock;
	int quiesce_depth;
	struct blk_mq_tag_set *tag_set;
	struct list_head tag_set_list;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct dentry *rqos_debugfs_dir;
	struct mutex debugfs_mutex;
	bool mq_sysfs_init_done;
};

enum positive_aop_returns {
	AOP_WRITEPAGE_ACTIVATE = 524288,
	AOP_TRUNCATED_PAGE = 524289,
};

struct io_comp_batch {
	struct request *req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

struct fprop_global {
	struct percpu_counter events;
	unsigned int period;
	seqcount_t sequence;
};

enum wb_state {
	WB_registered = 0,
	WB_writeback_running = 1,
	WB_has_dirty_io = 2,
	WB_start_all = 3,
};

struct wb_lock_cookie {
	bool locked;
	long unsigned int flags;
};

struct bvec_iter {
	sector_t bi_sector;
	unsigned int bi_size;
	unsigned int bi_idx;
	unsigned int bi_bvec_done;
} __attribute__((packed));

typedef void bio_end_io_t(struct bio *);

typedef u8 blk_status_t;

typedef unsigned int blk_qc_t;

struct bio_set;

struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	blk_opf_t bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t *bi_end_io;
	void *bi_private;
	union {};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec bi_inline_vecs[0];
};

struct bio_alloc_cache;

typedef void *mempool_alloc_t(gfp_t, void *);

typedef void mempool_free_t(void *, void *);

struct mempool_s {
	spinlock_t lock;
	int min_nr;
	int curr_nr;
	void **elements;
	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
};

typedef struct mempool_s mempool_t;

struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;
	struct bio_alloc_cache *cache;
	mempool_t bio_pool;
	mempool_t bvec_pool;
	unsigned int back_pad;
	spinlock_t rescue_lock;
	struct bio_list rescue_list;
	struct work_struct rescue_work;
	struct workqueue_struct *rescue_workqueue;
	struct hlist_node cpuhp_dead;
};

struct disk_events;

struct badblocks;

typedef unsigned int blk_mode_t;

struct block_device_operations;

struct timer_rand_state;

struct blk_independent_access_ranges;

struct gendisk {
	int major;
	int first_minor;
	int minors;
	char disk_name[32];
	short unsigned int events;
	short unsigned int event_flags;
	struct xarray part_tbl;
	struct block_device *part0;
	const struct block_device_operations *fops;
	struct request_queue *queue;
	void *private_data;
	struct bio_set bio_split;
	int flags;
	long unsigned int state;
	struct mutex open_mutex;
	unsigned int open_partitions;
	struct backing_dev_info *bdi;
	struct kobject queue_kobj;
	struct kobject *slave_dir;
	struct timer_rand_state *random;
	atomic_t sync_io;
	struct disk_events *ev;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
	blk_mode_t open_mode;
	struct blk_independent_access_ranges *ia_ranges;
};

struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};

struct wb_domain {
	spinlock_t lock;
	struct fprop_global completions;
	struct timer_list period_timer;
	long unsigned int period_time;
	long unsigned int dirty_limit_tstamp;
	long unsigned int dirty_limit;
};

typedef int (*writepage_t)(struct folio *, struct writeback_control *, void *);

enum mapping_flags {
	AS_EIO = 0,
	AS_ENOSPC = 1,
	AS_MM_ALL_LOCKS = 2,
	AS_UNEVICTABLE = 3,
	AS_EXITING = 4,
	AS_NO_WRITEBACK_TAGS = 5,
	AS_LARGE_FOLIO_SUPPORT = 6,
};

struct blk_zone {
	__u64 start;
	__u64 len;
	__u64 wp;
	__u8 type;
	__u8 cond;
	__u8 non_seq;
	__u8 reset;
	__u8 resv[4];
	__u64 capacity;
	__u8 reserved[24];
};

struct hd_geometry;

typedef int (*report_zones_cb)(struct blk_zone *, unsigned int, void *);

enum blk_unique_id {
	BLK_UID_T10 = 1,
	BLK_UID_EUI64 = 2,
	BLK_UID_NAA = 3,
};

struct pr_ops;

struct block_device_operations {
	void (*submit_bio)(struct bio *);
	int (*poll_bio)(struct bio *, struct io_comp_batch *, unsigned int);
	int (*open)(struct gendisk *, blk_mode_t);
	void (*release)(struct gendisk *);
	int (*ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct block_device *, blk_mode_t, unsigned int, long unsigned int);
	unsigned int (*check_events)(struct gendisk *, unsigned int);
	void (*unlock_native_capacity)(struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *, bool);
	void (*free_disk)(struct gendisk *);
	void (*swap_slot_free_notify)(struct block_device *, long unsigned int);
	int (*report_zones)(struct gendisk *, sector_t, unsigned int, report_zones_cb, void *);
	char * (*devnode)(struct gendisk *, umode_t *);
	int (*get_unique_id)(struct gendisk *, u8 *, enum blk_unique_id);
	struct module *owner;
	const struct pr_ops *pr_ops;
	int (*alternative_gpt_sector)(struct gendisk *, sector_t *);
};

struct blk_independent_access_range {
	struct kobject kobj;
	sector_t sector;
	sector_t nr_sectors;
};

struct blk_independent_access_ranges {
	struct kobject kobj;
	bool sysfs_registered;
	unsigned int nr_ia_ranges;
	struct blk_independent_access_range ia_range[0];
};

struct pagevec {
	unsigned char nr;
	bool percpu_pvec_drained;
	struct page *pages[15];
};

struct folio_batch {
	unsigned char nr;
	bool percpu_pvec_drained;
	struct folio *folios[15];
};

struct dirty_throttle_control {
	struct bdi_writeback *wb;
	struct fprop_local_percpu *wb_completions;
	long unsigned int avail;
	long unsigned int dirty;
	long unsigned int thresh;
	long unsigned int bg_thresh;
	long unsigned int wb_dirty;
	long unsigned int wb_thresh;
	long unsigned int wb_bg_thresh;
	long unsigned int pos_ratio;
};

enum system_states {
	SYSTEM_BOOTING = 0,
	SYSTEM_SCHEDULING = 1,
	SYSTEM_FREEING_INITMEM = 2,
	SYSTEM_RUNNING = 3,
	SYSTEM_HALT = 4,
	SYSTEM_POWER_OFF = 5,
	SYSTEM_RESTART = 6,
	SYSTEM_SUSPEND = 7,
};

enum {
	WQ_UNBOUND = 2,
	WQ_FREEZABLE = 4,
	WQ_MEM_RECLAIM = 8,
	WQ_HIGHPRI = 16,
	WQ_CPU_INTENSIVE = 32,
	WQ_SYSFS = 64,
	WQ_POWER_EFFICIENT = 128,
	__WQ_DESTROYING = 32768,
	__WQ_DRAINING = 65536,
	__WQ_ORDERED = 131072,
	__WQ_LEGACY = 262144,
	__WQ_ORDERED_EXPLICIT = 524288,
	WQ_MAX_ACTIVE = 512,
	WQ_MAX_UNBOUND_PER_CPU = 4,
	WQ_DFL_ACTIVE = 256,
};

enum {
	DUMP_PREFIX_NONE = 0,
	DUMP_PREFIX_ADDRESS = 1,
	DUMP_PREFIX_OFFSET = 2,
};

struct trace_print_flags {
	long unsigned int mask;
	const char *name;
};

enum migrate_reason {
	MR_COMPACTION = 0,
	MR_MEMORY_FAILURE = 1,
	MR_MEMORY_HOTPLUG = 2,
	MR_SYSCALL = 3,
	MR_MEMPOLICY_MBIND = 4,
	MR_NUMA_MISPLACED = 5,
	MR_CONTIG_RANGE = 6,
	MR_LONGTERM_PIN = 7,
	MR_DEMOTION = 8,
	MR_TYPES = 9,
};

typedef u64 pudval_t;

struct maple_alloc {
	long unsigned int total;
	unsigned char node_count;
	unsigned int request_count;
	struct maple_alloc *slot[30];
};

struct maple_enode;

struct ma_state {
	struct maple_tree *tree;
	long unsigned int index;
	long unsigned int last;
	struct maple_enode *node;
	long unsigned int min;
	long unsigned int max;
	struct maple_alloc *alloc;
	unsigned char depth;
	unsigned char offset;
	unsigned char mas_flags;
};

struct anon_vma_name {
	struct kref kref;
	char name[0];
};

struct vma_iterator {
	struct ma_state mas;
};

struct encoded_page;

struct mm_walk;

struct mm_walk_ops {
	int (*pgd_entry)(pgd_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*p4d_entry)(p4d_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pud_entry)(pud_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pmd_entry)(pmd_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pte_entry)(pte_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pte_hole)(long unsigned int, long unsigned int, int, struct mm_walk *);
	int (*hugetlb_entry)(pte_t *, long unsigned int, long unsigned int, long unsigned int, struct mm_walk *);
	int (*test_walk)(long unsigned int, long unsigned int, struct mm_walk *);
	int (*pre_vma)(long unsigned int, long unsigned int, struct mm_walk *);
	void (*post_vma)(struct mm_walk *);
};

enum page_walk_action {
	ACTION_SUBTREE = 0,
	ACTION_CONTINUE = 1,
	ACTION_AGAIN = 2,
};

struct mm_walk {
	const struct mm_walk_ops *ops;
	struct mm_struct *mm;
	pgd_t *pgd;
	struct vm_area_struct *vma;
	enum page_walk_action action;
	bool no_vma;
	void *private;
};

struct mempolicy {};

typedef long unsigned int pte_marker;

struct mmu_notifier_range {
	long unsigned int start;
	long unsigned int end;
};

struct mmu_table_batch {
	struct callback_head rcu;
	unsigned int nr;
	void *tables[0];
};

struct mmu_gather_batch {
	struct mmu_gather_batch *next;
	unsigned int nr;
	unsigned int max;
	struct encoded_page *encoded_pages[0];
};

struct mmu_gather {
	struct mm_struct *mm;
	struct mmu_table_batch *batch;
	long unsigned int start;
	long unsigned int end;
	unsigned int fullmm: 1;
	unsigned int need_flush_all: 1;
	unsigned int freed_tables: 1;
	unsigned int delayed_rmap: 1;
	unsigned int cleared_ptes: 1;
	unsigned int cleared_pmds: 1;
	unsigned int cleared_puds: 1;
	unsigned int cleared_p4ds: 1;
	unsigned int vma_exec: 1;
	unsigned int vma_huge: 1;
	unsigned int vma_pfn: 1;
	unsigned int batch_count;
	struct mmu_gather_batch *active;
	struct mmu_gather_batch local;
	struct page *__pages[8];
};

enum pageblock_bits {
	PB_migrate = 0,
	PB_migrate_end = 2,
	PB_migrate_skip = 3,
	NR_PAGEBLOCK_BITS = 4,
};

struct mem_section_usage {
	long unsigned int subsection_map[1];
	long unsigned int pageblock_flags[0];
};

struct mem_section {
	long unsigned int section_mem_map;
	struct mem_section_usage *usage;
};

enum {
	SECTION_MARKED_PRESENT_BIT = 0,
	SECTION_HAS_MEM_MAP_BIT = 1,
	SECTION_IS_ONLINE_BIT = 2,
	SECTION_IS_EARLY_BIT = 3,
	SECTION_MAP_LAST_BIT = 4,
};

enum mminit_level {
	MMINIT_WARNING = 0,
	MMINIT_VERIFY = 1,
	MMINIT_TRACE = 2,
};

typedef __kernel_ulong_t ino_t;

struct wait_bit_key {
	void *flags;
	int bit_nr;
	long unsigned int timeout;
};

struct wait_bit_queue_entry {
	struct wait_bit_key key;
	struct wait_queue_entry wq_entry;
};

typedef int wait_bit_action_f(struct wait_bit_key *, int);

struct wb_completion {
	atomic_t cnt;
	wait_queue_head_t *waitq;
};

struct wb_writeback_work {
	long int nr_pages;
	struct super_block *sb;
	enum writeback_sync_modes sync_mode;
	unsigned int tagged_writepages: 1;
	unsigned int for_kupdate: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_background: 1;
	unsigned int for_sync: 1;
	unsigned int auto_free: 1;
	enum wb_reason reason;
	struct list_head list;
	struct wb_completion *done;
};

struct trace_event_raw_writeback_folio_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int index;
	char __data[0];
};

struct trace_event_raw_writeback_dirty_inode_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int state;
	long unsigned int flags;
	char __data[0];
};

struct trace_event_raw_writeback_write_inode_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	int sync_mode;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_work_class {
	struct trace_entry ent;
	char name[32];
	long int nr_pages;
	dev_t sb_dev;
	int sync_mode;
	int for_kupdate;
	int range_cyclic;
	int for_background;
	int reason;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_pages_written {
	struct trace_entry ent;
	long int pages;
	char __data[0];
};

struct trace_event_raw_writeback_class {
	struct trace_entry ent;
	char name[32];
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_bdi_register {
	struct trace_entry ent;
	char name[32];
	char __data[0];
};

struct trace_event_raw_wbc_class {
	struct trace_entry ent;
	char name[32];
	long int nr_to_write;
	long int pages_skipped;
	int sync_mode;
	int for_kupdate;
	int for_background;
	int for_reclaim;
	int range_cyclic;
	long int range_start;
	long int range_end;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_queue_io {
	struct trace_entry ent;
	char name[32];
	long unsigned int older;
	long int age;
	int moved;
	int reason;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_global_dirty_state {
	struct trace_entry ent;
	long unsigned int nr_dirty;
	long unsigned int nr_writeback;
	long unsigned int background_thresh;
	long unsigned int dirty_thresh;
	long unsigned int dirty_limit;
	long unsigned int nr_dirtied;
	long unsigned int nr_written;
	char __data[0];
};

struct trace_event_raw_bdi_dirty_ratelimit {
	struct trace_entry ent;
	char bdi[32];
	long unsigned int write_bw;
	long unsigned int avg_write_bw;
	long unsigned int dirty_rate;
	long unsigned int dirty_ratelimit;
	long unsigned int task_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_balance_dirty_pages {
	struct trace_entry ent;
	char bdi[32];
	long unsigned int limit;
	long unsigned int setpoint;
	long unsigned int dirty;
	long unsigned int bdi_setpoint;
	long unsigned int bdi_dirty;
	long unsigned int dirty_ratelimit;
	long unsigned int task_ratelimit;
	unsigned int dirtied;
	unsigned int dirtied_pause;
	long unsigned int paused;
	long int pause;
	long unsigned int period;
	long int think;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_sb_inodes_requeue {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int state;
	long unsigned int dirtied_when;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_single_inode_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int state;
	long unsigned int dirtied_when;
	long unsigned int writeback_index;
	long int nr_to_write;
	long unsigned int wrote;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_inode_template {
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	long unsigned int state;
	__u16 mode;
	long unsigned int dirtied_when;
	char __data[0];
};

struct trace_event_data_offsets_writeback_folio_template {};

struct trace_event_data_offsets_writeback_dirty_inode_template {};

struct trace_event_data_offsets_writeback_write_inode_template {};

struct trace_event_data_offsets_writeback_work_class {};

struct trace_event_data_offsets_writeback_pages_written {};

struct trace_event_data_offsets_writeback_class {};

struct trace_event_data_offsets_writeback_bdi_register {};

struct trace_event_data_offsets_wbc_class {};

struct trace_event_data_offsets_writeback_queue_io {};

struct trace_event_data_offsets_global_dirty_state {};

struct trace_event_data_offsets_bdi_dirty_ratelimit {};

struct trace_event_data_offsets_balance_dirty_pages {};

struct trace_event_data_offsets_writeback_sb_inodes_requeue {};

struct trace_event_data_offsets_writeback_single_inode_template {};

struct trace_event_data_offsets_writeback_inode_template {};

typedef void (*btf_trace_writeback_dirty_folio)(void *, struct folio *, struct address_space *);

typedef void (*btf_trace_folio_wait_writeback)(void *, struct folio *, struct address_space *);

typedef void (*btf_trace_writeback_mark_inode_dirty)(void *, struct inode *, int);

typedef void (*btf_trace_writeback_dirty_inode_start)(void *, struct inode *, int);

typedef void (*btf_trace_writeback_dirty_inode)(void *, struct inode *, int);

typedef void (*btf_trace_writeback_write_inode_start)(void *, struct inode *, struct writeback_control *);

typedef void (*btf_trace_writeback_write_inode)(void *, struct inode *, struct writeback_control *);

typedef void (*btf_trace_writeback_queue)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_exec)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_start)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_written)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_wait)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_pages_written)(void *, long int);

typedef void (*btf_trace_writeback_wake_background)(void *, struct bdi_writeback *);

typedef void (*btf_trace_writeback_bdi_register)(void *, struct backing_dev_info *);

typedef void (*btf_trace_wbc_writepage)(void *, struct writeback_control *, struct backing_dev_info *);

typedef void (*btf_trace_writeback_queue_io)(void *, struct bdi_writeback *, struct wb_writeback_work *, long unsigned int, int);

typedef void (*btf_trace_global_dirty_state)(void *, long unsigned int, long unsigned int);

typedef void (*btf_trace_bdi_dirty_ratelimit)(void *, struct bdi_writeback *, long unsigned int, long unsigned int);

typedef void (*btf_trace_balance_dirty_pages)(void *, struct bdi_writeback *, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long int, long unsigned int);

typedef void (*btf_trace_writeback_sb_inodes_requeue)(void *, struct inode *);

typedef void (*btf_trace_writeback_single_inode_start)(void *, struct inode *, struct writeback_control *, long unsigned int);

typedef void (*btf_trace_writeback_single_inode)(void *, struct inode *, struct writeback_control *, long unsigned int);

typedef void (*btf_trace_writeback_lazytime)(void *, struct inode *);

typedef void (*btf_trace_writeback_lazytime_iput)(void *, struct inode *);

typedef void (*btf_trace_writeback_dirty_inode_enqueue)(void *, struct inode *);

typedef void (*btf_trace_sb_mark_inode_writeback)(void *, struct inode *);

typedef void (*btf_trace_sb_clear_inode_writeback)(void *, struct inode *);

struct name_snapshot {
	struct qstr name;
	unsigned char inline_name[32];
};

struct tree_descr {
	const char *name;
	const struct file_operations *ops;
	int mode;
};

typedef struct vfsmount * (*debugfs_automount_t)(struct dentry *, void *);

enum fsnotify_data_type {
	FSNOTIFY_EVENT_NONE = 0,
	FSNOTIFY_EVENT_PATH = 1,
	FSNOTIFY_EVENT_INODE = 2,
	FSNOTIFY_EVENT_DENTRY = 3,
	FSNOTIFY_EVENT_ERROR = 4,
};

struct match_token {
	int token;
	const char *pattern;
};

enum {
	MAX_OPT_ARGS = 3,
};

typedef struct {
	char *from;
	char *to;
} substring_t;

struct debugfs_fsdata {
	const struct file_operations *real_fops;
	refcount_t active_users;
	struct completion active_users_drained;
};

struct debugfs_mount_opts {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	unsigned int opts;
};

enum {
	Opt_uid = 0,
	Opt_gid = 1,
	Opt_mode = 2,
	Opt_err = 3,
};

struct debugfs_fs_info {
	struct debugfs_mount_opts mount_opts;
};

struct rhash_lock_head;

struct bucket_table {
	unsigned int size;
	unsigned int nest;
	u32 hash_rnd;
	struct list_head walkers;
	struct callback_head rcu;
	struct bucket_table *future_tbl;
	struct lockdep_map dep_map;
	long: 64;
	struct rhash_lock_head *buckets[0];
};

struct rhltable {
	struct rhashtable ht;
};

struct rhashtable_walker {
	struct list_head list;
	struct bucket_table *tbl;
};

struct rhashtable_iter {
	struct rhashtable *ht;
	struct rhash_head *p;
	struct rhlist_head *list;
	struct rhashtable_walker walker;
	unsigned int slot;
	unsigned int skip;
	bool end_of_table;
};

struct __una_u32 {
	u32 x;
};

struct rhash_lock_head {};

union nested_table {
	union nested_table *table;
	struct rhash_lock_head *bucket;
};

enum blake2s_lengths {
	BLAKE2S_BLOCK_SIZE = 64,
	BLAKE2S_HASH_SIZE = 32,
	BLAKE2S_KEY_SIZE = 32,
	BLAKE2S_128_HASH_SIZE = 16,
	BLAKE2S_160_HASH_SIZE = 20,
	BLAKE2S_224_HASH_SIZE = 28,
	BLAKE2S_256_HASH_SIZE = 32,
};

struct blake2s_state {
	u32 h[8];
	u32 t[2];
	u32 f[2];
	u8 buf[64];
	unsigned int buflen;
	unsigned int outlen;
};

enum blake2s_iv {
	BLAKE2S_IV0 = 1779033703,
	BLAKE2S_IV1 = 3144134277,
	BLAKE2S_IV2 = 1013904242,
	BLAKE2S_IV3 = 2773480762,
	BLAKE2S_IV4 = 1359893119,
	BLAKE2S_IV5 = 2600822924,
	BLAKE2S_IV6 = 528734635,
	BLAKE2S_IV7 = 1541459225,
};

enum {
	TEST_ALIGNMENT = 16,
};

typedef __u16 __sum16;

struct word_at_a_time {
	const long unsigned int one_bits;
	const long unsigned int high_bits;
};

enum {
	IRQCHIP_FWNODE_REAL = 0,
	IRQCHIP_FWNODE_NAMED = 1,
	IRQCHIP_FWNODE_NAMED_ID = 2,
};

struct its_vpe;

struct its_vm {
	struct fwnode_handle *fwnode;
	struct irq_domain *domain;
	struct page *vprop_page;
	struct its_vpe **vpes;
	int nr_vpes;
	irq_hw_number_t db_lpi_base;
	long unsigned int *db_bitmap;
	int nr_db_lpis;
	u32 vlpi_count[16];
};

struct its_vpe {
	struct page *vpt_page;
	struct its_vm *its_vm;
	atomic_t vlpi_count;
	int irq;
	irq_hw_number_t vpe_db_lpi;
	bool resident;
	bool ready;
	union {
		struct {
			int vpe_proxy_event;
			bool idai;
		};
		struct {
			struct fwnode_handle *fwnode;
			struct irq_domain *sgi_domain;
			struct {
				u8 priority;
				bool enabled;
				bool group;
			} sgi_config[16];
			atomic_t vmapp_count;
		};
	};
	raw_spinlock_t vpe_lock;
	u16 col_idx;
	u16 vpe_id;
	bool pending_last;
};

struct its_vlpi_map {
	struct its_vm *vm;
	struct its_vpe *vpe;
	u32 vintid;
	u8 properties;
	bool db_enabled;
};

enum its_vcpu_info_cmd_type {
	MAP_VLPI = 0,
	GET_VLPI = 1,
	PROP_UPDATE_VLPI = 2,
	PROP_UPDATE_AND_INV_VLPI = 3,
	SCHEDULE_VPE = 4,
	DESCHEDULE_VPE = 5,
	COMMIT_VPE = 6,
	INVALL_VPE = 7,
	PROP_UPDATE_VSGI = 8,
};

struct its_cmd_info {
	enum its_vcpu_info_cmd_type cmd_type;
	union {
		struct its_vlpi_map *map;
		u8 config;
		bool req_db;
		struct {
			bool g0en;
			bool g1en;
		};
		struct {
			u8 priority;
			bool group;
		};
	};
};

struct clk;

struct clk_bulk_data {
	const char *id;
	struct clk *clk;
};

typedef void (*dr_release_t)(struct device *, void *);

typedef int (*dr_match_t)(struct device *, void *, void *);

struct devm_clk_state {
	struct clk *clk;
	void (*exit)(struct clk *);
};

struct clk_bulk_devres {
	struct clk_bulk_data *clks;
	int num_clks;
};

struct clk_core;

struct clk_hw;

struct clk_rate_request {
	struct clk_core *core;
	long unsigned int rate;
	long unsigned int min_rate;
	long unsigned int max_rate;
	long unsigned int best_parent_rate;
	struct clk_hw *best_parent_hw;
};

struct clk_init_data;

struct clk_hw {
	struct clk_core *core;
	struct clk *clk;
	const struct clk_init_data *init;
};

struct clk_duty {
	unsigned int num;
	unsigned int den;
};

struct clk_ops {
	int (*prepare)(struct clk_hw *);
	void (*unprepare)(struct clk_hw *);
	int (*is_prepared)(struct clk_hw *);
	void (*unprepare_unused)(struct clk_hw *);
	int (*enable)(struct clk_hw *);
	void (*disable)(struct clk_hw *);
	int (*is_enabled)(struct clk_hw *);
	void (*disable_unused)(struct clk_hw *);
	int (*save_context)(struct clk_hw *);
	void (*restore_context)(struct clk_hw *);
	long unsigned int (*recalc_rate)(struct clk_hw *, long unsigned int);
	long int (*round_rate)(struct clk_hw *, long unsigned int, long unsigned int *);
	int (*determine_rate)(struct clk_hw *, struct clk_rate_request *);
	int (*set_parent)(struct clk_hw *, u8);
	u8 (*get_parent)(struct clk_hw *);
	int (*set_rate)(struct clk_hw *, long unsigned int, long unsigned int);
	int (*set_rate_and_parent)(struct clk_hw *, long unsigned int, long unsigned int, u8);
	long unsigned int (*recalc_accuracy)(struct clk_hw *, long unsigned int);
	int (*get_phase)(struct clk_hw *);
	int (*set_phase)(struct clk_hw *, int);
	int (*get_duty_cycle)(struct clk_hw *, struct clk_duty *);
	int (*set_duty_cycle)(struct clk_hw *, struct clk_duty *);
	int (*init)(struct clk_hw *);
	void (*terminate)(struct clk_hw *);
	void (*debug_init)(struct clk_hw *, struct dentry *);
};

struct clk_parent_data {
	const struct clk_hw *hw;
	const char *fw_name;
	const char *name;
	int index;
};

struct clk_init_data {
	const char *name;
	const struct clk_ops *ops;
	const char * const *parent_names;
	const struct clk_parent_data *parent_data;
	const struct clk_hw **parent_hws;
	u8 num_parents;
	long unsigned int flags;
};

struct clk_mux {
	struct clk_hw hw;
	void *reg;
	const u32 *table;
	u32 mask;
	u8 shift;
	u8 flags;
	spinlock_t *lock;
};

struct plist_head {
	struct list_head node_list;
};

struct klist_node;

struct klist {
	spinlock_t k_lock;
	struct list_head k_list;
	void (*get)(struct klist_node *);
	void (*put)(struct klist_node *);
};

struct klist_node {
	void *n_klist;
	struct list_head n_node;
	struct kref n_ref;
};

struct klist_iter {
	struct klist *i_klist;
	struct klist_node *i_cur;
};

enum pm_qos_type {
	PM_QOS_UNITIALIZED = 0,
	PM_QOS_MAX = 1,
	PM_QOS_MIN = 2,
};

struct pm_qos_constraints {
	struct plist_head list;
	s32 target_value;
	s32 default_value;
	s32 no_constraint_value;
	enum pm_qos_type type;
	struct blocking_notifier_head *notifiers;
};

struct freq_constraints {
	struct pm_qos_constraints min_freq;
	struct blocking_notifier_head min_freq_notifiers;
	struct pm_qos_constraints max_freq;
	struct blocking_notifier_head max_freq_notifiers;
};

struct pm_qos_flags {
	struct list_head list;
	s32 effective_flags;
};

struct dev_pm_qos_request;

struct dev_pm_qos {
	struct pm_qos_constraints resume_latency;
	struct pm_qos_constraints latency_tolerance;
	struct freq_constraints freq;
	struct pm_qos_flags flags;
	struct dev_pm_qos_request *resume_latency_req;
	struct dev_pm_qos_request *latency_tolerance_req;
	struct dev_pm_qos_request *flags_req;
};

struct bus_attribute {
	struct attribute attr;
	ssize_t (*show)(const struct bus_type *, char *);
	ssize_t (*store)(const struct bus_type *, const char *, size_t);
};

enum bus_notifier_event {
	BUS_NOTIFY_ADD_DEVICE = 0,
	BUS_NOTIFY_DEL_DEVICE = 1,
	BUS_NOTIFY_REMOVED_DEVICE = 2,
	BUS_NOTIFY_BIND_DRIVER = 3,
	BUS_NOTIFY_BOUND_DRIVER = 4,
	BUS_NOTIFY_UNBIND_DRIVER = 5,
	BUS_NOTIFY_UNBOUND_DRIVER = 6,
	BUS_NOTIFY_DRIVER_NOT_BOUND = 7,
};

struct subsys_private {
	struct kset subsys;
	struct kset *devices_kset;
	struct list_head interfaces;
	struct mutex mutex;
	struct kset *drivers_kset;
	struct klist klist_devices;
	struct klist klist_drivers;
	struct blocking_notifier_head bus_notifier;
	unsigned int drivers_autoprobe: 1;
	const struct bus_type *bus;
	struct device *dev_root;
	struct kset glue_dirs;
	const struct class *class;
	struct lock_class_key lock_key;
};

struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;
};

struct driver_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device_driver *, char *);
	ssize_t (*store)(struct device_driver *, const char *, size_t);
};

struct subsys_interface {
	const char *name;
	struct bus_type *subsys;
	struct list_head node;
	int (*add_dev)(struct device *, struct subsys_interface *);
	void (*remove_dev)(struct device *, struct subsys_interface *);
};

struct device_private {
	struct klist klist_children;
	struct klist_node knode_parent;
	struct klist_node knode_driver;
	struct klist_node knode_bus;
	struct klist_node knode_class;
	struct list_head deferred_probe;
	struct device_driver *async_driver;
	char *deferred_probe_reason;
	struct device *device;
	u8 dead: 1;
};

struct pm_qos_flags_request {
	struct list_head node;
	s32 flags;
};

enum freq_qos_req_type {
	FREQ_QOS_MIN = 1,
	FREQ_QOS_MAX = 2,
};

struct freq_qos_request {
	enum freq_qos_req_type type;
	struct plist_node pnode;
	struct freq_constraints *qos;
};

enum dev_pm_qos_req_type {
	DEV_PM_QOS_RESUME_LATENCY = 1,
	DEV_PM_QOS_LATENCY_TOLERANCE = 2,
	DEV_PM_QOS_MIN_FREQUENCY = 3,
	DEV_PM_QOS_MAX_FREQUENCY = 4,
	DEV_PM_QOS_FLAGS = 5,
};

struct dev_pm_qos_request {
	enum dev_pm_qos_req_type type;
	union {
		struct plist_node pnode;
		struct pm_qos_flags_request flr;
		struct freq_qos_request freq;
	} data;
	struct device *dev;
};

struct subsys_dev_iter {
	struct klist_iter ki;
	const struct device_type *type;
};

typedef long unsigned int cycles_t;

typedef __be32 fdt32_t;

struct fdt_property {
	fdt32_t tag;
	fdt32_t len;
	fdt32_t nameoff;
	char data[0];
};

struct radix_tree_iter {
	long unsigned int index;
	long unsigned int next_index;
	long unsigned int tags;
	struct xa_node *node;
};

enum {
	RADIX_TREE_ITER_TAG_MASK = 15,
	RADIX_TREE_ITER_TAGGED = 16,
	RADIX_TREE_ITER_CONTIG = 32,
};

struct ida_bitmap {
	long unsigned int bitmap[16];
};

struct ida {
	struct xarray xa;
};

typedef struct {} local_lock_t;

struct radix_tree_preload {
	local_lock_t lock;
	unsigned int nr;
	struct xa_node *nodes;
};

struct __va_list {
	void *__stack;
	void *__gr_top;
	void *__vr_top;
	int __gr_offs;
	int __vr_offs;
};

typedef struct __va_list va_list;

typedef long unsigned int efi_status_t;

typedef int (*initcall_t)();

typedef int initcall_entry_t;

struct fc_log;

struct p_log {
	const char *prefix;
	struct fc_log *log;
};

enum fs_context_purpose {
	FS_CONTEXT_FOR_MOUNT = 0,
	FS_CONTEXT_FOR_SUBMOUNT = 1,
	FS_CONTEXT_FOR_RECONFIGURE = 2,
};

enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS = 0,
	FS_CONTEXT_CREATING = 1,
	FS_CONTEXT_AWAITING_MOUNT = 2,
	FS_CONTEXT_AWAITING_RECONF = 3,
	FS_CONTEXT_RECONF_PARAMS = 4,
	FS_CONTEXT_RECONFIGURING = 5,
	FS_CONTEXT_FAILED = 6,
};

struct fs_context_operations;

struct fs_context {
	const struct fs_context_operations *ops;
	struct mutex uapi_mutex;
	struct file_system_type *fs_type;
	void *fs_private;
	void *sget_key;
	struct dentry *root;
	struct user_namespace *user_ns;
	struct net *net_ns;
	const struct cred *cred;
	struct p_log log;
	const char *source;
	void *security;
	void *s_fs_info;
	unsigned int sb_flags;
	unsigned int sb_flags_mask;
	unsigned int s_iflags;
	enum fs_context_purpose purpose: 8;
	enum fs_context_phase phase: 8;
	bool need_free: 1;
	bool global: 1;
	bool oldapi: 1;
};

struct audit_names;

struct filename {
	const char *name;
	const char *uptr;
	int refcnt;
	struct audit_names *aname;
	const char iname[0];
};

struct nsset {
	unsigned int flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
};

enum fs_value_type {
	fs_value_is_undefined = 0,
	fs_value_is_flag = 1,
	fs_value_is_string = 2,
	fs_value_is_blob = 3,
	fs_value_is_filename = 4,
	fs_value_is_file = 5,
};

struct fs_parameter {
	const char *key;
	enum fs_value_type type: 8;
	union {
		char *string;
		void *blob;
		struct filename *name;
		struct file *file;
	};
	size_t size;
	int dirfd;
};

struct fc_log {
	refcount_t usage;
	u8 head;
	u8 tail;
	u8 need_free;
	struct module *owner;
	char *buffer[8];
};

struct fs_context_operations {
	void (*free)(struct fs_context *);
	int (*dup)(struct fs_context *, struct fs_context *);
	int (*parse_param)(struct fs_context *, struct fs_parameter *);
	int (*parse_monolithic)(struct fs_context *, void *);
	int (*get_tree)(struct fs_context *);
	int (*reconfigure)(struct fs_context *);
};

struct fs_parse_result {
	bool negated;
	union {
		bool boolean;
		int int_32;
		unsigned int uint_32;
		u64 uint_64;
	};
};

enum {
	IPSTATS_MIB_NUM = 0,
	IPSTATS_MIB_INPKTS = 1,
	IPSTATS_MIB_INOCTETS = 2,
	IPSTATS_MIB_INDELIVERS = 3,
	IPSTATS_MIB_OUTFORWDATAGRAMS = 4,
	IPSTATS_MIB_OUTPKTS = 5,
	IPSTATS_MIB_OUTOCTETS = 6,
	IPSTATS_MIB_INHDRERRORS = 7,
	IPSTATS_MIB_INTOOBIGERRORS = 8,
	IPSTATS_MIB_INNOROUTES = 9,
	IPSTATS_MIB_INADDRERRORS = 10,
	IPSTATS_MIB_INUNKNOWNPROTOS = 11,
	IPSTATS_MIB_INTRUNCATEDPKTS = 12,
	IPSTATS_MIB_INDISCARDS = 13,
	IPSTATS_MIB_OUTDISCARDS = 14,
	IPSTATS_MIB_OUTNOROUTES = 15,
	IPSTATS_MIB_REASMTIMEOUT = 16,
	IPSTATS_MIB_REASMREQDS = 17,
	IPSTATS_MIB_REASMOKS = 18,
	IPSTATS_MIB_REASMFAILS = 19,
	IPSTATS_MIB_FRAGOKS = 20,
	IPSTATS_MIB_FRAGFAILS = 21,
	IPSTATS_MIB_FRAGCREATES = 22,
	IPSTATS_MIB_INMCASTPKTS = 23,
	IPSTATS_MIB_OUTMCASTPKTS = 24,
	IPSTATS_MIB_INBCASTPKTS = 25,
	IPSTATS_MIB_OUTBCASTPKTS = 26,
	IPSTATS_MIB_INMCASTOCTETS = 27,
	IPSTATS_MIB_OUTMCASTOCTETS = 28,
	IPSTATS_MIB_INBCASTOCTETS = 29,
	IPSTATS_MIB_OUTBCASTOCTETS = 30,
	IPSTATS_MIB_CSUMERRORS = 31,
	IPSTATS_MIB_NOECTPKTS = 32,
	IPSTATS_MIB_ECT1PKTS = 33,
	IPSTATS_MIB_ECT0PKTS = 34,
	IPSTATS_MIB_CEPKTS = 35,
	IPSTATS_MIB_REASM_OVERLAPS = 36,
	__IPSTATS_MIB_MAX = 37,
};

enum {
	ICMP_MIB_NUM = 0,
	ICMP_MIB_INMSGS = 1,
	ICMP_MIB_INERRORS = 2,
	ICMP_MIB_INDESTUNREACHS = 3,
	ICMP_MIB_INTIMEEXCDS = 4,
	ICMP_MIB_INPARMPROBS = 5,
	ICMP_MIB_INSRCQUENCHS = 6,
	ICMP_MIB_INREDIRECTS = 7,
	ICMP_MIB_INECHOS = 8,
	ICMP_MIB_INECHOREPS = 9,
	ICMP_MIB_INTIMESTAMPS = 10,
	ICMP_MIB_INTIMESTAMPREPS = 11,
	ICMP_MIB_INADDRMASKS = 12,
	ICMP_MIB_INADDRMASKREPS = 13,
	ICMP_MIB_OUTMSGS = 14,
	ICMP_MIB_OUTERRORS = 15,
	ICMP_MIB_OUTDESTUNREACHS = 16,
	ICMP_MIB_OUTTIMEEXCDS = 17,
	ICMP_MIB_OUTPARMPROBS = 18,
	ICMP_MIB_OUTSRCQUENCHS = 19,
	ICMP_MIB_OUTREDIRECTS = 20,
	ICMP_MIB_OUTECHOS = 21,
	ICMP_MIB_OUTECHOREPS = 22,
	ICMP_MIB_OUTTIMESTAMPS = 23,
	ICMP_MIB_OUTTIMESTAMPREPS = 24,
	ICMP_MIB_OUTADDRMASKS = 25,
	ICMP_MIB_OUTADDRMASKREPS = 26,
	ICMP_MIB_CSUMERRORS = 27,
	ICMP_MIB_RATELIMITGLOBAL = 28,
	ICMP_MIB_RATELIMITHOST = 29,
	__ICMP_MIB_MAX = 30,
};

enum {
	ICMP6_MIB_NUM = 0,
	ICMP6_MIB_INMSGS = 1,
	ICMP6_MIB_INERRORS = 2,
	ICMP6_MIB_OUTMSGS = 3,
	ICMP6_MIB_OUTERRORS = 4,
	ICMP6_MIB_CSUMERRORS = 5,
	ICMP6_MIB_RATELIMITHOST = 6,
	__ICMP6_MIB_MAX = 7,
};

enum {
	TCP_MIB_NUM = 0,
	TCP_MIB_RTOALGORITHM = 1,
	TCP_MIB_RTOMIN = 2,
	TCP_MIB_RTOMAX = 3,
	TCP_MIB_MAXCONN = 4,
	TCP_MIB_ACTIVEOPENS = 5,
	TCP_MIB_PASSIVEOPENS = 6,
	TCP_MIB_ATTEMPTFAILS = 7,
	TCP_MIB_ESTABRESETS = 8,
	TCP_MIB_CURRESTAB = 9,
	TCP_MIB_INSEGS = 10,
	TCP_MIB_OUTSEGS = 11,
	TCP_MIB_RETRANSSEGS = 12,
	TCP_MIB_INERRS = 13,
	TCP_MIB_OUTRSTS = 14,
	TCP_MIB_CSUMERRORS = 15,
	__TCP_MIB_MAX = 16,
};

enum {
	UDP_MIB_NUM = 0,
	UDP_MIB_INDATAGRAMS = 1,
	UDP_MIB_NOPORTS = 2,
	UDP_MIB_INERRORS = 3,
	UDP_MIB_OUTDATAGRAMS = 4,
	UDP_MIB_RCVBUFERRORS = 5,
	UDP_MIB_SNDBUFERRORS = 6,
	UDP_MIB_CSUMERRORS = 7,
	UDP_MIB_IGNOREDMULTI = 8,
	UDP_MIB_MEMERRORS = 9,
	__UDP_MIB_MAX = 10,
};

enum {
	LINUX_MIB_NUM = 0,
	LINUX_MIB_SYNCOOKIESSENT = 1,
	LINUX_MIB_SYNCOOKIESRECV = 2,
	LINUX_MIB_SYNCOOKIESFAILED = 3,
	LINUX_MIB_EMBRYONICRSTS = 4,
	LINUX_MIB_PRUNECALLED = 5,
	LINUX_MIB_RCVPRUNED = 6,
	LINUX_MIB_OFOPRUNED = 7,
	LINUX_MIB_OUTOFWINDOWICMPS = 8,
	LINUX_MIB_LOCKDROPPEDICMPS = 9,
	LINUX_MIB_ARPFILTER = 10,
	LINUX_MIB_TIMEWAITED = 11,
	LINUX_MIB_TIMEWAITRECYCLED = 12,
	LINUX_MIB_TIMEWAITKILLED = 13,
	LINUX_MIB_PAWSACTIVEREJECTED = 14,
	LINUX_MIB_PAWSESTABREJECTED = 15,
	LINUX_MIB_DELAYEDACKS = 16,
	LINUX_MIB_DELAYEDACKLOCKED = 17,
	LINUX_MIB_DELAYEDACKLOST = 18,
	LINUX_MIB_LISTENOVERFLOWS = 19,
	LINUX_MIB_LISTENDROPS = 20,
	LINUX_MIB_TCPHPHITS = 21,
	LINUX_MIB_TCPPUREACKS = 22,
	LINUX_MIB_TCPHPACKS = 23,
	LINUX_MIB_TCPRENORECOVERY = 24,
	LINUX_MIB_TCPSACKRECOVERY = 25,
	LINUX_MIB_TCPSACKRENEGING = 26,
	LINUX_MIB_TCPSACKREORDER = 27,
	LINUX_MIB_TCPRENOREORDER = 28,
	LINUX_MIB_TCPTSREORDER = 29,
	LINUX_MIB_TCPFULLUNDO = 30,
	LINUX_MIB_TCPPARTIALUNDO = 31,
	LINUX_MIB_TCPDSACKUNDO = 32,
	LINUX_MIB_TCPLOSSUNDO = 33,
	LINUX_MIB_TCPLOSTRETRANSMIT = 34,
	LINUX_MIB_TCPRENOFAILURES = 35,
	LINUX_MIB_TCPSACKFAILURES = 36,
	LINUX_MIB_TCPLOSSFAILURES = 37,
	LINUX_MIB_TCPFASTRETRANS = 38,
	LINUX_MIB_TCPSLOWSTARTRETRANS = 39,
	LINUX_MIB_TCPTIMEOUTS = 40,
	LINUX_MIB_TCPLOSSPROBES = 41,
	LINUX_MIB_TCPLOSSPROBERECOVERY = 42,
	LINUX_MIB_TCPRENORECOVERYFAIL = 43,
	LINUX_MIB_TCPSACKRECOVERYFAIL = 44,
	LINUX_MIB_TCPRCVCOLLAPSED = 45,
	LINUX_MIB_TCPDSACKOLDSENT = 46,
	LINUX_MIB_TCPDSACKOFOSENT = 47,
	LINUX_MIB_TCPDSACKRECV = 48,
	LINUX_MIB_TCPDSACKOFORECV = 49,
	LINUX_MIB_TCPABORTONDATA = 50,
	LINUX_MIB_TCPABORTONCLOSE = 51,
	LINUX_MIB_TCPABORTONMEMORY = 52,
	LINUX_MIB_TCPABORTONTIMEOUT = 53,
	LINUX_MIB_TCPABORTONLINGER = 54,
	LINUX_MIB_TCPABORTFAILED = 55,
	LINUX_MIB_TCPMEMORYPRESSURES = 56,
	LINUX_MIB_TCPMEMORYPRESSURESCHRONO = 57,
	LINUX_MIB_TCPSACKDISCARD = 58,
	LINUX_MIB_TCPDSACKIGNOREDOLD = 59,
	LINUX_MIB_TCPDSACKIGNOREDNOUNDO = 60,
	LINUX_MIB_TCPSPURIOUSRTOS = 61,
	LINUX_MIB_TCPMD5NOTFOUND = 62,
	LINUX_MIB_TCPMD5UNEXPECTED = 63,
	LINUX_MIB_TCPMD5FAILURE = 64,
	LINUX_MIB_SACKSHIFTED = 65,
	LINUX_MIB_SACKMERGED = 66,
	LINUX_MIB_SACKSHIFTFALLBACK = 67,
	LINUX_MIB_TCPBACKLOGDROP = 68,
	LINUX_MIB_PFMEMALLOCDROP = 69,
	LINUX_MIB_TCPMINTTLDROP = 70,
	LINUX_MIB_TCPDEFERACCEPTDROP = 71,
	LINUX_MIB_IPRPFILTER = 72,
	LINUX_MIB_TCPTIMEWAITOVERFLOW = 73,
	LINUX_MIB_TCPREQQFULLDOCOOKIES = 74,
	LINUX_MIB_TCPREQQFULLDROP = 75,
	LINUX_MIB_TCPRETRANSFAIL = 76,
	LINUX_MIB_TCPRCVCOALESCE = 77,
	LINUX_MIB_TCPBACKLOGCOALESCE = 78,
	LINUX_MIB_TCPOFOQUEUE = 79,
	LINUX_MIB_TCPOFODROP = 80,
	LINUX_MIB_TCPOFOMERGE = 81,
	LINUX_MIB_TCPCHALLENGEACK = 82,
	LINUX_MIB_TCPSYNCHALLENGE = 83,
	LINUX_MIB_TCPFASTOPENACTIVE = 84,
	LINUX_MIB_TCPFASTOPENACTIVEFAIL = 85,
	LINUX_MIB_TCPFASTOPENPASSIVE = 86,
	LINUX_MIB_TCPFASTOPENPASSIVEFAIL = 87,
	LINUX_MIB_TCPFASTOPENLISTENOVERFLOW = 88,
	LINUX_MIB_TCPFASTOPENCOOKIEREQD = 89,
	LINUX_MIB_TCPFASTOPENBLACKHOLE = 90,
	LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES = 91,
	LINUX_MIB_BUSYPOLLRXPACKETS = 92,
	LINUX_MIB_TCPAUTOCORKING = 93,
	LINUX_MIB_TCPFROMZEROWINDOWADV = 94,
	LINUX_MIB_TCPTOZEROWINDOWADV = 95,
	LINUX_MIB_TCPWANTZEROWINDOWADV = 96,
	LINUX_MIB_TCPSYNRETRANS = 97,
	LINUX_MIB_TCPORIGDATASENT = 98,
	LINUX_MIB_TCPHYSTARTTRAINDETECT = 99,
	LINUX_MIB_TCPHYSTARTTRAINCWND = 100,
	LINUX_MIB_TCPHYSTARTDELAYDETECT = 101,
	LINUX_MIB_TCPHYSTARTDELAYCWND = 102,
	LINUX_MIB_TCPACKSKIPPEDSYNRECV = 103,
	LINUX_MIB_TCPACKSKIPPEDPAWS = 104,
	LINUX_MIB_TCPACKSKIPPEDSEQ = 105,
	LINUX_MIB_TCPACKSKIPPEDFINWAIT2 = 106,
	LINUX_MIB_TCPACKSKIPPEDTIMEWAIT = 107,
	LINUX_MIB_TCPACKSKIPPEDCHALLENGE = 108,
	LINUX_MIB_TCPWINPROBE = 109,
	LINUX_MIB_TCPKEEPALIVE = 110,
	LINUX_MIB_TCPMTUPFAIL = 111,
	LINUX_MIB_TCPMTUPSUCCESS = 112,
	LINUX_MIB_TCPDELIVERED = 113,
	LINUX_MIB_TCPDELIVEREDCE = 114,
	LINUX_MIB_TCPACKCOMPRESSED = 115,
	LINUX_MIB_TCPZEROWINDOWDROP = 116,
	LINUX_MIB_TCPRCVQDROP = 117,
	LINUX_MIB_TCPWQUEUETOOBIG = 118,
	LINUX_MIB_TCPFASTOPENPASSIVEALTKEY = 119,
	LINUX_MIB_TCPTIMEOUTREHASH = 120,
	LINUX_MIB_TCPDUPLICATEDATAREHASH = 121,
	LINUX_MIB_TCPDSACKRECVSEGS = 122,
	LINUX_MIB_TCPDSACKIGNOREDDUBIOUS = 123,
	LINUX_MIB_TCPMIGRATEREQSUCCESS = 124,
	LINUX_MIB_TCPMIGRATEREQFAILURE = 125,
	LINUX_MIB_TCPPLBREHASH = 126,
	__LINUX_MIB_MAX = 127,
};

enum {
	LINUX_MIB_XFRMNUM = 0,
	LINUX_MIB_XFRMINERROR = 1,
	LINUX_MIB_XFRMINBUFFERERROR = 2,
	LINUX_MIB_XFRMINHDRERROR = 3,
	LINUX_MIB_XFRMINNOSTATES = 4,
	LINUX_MIB_XFRMINSTATEPROTOERROR = 5,
	LINUX_MIB_XFRMINSTATEMODEERROR = 6,
	LINUX_MIB_XFRMINSTATESEQERROR = 7,
	LINUX_MIB_XFRMINSTATEEXPIRED = 8,
	LINUX_MIB_XFRMINSTATEMISMATCH = 9,
	LINUX_MIB_XFRMINSTATEINVALID = 10,
	LINUX_MIB_XFRMINTMPLMISMATCH = 11,
	LINUX_MIB_XFRMINNOPOLS = 12,
	LINUX_MIB_XFRMINPOLBLOCK = 13,
	LINUX_MIB_XFRMINPOLERROR = 14,
	LINUX_MIB_XFRMOUTERROR = 15,
	LINUX_MIB_XFRMOUTBUNDLEGENERROR = 16,
	LINUX_MIB_XFRMOUTBUNDLECHECKERROR = 17,
	LINUX_MIB_XFRMOUTNOSTATES = 18,
	LINUX_MIB_XFRMOUTSTATEPROTOERROR = 19,
	LINUX_MIB_XFRMOUTSTATEMODEERROR = 20,
	LINUX_MIB_XFRMOUTSTATESEQERROR = 21,
	LINUX_MIB_XFRMOUTSTATEEXPIRED = 22,
	LINUX_MIB_XFRMOUTPOLBLOCK = 23,
	LINUX_MIB_XFRMOUTPOLDEAD = 24,
	LINUX_MIB_XFRMOUTPOLERROR = 25,
	LINUX_MIB_XFRMFWDHDRERROR = 26,
	LINUX_MIB_XFRMOUTSTATEINVALID = 27,
	LINUX_MIB_XFRMACQUIREERROR = 28,
	__LINUX_MIB_XFRMMAX = 29,
};

enum {
	LINUX_MIB_TLSNUM = 0,
	LINUX_MIB_TLSCURRTXSW = 1,
	LINUX_MIB_TLSCURRRXSW = 2,
	LINUX_MIB_TLSCURRTXDEVICE = 3,
	LINUX_MIB_TLSCURRRXDEVICE = 4,
	LINUX_MIB_TLSTXSW = 5,
	LINUX_MIB_TLSRXSW = 6,
	LINUX_MIB_TLSTXDEVICE = 7,
	LINUX_MIB_TLSRXDEVICE = 8,
	LINUX_MIB_TLSDECRYPTERROR = 9,
	LINUX_MIB_TLSRXDEVICERESYNC = 10,
	LINUX_MIB_TLSDECRYPTRETRY = 11,
	LINUX_MIB_TLSRXNOPADVIOL = 12,
	__LINUX_MIB_TLSMAX = 13,
};

enum nf_inet_hooks {
	NF_INET_PRE_ROUTING = 0,
	NF_INET_LOCAL_IN = 1,
	NF_INET_FORWARD = 2,
	NF_INET_LOCAL_OUT = 3,
	NF_INET_POST_ROUTING = 4,
	NF_INET_NUMHOOKS = 5,
	NF_INET_INGRESS = 5,
};

enum {
	NFPROTO_UNSPEC = 0,
	NFPROTO_INET = 1,
	NFPROTO_IPV4 = 2,
	NFPROTO_ARP = 3,
	NFPROTO_NETDEV = 5,
	NFPROTO_BRIDGE = 7,
	NFPROTO_IPV6 = 10,
	NFPROTO_NUMPROTO = 11,
};

enum {
	XFRM_POLICY_IN = 0,
	XFRM_POLICY_OUT = 1,
	XFRM_POLICY_FWD = 2,
	XFRM_POLICY_MASK = 3,
	XFRM_POLICY_MAX = 3,
};

enum netns_bpf_attach_type {
	NETNS_BPF_INVALID = -1,
	NETNS_BPF_FLOW_DISSECTOR = 0,
	NETNS_BPF_SK_LOOKUP = 1,
	MAX_NETNS_BPF_ATTACH_TYPE = 2,
};

enum flow_dissector_key_id {
	FLOW_DISSECTOR_KEY_CONTROL = 0,
	FLOW_DISSECTOR_KEY_BASIC = 1,
	FLOW_DISSECTOR_KEY_IPV4_ADDRS = 2,
	FLOW_DISSECTOR_KEY_IPV6_ADDRS = 3,
	FLOW_DISSECTOR_KEY_PORTS = 4,
	FLOW_DISSECTOR_KEY_PORTS_RANGE = 5,
	FLOW_DISSECTOR_KEY_ICMP = 6,
	FLOW_DISSECTOR_KEY_ETH_ADDRS = 7,
	FLOW_DISSECTOR_KEY_TIPC = 8,
	FLOW_DISSECTOR_KEY_ARP = 9,
	FLOW_DISSECTOR_KEY_VLAN = 10,
	FLOW_DISSECTOR_KEY_FLOW_LABEL = 11,
	FLOW_DISSECTOR_KEY_GRE_KEYID = 12,
	FLOW_DISSECTOR_KEY_MPLS_ENTROPY = 13,
	FLOW_DISSECTOR_KEY_ENC_KEYID = 14,
	FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS = 15,
	FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS = 16,
	FLOW_DISSECTOR_KEY_ENC_CONTROL = 17,
	FLOW_DISSECTOR_KEY_ENC_PORTS = 18,
	FLOW_DISSECTOR_KEY_MPLS = 19,
	FLOW_DISSECTOR_KEY_TCP = 20,
	FLOW_DISSECTOR_KEY_IP = 21,
	FLOW_DISSECTOR_KEY_CVLAN = 22,
	FLOW_DISSECTOR_KEY_ENC_IP = 23,
	FLOW_DISSECTOR_KEY_ENC_OPTS = 24,
	FLOW_DISSECTOR_KEY_META = 25,
	FLOW_DISSECTOR_KEY_CT = 26,
	FLOW_DISSECTOR_KEY_HASH = 27,
	FLOW_DISSECTOR_KEY_NUM_OF_VLANS = 28,
	FLOW_DISSECTOR_KEY_PPPOE = 29,
	FLOW_DISSECTOR_KEY_L2TPV3 = 30,
	FLOW_DISSECTOR_KEY_MAX = 31,
};

struct trace_event_raw_initcall_level {
	struct trace_entry ent;
	u32 __data_loc_level;
	char __data[0];
};

struct trace_event_raw_initcall_start {
	struct trace_entry ent;
	initcall_t func;
	char __data[0];
};

struct trace_event_raw_initcall_finish {
	struct trace_entry ent;
	initcall_t func;
	int ret;
	char __data[0];
};

struct trace_event_data_offsets_initcall_level {
	u32 level;
};

struct trace_event_data_offsets_initcall_start {};

struct trace_event_data_offsets_initcall_finish {};

typedef void (*btf_trace_initcall_level)(void *, const char *);

typedef void (*btf_trace_initcall_start)(void *, initcall_t);

typedef void (*btf_trace_initcall_finish)(void *, initcall_t, int);

struct blacklist_entry {
	struct list_head next;
	char *buf;
};

typedef long int (*syscall_fn_t)(const struct pt_regs *);

enum {
	FOLL_WRITE = 1,
	FOLL_GET = 2,
	FOLL_DUMP = 4,
	FOLL_FORCE = 8,
	FOLL_NOWAIT = 16,
	FOLL_NOFAULT = 32,
	FOLL_HWPOISON = 64,
	FOLL_ANON = 128,
	FOLL_LONGTERM = 256,
	FOLL_SPLIT_PMD = 512,
	FOLL_PCI_P2PDMA = 1024,
	FOLL_INTERRUPTIBLE = 2048,
};

struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *, struct device_attribute *, char *);
	ssize_t (*store)(struct device *, struct device_attribute *, const char *, size_t);
};

typedef u64 p4dval_t;

enum fixed_addresses {
	FIX_HOLE = 0,
	FIX_FDT_END = 1,
	FIX_FDT = 514,
	FIX_EARLYCON_MEM_BASE = 515,
	FIX_TEXT_POKE0 = 516,
	FIX_ENTRY_TRAMP_TEXT4 = 517,
	FIX_ENTRY_TRAMP_TEXT3 = 518,
	FIX_ENTRY_TRAMP_TEXT2 = 519,
	FIX_ENTRY_TRAMP_TEXT1 = 520,
	__end_of_permanent_fixed_addresses = 521,
	FIX_BTMAP_END = 521,
	FIX_BTMAP_BEGIN = 968,
	FIX_PTE = 969,
	FIX_PMD = 970,
	FIX_PUD = 971,
	FIX_PGD = 972,
	__end_of_fixed_addresses = 973,
};

enum key_being_used_for {
	VERIFYING_MODULE_SIGNATURE = 0,
	VERIFYING_FIRMWARE_SIGNATURE = 1,
	VERIFYING_KEXEC_PE_SIGNATURE = 2,
	VERIFYING_KEY_SIGNATURE = 3,
	VERIFYING_KEY_SELF_SIGNATURE = 4,
	VERIFYING_UNSPECIFIED_SIGNATURE = 5,
	NR__KEY_BEING_USED_FOR = 6,
};

enum memblock_flags {
	MEMBLOCK_NONE = 0,
	MEMBLOCK_HOTPLUG = 1,
	MEMBLOCK_MIRROR = 2,
	MEMBLOCK_NOMAP = 4,
	MEMBLOCK_DRIVER_MANAGED = 8,
};

struct memblock_region {
	phys_addr_t base;
	phys_addr_t size;
	enum memblock_flags flags;
};

struct memblock_type {
	long unsigned int cnt;
	long unsigned int max;
	phys_addr_t total_size;
	struct memblock_region *regions;
	char *name;
};

struct memblock {
	bool bottom_up;
	phys_addr_t current_limit;
	struct memblock_type memory;
	struct memblock_type reserved;
};

typedef void ttbr_replace_func(phys_addr_t);

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_L2TP = 115,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};

enum {
	RTAX_UNSPEC = 0,
	RTAX_LOCK = 1,
	RTAX_MTU = 2,
	RTAX_WINDOW = 3,
	RTAX_RTT = 4,
	RTAX_RTTVAR = 5,
	RTAX_SSTHRESH = 6,
	RTAX_CWND = 7,
	RTAX_ADVMSS = 8,
	RTAX_REORDERING = 9,
	RTAX_HOPLIMIT = 10,
	RTAX_INITCWND = 11,
	RTAX_FEATURES = 12,
	RTAX_RTO_MIN = 13,
	RTAX_INITRWND = 14,
	RTAX_QUICKACK = 15,
	RTAX_CC_ALGO = 16,
	RTAX_FASTOPEN_NO_COOKIE = 17,
	__RTAX_MAX = 18,
};

enum rpc_display_format_t {
	RPC_DISPLAY_ADDR = 0,
	RPC_DISPLAY_PORT = 1,
	RPC_DISPLAY_PROTO = 2,
	RPC_DISPLAY_HEX_ADDR = 3,
	RPC_DISPLAY_HEX_PORT = 4,
	RPC_DISPLAY_NETID = 5,
	RPC_DISPLAY_MAX = 6,
};

enum {
	NEIGH_VAR_MCAST_PROBES = 0,
	NEIGH_VAR_UCAST_PROBES = 1,
	NEIGH_VAR_APP_PROBES = 2,
	NEIGH_VAR_MCAST_REPROBES = 3,
	NEIGH_VAR_RETRANS_TIME = 4,
	NEIGH_VAR_BASE_REACHABLE_TIME = 5,
	NEIGH_VAR_DELAY_PROBE_TIME = 6,
	NEIGH_VAR_INTERVAL_PROBE_TIME_MS = 7,
	NEIGH_VAR_GC_STALETIME = 8,
	NEIGH_VAR_QUEUE_LEN_BYTES = 9,
	NEIGH_VAR_PROXY_QLEN = 10,
	NEIGH_VAR_ANYCAST_DELAY = 11,
	NEIGH_VAR_PROXY_DELAY = 12,
	NEIGH_VAR_LOCKTIME = 13,
	NEIGH_VAR_QUEUE_LEN = 14,
	NEIGH_VAR_RETRANS_TIME_MS = 15,
	NEIGH_VAR_BASE_REACHABLE_TIME_MS = 16,
	NEIGH_VAR_GC_INTERVAL = 17,
	NEIGH_VAR_GC_THRESH1 = 18,
	NEIGH_VAR_GC_THRESH2 = 19,
	NEIGH_VAR_GC_THRESH3 = 20,
	NEIGH_VAR_MAX = 21,
};

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_MAX_STATES = 13,
};

enum tsq_enum {
	TSQ_THROTTLED = 0,
	TSQ_QUEUED = 1,
	TCP_TSQ_DEFERRED = 2,
	TCP_WRITE_TIMER_DEFERRED = 3,
	TCP_DELACK_TIMER_DEFERRED = 4,
	TCP_MTU_REDUCED_DEFERRED = 5,
};

enum nfs_opnum4 {
	OP_ACCESS = 3,
	OP_CLOSE = 4,
	OP_COMMIT = 5,
	OP_CREATE = 6,
	OP_DELEGPURGE = 7,
	OP_DELEGRETURN = 8,
	OP_GETATTR = 9,
	OP_GETFH = 10,
	OP_LINK = 11,
	OP_LOCK = 12,
	OP_LOCKT = 13,
	OP_LOCKU = 14,
	OP_LOOKUP = 15,
	OP_LOOKUPP = 16,
	OP_NVERIFY = 17,
	OP_OPEN = 18,
	OP_OPENATTR = 19,
	OP_OPEN_CONFIRM = 20,
	OP_OPEN_DOWNGRADE = 21,
	OP_PUTFH = 22,
	OP_PUTPUBFH = 23,
	OP_PUTROOTFH = 24,
	OP_READ = 25,
	OP_READDIR = 26,
	OP_READLINK = 27,
	OP_REMOVE = 28,
	OP_RENAME = 29,
	OP_RENEW = 30,
	OP_RESTOREFH = 31,
	OP_SAVEFH = 32,
	OP_SECINFO = 33,
	OP_SETATTR = 34,
	OP_SETCLIENTID = 35,
	OP_SETCLIENTID_CONFIRM = 36,
	OP_VERIFY = 37,
	OP_WRITE = 38,
	OP_RELEASE_LOCKOWNER = 39,
	OP_BACKCHANNEL_CTL = 40,
	OP_BIND_CONN_TO_SESSION = 41,
	OP_EXCHANGE_ID = 42,
	OP_CREATE_SESSION = 43,
	OP_DESTROY_SESSION = 44,
	OP_FREE_STATEID = 45,
	OP_GET_DIR_DELEGATION = 46,
	OP_GETDEVICEINFO = 47,
	OP_GETDEVICELIST = 48,
	OP_LAYOUTCOMMIT = 49,
	OP_LAYOUTGET = 50,
	OP_LAYOUTRETURN = 51,
	OP_SECINFO_NO_NAME = 52,
	OP_SEQUENCE = 53,
	OP_SET_SSV = 54,
	OP_TEST_STATEID = 55,
	OP_WANT_DELEGATION = 56,
	OP_DESTROY_CLIENTID = 57,
	OP_RECLAIM_COMPLETE = 58,
	OP_ALLOCATE = 59,
	OP_COPY = 60,
	OP_COPY_NOTIFY = 61,
	OP_DEALLOCATE = 62,
	OP_IO_ADVISE = 63,
	OP_LAYOUTERROR = 64,
	OP_LAYOUTSTATS = 65,
	OP_OFFLOAD_CANCEL = 66,
	OP_OFFLOAD_STATUS = 67,
	OP_READ_PLUS = 68,
	OP_SEEK = 69,
	OP_WRITE_SAME = 70,
	OP_CLONE = 71,
	OP_GETXATTR = 72,
	OP_SETXATTR = 73,
	OP_LISTXATTRS = 74,
	OP_REMOVEXATTR = 75,
	OP_ILLEGAL = 10044,
};

enum {
	PROC_ROOT_INO = 1,
	PROC_IPC_INIT_INO = 4026531839,
	PROC_UTS_INIT_INO = 4026531838,
	PROC_USER_INIT_INO = 4026531837,
	PROC_PID_INIT_INO = 4026531836,
	PROC_CGROUP_INIT_INO = 4026531835,
	PROC_TIME_INIT_INO = 4026531834,
};

enum {
	NAPI_STATE_SCHED = 0,
	NAPI_STATE_MISSED = 1,
	NAPI_STATE_DISABLE = 2,
	NAPI_STATE_NPSVC = 3,
	NAPI_STATE_LISTED = 4,
	NAPI_STATE_NO_BUSY_POLL = 5,
	NAPI_STATE_IN_BUSY_POLL = 6,
	NAPI_STATE_PREFER_BUSY_POLL = 7,
	NAPI_STATE_THREADED = 8,
	NAPI_STATE_SCHED_THREADED = 9,
};

enum bpf_xdp_mode {
	XDP_MODE_SKB = 0,
	XDP_MODE_DRV = 1,
	XDP_MODE_HW = 2,
	__MAX_XDP_MODE = 3,
};

enum {
	NETIF_MSG_DRV_BIT = 0,
	NETIF_MSG_PROBE_BIT = 1,
	NETIF_MSG_LINK_BIT = 2,
	NETIF_MSG_TIMER_BIT = 3,
	NETIF_MSG_IFDOWN_BIT = 4,
	NETIF_MSG_IFUP_BIT = 5,
	NETIF_MSG_RX_ERR_BIT = 6,
	NETIF_MSG_TX_ERR_BIT = 7,
	NETIF_MSG_TX_QUEUED_BIT = 8,
	NETIF_MSG_INTR_BIT = 9,
	NETIF_MSG_TX_DONE_BIT = 10,
	NETIF_MSG_RX_STATUS_BIT = 11,
	NETIF_MSG_PKTDATA_BIT = 12,
	NETIF_MSG_HW_BIT = 13,
	NETIF_MSG_WOL_BIT = 14,
	NETIF_MSG_CLASS_COUNT = 15,
};

enum {
	IRQ_SET_MASK_OK = 0,
	IRQ_SET_MASK_OK_NOCOPY = 1,
	IRQ_SET_MASK_OK_DONE = 2,
};

enum {
	IRQC_IS_HARDIRQ = 0,
	IRQC_IS_NESTED = 1,
};

enum hk_type {
	HK_TYPE_TIMER = 0,
	HK_TYPE_RCU = 1,
	HK_TYPE_MISC = 2,
	HK_TYPE_SCHED = 3,
	HK_TYPE_TICK = 4,
	HK_TYPE_DOMAIN = 5,
	HK_TYPE_WQ = 6,
	HK_TYPE_MANAGED_IRQ = 7,
	HK_TYPE_KTHREAD = 8,
	HK_TYPE_MAX = 9,
};

typedef void (*task_work_func_t)(struct callback_head *);

enum task_work_notify_mode {
	TWA_NONE = 0,
	TWA_RESUME = 1,
	TWA_SIGNAL = 2,
	TWA_SIGNAL_NO_IPI = 3,
};

enum {
	IRQ_DOMAIN_FLAG_HIERARCHY = 1,
	IRQ_DOMAIN_NAME_ALLOCATED = 2,
	IRQ_DOMAIN_FLAG_IPI_PER_CPU = 4,
	IRQ_DOMAIN_FLAG_IPI_SINGLE = 8,
	IRQ_DOMAIN_FLAG_MSI = 16,
	IRQ_DOMAIN_FLAG_ISOLATED_MSI = 32,
	IRQ_DOMAIN_FLAG_NO_MAP = 64,
	IRQ_DOMAIN_FLAG_MSI_PARENT = 256,
	IRQ_DOMAIN_FLAG_MSI_DEVICE = 512,
	IRQ_DOMAIN_FLAG_NONCORE = 65536,
};

typedef long unsigned int ulong;

typedef void (*call_rcu_func_t)(struct callback_head *, rcu_callback_t);

enum ftrace_dump_mode {
	DUMP_NONE = 0,
	DUMP_ALL = 1,
	DUMP_ORIG = 2,
};

enum {
	CSD_FLAG_LOCK = 1,
	IRQ_WORK_PENDING = 1,
	IRQ_WORK_BUSY = 2,
	IRQ_WORK_LAZY = 4,
	IRQ_WORK_HARD_IRQ = 8,
	IRQ_WORK_CLAIMED = 3,
	CSD_TYPE_ASYNC = 0,
	CSD_TYPE_SYNC = 16,
	CSD_TYPE_IRQ_WORK = 32,
	CSD_TYPE_TTWU = 48,
	CSD_FLAG_TYPE_MASK = 240,
};

typedef void (*smp_call_func_t)(void *);

struct rcu_gp_oldstate {
	long unsigned int rgos_norm;
	long unsigned int rgos_exp;
};

struct swait_queue {
	struct task_struct *task;
	struct list_head task_list;
};

struct rcu_synchronize {
	struct callback_head head;
	struct completion completion;
};

struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};

enum hrtimer_mode {
	HRTIMER_MODE_ABS = 0,
	HRTIMER_MODE_REL = 1,
	HRTIMER_MODE_PINNED = 2,
	HRTIMER_MODE_SOFT = 4,
	HRTIMER_MODE_HARD = 8,
	HRTIMER_MODE_ABS_PINNED = 2,
	HRTIMER_MODE_REL_PINNED = 3,
	HRTIMER_MODE_ABS_SOFT = 4,
	HRTIMER_MODE_REL_SOFT = 5,
	HRTIMER_MODE_ABS_PINNED_SOFT = 6,
	HRTIMER_MODE_REL_PINNED_SOFT = 7,
	HRTIMER_MODE_ABS_HARD = 8,
	HRTIMER_MODE_REL_HARD = 9,
	HRTIMER_MODE_ABS_PINNED_HARD = 10,
	HRTIMER_MODE_REL_PINNED_HARD = 11,
};

struct rcu_cblist {
	struct callback_head *head;
	struct callback_head **tail;
	long int len;
};

struct atomic_notifier_head {
	spinlock_t lock;
	struct notifier_block *head;
};

struct softirq_action {
	void (*action)(struct softirq_action *);
};

struct kernel_cpustat {
	u64 cpustat[10];
};

struct sched_param {
	int sched_priority;
};

enum tick_dep_bits {
	TICK_DEP_BIT_POSIX_TIMER = 0,
	TICK_DEP_BIT_PERF_EVENTS = 1,
	TICK_DEP_BIT_SCHED = 2,
	TICK_DEP_BIT_CLOCK_UNSTABLE = 3,
	TICK_DEP_BIT_RCU = 4,
	TICK_DEP_BIT_RCU_EXP = 5,
};

struct sysrq_key_op {
	void (* const handler)(int);
	const char * const help_msg;
	const char * const action_msg;
	const int enable_mask;
};

struct smp_hotplug_thread {
	struct task_struct **store;
	struct list_head list;
	int (*thread_should_run)(unsigned int);
	void (*thread_fn)(unsigned int);
	void (*create)(unsigned int);
	void (*setup)(unsigned int);
	void (*cleanup)(unsigned int, bool);
	void (*park)(unsigned int);
	void (*unpark)(unsigned int);
	bool selfparking;
	const char *thread_comm;
};

struct rt_mutex_base {
	raw_spinlock_t wait_lock;
	struct rb_root_cached waiters;
	struct task_struct *owner;
};

struct rt_mutex {
	struct rt_mutex_base rtmutex;
};

struct rcu_exp_work {
	long unsigned int rew_s;
	struct work_struct rew_work;
};

struct rcu_node {
	raw_spinlock_t lock;
	long unsigned int gp_seq;
	long unsigned int gp_seq_needed;
	long unsigned int completedqs;
	long unsigned int qsmask;
	long unsigned int rcu_gp_init_mask;
	long unsigned int qsmaskinit;
	long unsigned int qsmaskinitnext;
	long unsigned int expmask;
	long unsigned int expmaskinit;
	long unsigned int expmaskinitnext;
	long unsigned int cbovldmask;
	long unsigned int ffmask;
	long unsigned int grpmask;
	int grplo;
	int grphi;
	u8 grpnum;
	u8 level;
	bool wait_blkd_tasks;
	struct rcu_node *parent;
	struct list_head blkd_tasks;
	struct list_head *gp_tasks;
	struct list_head *exp_tasks;
	struct list_head *boost_tasks;
	struct rt_mutex boost_mtx;
	long unsigned int boost_time;
	struct mutex boost_kthread_mutex;
	struct task_struct *boost_kthread_task;
	unsigned int boost_kthread_status;
	long unsigned int n_boosts;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	raw_spinlock_t fqslock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t exp_lock;
	long unsigned int exp_seq_rq;
	wait_queue_head_t exp_wq[4];
	struct rcu_exp_work rew;
	bool exp_need_flush;
	raw_spinlock_t exp_poll_lock;
	long unsigned int exp_seq_poll_rq;
	struct work_struct exp_poll_wq;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

union rcu_noqs {
	struct {
		u8 norm;
		u8 exp;
	} b;
	u16 s;
};

struct rcu_snap_record {
	long unsigned int gp_seq;
	u64 cputime_irq;
	u64 cputime_softirq;
	u64 cputime_system;
	long unsigned int nr_hardirqs;
	unsigned int nr_softirqs;
	long long unsigned int nr_csw;
	long unsigned int jiffies;
};

struct rcu_data {
	long unsigned int gp_seq;
	long unsigned int gp_seq_needed;
	union rcu_noqs cpu_no_qs;
	bool core_needs_qs;
	bool beenonline;
	bool gpwrap;
	bool cpu_started;
	struct rcu_node *mynode;
	long unsigned int grpmask;
	long unsigned int ticks_this_gp;
	struct irq_work defer_qs_iw;
	bool defer_qs_iw_pending;
	struct work_struct strict_work;
	struct rcu_segcblist cblist;
	long int qlen_last_fqs_check;
	long unsigned int n_cbs_invoked;
	long unsigned int n_force_qs_snap;
	long int blimit;
	int dynticks_snap;
	bool rcu_need_heavy_qs;
	bool rcu_urgent_qs;
	bool rcu_forced_tick;
	bool rcu_forced_tick_exp;
	long unsigned int barrier_seq_snap;
	struct callback_head barrier_head;
	int exp_dynticks_snap;
	struct task_struct *rcu_cpu_kthread_task;
	unsigned int rcu_cpu_kthread_status;
	char rcu_cpu_has_work;
	long unsigned int rcuc_activity;
	unsigned int softirq_snap;
	struct irq_work rcu_iw;
	bool rcu_iw_pending;
	long unsigned int rcu_iw_gp_seq;
	long unsigned int rcu_ofl_gp_seq;
	short int rcu_ofl_gp_flags;
	long unsigned int rcu_onl_gp_seq;
	short int rcu_onl_gp_flags;
	long unsigned int last_fqs_resched;
	long unsigned int last_sched_clock;
	struct rcu_snap_record snap_record;
	long int lazy_len;
	int cpu;
};

struct rcu_state {
	struct rcu_node node[17];
	struct rcu_node *level[3];
	int ncpus;
	int n_online_cpus;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int gp_seq;
	long unsigned int gp_max;
	struct task_struct *gp_kthread;
	struct swait_queue_head gp_wq;
	short int gp_flags;
	short int gp_state;
	long unsigned int gp_wake_time;
	long unsigned int gp_wake_seq;
	long unsigned int gp_seq_polled;
	long unsigned int gp_seq_polled_snap;
	long unsigned int gp_seq_polled_exp_snap;
	struct mutex barrier_mutex;
	atomic_t barrier_cpu_count;
	struct completion barrier_completion;
	long unsigned int barrier_sequence;
	raw_spinlock_t barrier_lock;
	struct mutex exp_mutex;
	struct mutex exp_wake_mutex;
	long unsigned int expedited_sequence;
	atomic_t expedited_need_qs;
	struct swait_queue_head expedited_wq;
	int ncpus_snap;
	u8 cbovld;
	u8 cbovldnext;
	long unsigned int jiffies_force_qs;
	long unsigned int jiffies_kick_kthreads;
	long unsigned int n_force_qs;
	long unsigned int gp_start;
	long unsigned int gp_end;
	long unsigned int gp_activity;
	long unsigned int gp_req_activity;
	long unsigned int jiffies_stall;
	long unsigned int jiffies_resched;
	long unsigned int n_force_qs_gpstart;
	const char *name;
	char abbr;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	arch_spinlock_t ofl_lock;
	int nocb_is_setup;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum rcutorture_type {
	RCU_FLAVOR = 0,
	RCU_TASKS_FLAVOR = 1,
	RCU_TASKS_RUDE_FLAVOR = 2,
	RCU_TASKS_TRACING_FLAVOR = 3,
	RCU_TRIVIAL_FLAVOR = 4,
	SRCU_FLAVOR = 5,
	INVALID_RCU_FLAVOR = 6,
};

struct kvfree_rcu_bulk_data {
	struct list_head list;
	long unsigned int gp_snap;
	long unsigned int nr_records;
	void *records[0];
};

struct kfree_rcu_cpu;

struct kfree_rcu_cpu_work {
	struct rcu_work rcu_work;
	struct callback_head *head_free;
	struct list_head bulk_head_free[2];
	struct kfree_rcu_cpu *krcp;
};

struct kfree_rcu_cpu {
	struct callback_head *head;
	long unsigned int head_gp_snap;
	atomic_t head_count;
	struct list_head bulk_head[2];
	atomic_t bulk_count[2];
	struct kfree_rcu_cpu_work krw_arr[2];
	raw_spinlock_t lock;
	struct delayed_work monitor_work;
	bool initialized;
	struct delayed_work page_cache_work;
	atomic_t backoff_page_cache_fill;
	atomic_t work_in_progress;
	struct hrtimer hrtimer;
	struct llist_head bkvcache;
	int nr_bkv_objs;
};

enum pm_qos_req_action {
	PM_QOS_ADD_REQ = 0,
	PM_QOS_UPDATE_REQ = 1,
	PM_QOS_REMOVE_REQ = 2,
};

enum cpufreq_table_sorting {
	CPUFREQ_TABLE_UNSORTED = 0,
	CPUFREQ_TABLE_SORTED_ASCENDING = 1,
	CPUFREQ_TABLE_SORTED_DESCENDING = 2,
};

struct cpufreq_cpuinfo {
	unsigned int max_freq;
	unsigned int min_freq;
	unsigned int transition_latency;
};

struct cpufreq_stats;

struct thermal_cooling_device;

struct cpufreq_governor;

struct cpufreq_frequency_table;

struct cpufreq_policy {
	cpumask_var_t cpus;
	cpumask_var_t related_cpus;
	cpumask_var_t real_cpus;
	unsigned int shared_type;
	unsigned int cpu;
	struct clk *clk;
	struct cpufreq_cpuinfo cpuinfo;
	unsigned int min;
	unsigned int max;
	unsigned int cur;
	unsigned int suspend_freq;
	unsigned int policy;
	unsigned int last_policy;
	struct cpufreq_governor *governor;
	void *governor_data;
	char last_governor[16];
	struct work_struct update;
	struct freq_constraints constraints;
	struct freq_qos_request *min_freq_req;
	struct freq_qos_request *max_freq_req;
	struct cpufreq_frequency_table *freq_table;
	enum cpufreq_table_sorting freq_table_sorted;
	struct list_head policy_list;
	struct kobject kobj;
	struct completion kobj_unregister;
	struct rw_semaphore rwsem;
	bool fast_switch_possible;
	bool fast_switch_enabled;
	bool strict_target;
	bool efficiencies_available;
	unsigned int transition_delay_us;
	bool dvfs_possible_from_any_cpu;
	unsigned int cached_target_freq;
	unsigned int cached_resolved_idx;
	bool transition_ongoing;
	spinlock_t transition_lock;
	wait_queue_head_t transition_wait;
	struct task_struct *transition_task;
	struct cpufreq_stats *stats;
	void *driver_data;
	struct thermal_cooling_device *cdev;
	struct notifier_block nb_min;
	struct notifier_block nb_max;
};

struct cpufreq_governor {
	char name[16];
	int (*init)(struct cpufreq_policy *);
	void (*exit)(struct cpufreq_policy *);
	int (*start)(struct cpufreq_policy *);
	void (*stop)(struct cpufreq_policy *);
	void (*limits)(struct cpufreq_policy *);
	ssize_t (*show_setspeed)(struct cpufreq_policy *, char *);
	int (*store_setspeed)(struct cpufreq_policy *, unsigned int);
	struct list_head governor_list;
	struct module *owner;
	u8 flags;
};

struct cpufreq_frequency_table {
	unsigned int flags;
	unsigned int driver_data;
	unsigned int frequency;
};

struct trace_event_raw_cpu {
	struct trace_entry ent;
	u32 state;
	u32 cpu_id;
	char __data[0];
};

struct trace_event_raw_cpu_idle_miss {
	struct trace_entry ent;
	u32 cpu_id;
	u32 state;
	bool below;
	char __data[0];
};

struct trace_event_raw_powernv_throttle {
	struct trace_entry ent;
	int chip_id;
	u32 __data_loc_reason;
	int pmax;
	char __data[0];
};

struct trace_event_raw_pstate_sample {
	struct trace_entry ent;
	u32 core_busy;
	u32 scaled_busy;
	u32 from;
	u32 to;
	u64 mperf;
	u64 aperf;
	u64 tsc;
	u32 freq;
	u32 io_boost;
	char __data[0];
};

struct trace_event_raw_cpu_frequency_limits {
	struct trace_entry ent;
	u32 min_freq;
	u32 max_freq;
	u32 cpu_id;
	char __data[0];
};

struct trace_event_raw_device_pm_callback_start {
	struct trace_entry ent;
	u32 __data_loc_device;
	u32 __data_loc_driver;
	u32 __data_loc_parent;
	u32 __data_loc_pm_ops;
	int event;
	char __data[0];
};

struct trace_event_raw_device_pm_callback_end {
	struct trace_entry ent;
	u32 __data_loc_device;
	u32 __data_loc_driver;
	int error;
	char __data[0];
};

struct trace_event_raw_suspend_resume {
	struct trace_entry ent;
	const char *action;
	int val;
	bool start;
	char __data[0];
};

struct trace_event_raw_wakeup_source {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	char __data[0];
};

struct trace_event_raw_clock {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	u64 cpu_id;
	char __data[0];
};

struct trace_event_raw_power_domain {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	u64 cpu_id;
	char __data[0];
};

struct trace_event_raw_cpu_latency_qos_request {
	struct trace_entry ent;
	s32 value;
	char __data[0];
};

struct trace_event_raw_pm_qos_update {
	struct trace_entry ent;
	enum pm_qos_req_action action;
	int prev_value;
	int curr_value;
	char __data[0];
};

struct trace_event_raw_dev_pm_qos_request {
	struct trace_entry ent;
	u32 __data_loc_name;
	enum dev_pm_qos_req_type type;
	s32 new_value;
	char __data[0];
};

struct trace_event_raw_guest_halt_poll_ns {
	struct trace_entry ent;
	bool grow;
	unsigned int new;
	unsigned int old;
	char __data[0];
};

struct trace_event_data_offsets_cpu {};

struct trace_event_data_offsets_cpu_idle_miss {};

struct trace_event_data_offsets_powernv_throttle {
	u32 reason;
};

struct trace_event_data_offsets_pstate_sample {};

struct trace_event_data_offsets_cpu_frequency_limits {};

struct trace_event_data_offsets_device_pm_callback_start {
	u32 device;
	u32 driver;
	u32 parent;
	u32 pm_ops;
};

struct trace_event_data_offsets_device_pm_callback_end {
	u32 device;
	u32 driver;
};

struct trace_event_data_offsets_suspend_resume {};

struct trace_event_data_offsets_wakeup_source {
	u32 name;
};

struct trace_event_data_offsets_clock {
	u32 name;
};

struct trace_event_data_offsets_power_domain {
	u32 name;
};

struct trace_event_data_offsets_cpu_latency_qos_request {};

struct trace_event_data_offsets_pm_qos_update {};

struct trace_event_data_offsets_dev_pm_qos_request {
	u32 name;
};

struct trace_event_data_offsets_guest_halt_poll_ns {};

typedef void (*btf_trace_cpu_idle)(void *, unsigned int, unsigned int);

typedef void (*btf_trace_cpu_idle_miss)(void *, unsigned int, unsigned int, bool);

typedef void (*btf_trace_powernv_throttle)(void *, int, const char *, int);

typedef void (*btf_trace_pstate_sample)(void *, u32, u32, u32, u32, u64, u64, u64, u32, u32);

typedef void (*btf_trace_cpu_frequency)(void *, unsigned int, unsigned int);

typedef void (*btf_trace_cpu_frequency_limits)(void *, struct cpufreq_policy *);

typedef void (*btf_trace_device_pm_callback_start)(void *, struct device *, const char *, int);

typedef void (*btf_trace_device_pm_callback_end)(void *, struct device *, int);

typedef void (*btf_trace_suspend_resume)(void *, const char *, int, bool);

typedef void (*btf_trace_wakeup_source_activate)(void *, const char *, unsigned int);

typedef void (*btf_trace_wakeup_source_deactivate)(void *, const char *, unsigned int);

typedef void (*btf_trace_clock_enable)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_clock_disable)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_clock_set_rate)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_power_domain_target)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_pm_qos_add_request)(void *, s32);

typedef void (*btf_trace_pm_qos_update_request)(void *, s32);

typedef void (*btf_trace_pm_qos_remove_request)(void *, s32);

typedef void (*btf_trace_pm_qos_update_target)(void *, enum pm_qos_req_action, int, int);

typedef void (*btf_trace_pm_qos_update_flags)(void *, enum pm_qos_req_action, int, int);

typedef void (*btf_trace_dev_pm_qos_add_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

typedef void (*btf_trace_dev_pm_qos_update_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

typedef void (*btf_trace_dev_pm_qos_remove_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

typedef void (*btf_trace_guest_halt_poll_ns)(void *, bool, unsigned int, unsigned int);

union bpf_iter_link_info {
	struct {
		__u32 map_fd;
	} map;
	struct {
		enum bpf_cgroup_iter_order order;
		__u32 cgroup_fd;
		__u64 cgroup_id;
	} cgroup;
	struct {
		__u32 tid;
		__u32 pid;
		__u32 pid_fd;
	} task;
};

struct bpf_iter_num {
	__u64 __opaque[1];
};

struct bpf_link_primer {
	struct bpf_link *link;
	struct file *file;
	int fd;
	u32 id;
};

enum {
	BPF_MAX_LOOPS = 8388608,
};

typedef int (*bpf_iter_attach_target_t)(struct bpf_prog *, union bpf_iter_link_info *, struct bpf_iter_aux_info *);

typedef void (*bpf_iter_detach_target_t)(struct bpf_iter_aux_info *);

typedef void (*bpf_iter_show_fdinfo_t)(const struct bpf_iter_aux_info *, struct seq_file *);

typedef int (*bpf_iter_fill_link_info_t)(const struct bpf_iter_aux_info *, struct bpf_link_info *);

typedef const struct bpf_func_proto * (*bpf_iter_get_func_proto_t)(enum bpf_func_id, const struct bpf_prog *);

enum bpf_iter_feature {
	BPF_ITER_RESCHED = 1,
};

struct bpf_iter_reg {
	const char *target;
	bpf_iter_attach_target_t attach_target;
	bpf_iter_detach_target_t detach_target;
	bpf_iter_show_fdinfo_t show_fdinfo;
	bpf_iter_fill_link_info_t fill_link_info;
	bpf_iter_get_func_proto_t get_func_proto;
	u32 ctx_arg_info_size;
	u32 feature;
	struct bpf_ctx_arg_aux ctx_arg_info[2];
	const struct bpf_iter_seq_info *seq_info;
};

struct bpf_iter_meta {
	union {
		struct seq_file *seq;
	};
	u64 session_id;
	u64 seq_num;
};

struct bpf_iter_target_info {
	struct list_head list;
	const struct bpf_iter_reg *reg_info;
	u32 btf_id;
};

struct bpf_iter_link {
	struct bpf_link link;
	struct bpf_iter_aux_info aux;
	struct bpf_iter_target_info *tinfo;
};

struct bpf_iter_priv_data {
	struct bpf_iter_target_info *tinfo;
	const struct bpf_iter_seq_info *seq_info;
	struct bpf_prog *prog;
	u64 session_id;
	u64 seq_num;
	bool done_stop;
	long: 0;
	u8 target_private[0];
};

typedef u64 (*btf_bpf_for_each_map_elem)(struct bpf_map *, void *, void *, u64);

typedef u64 (*btf_bpf_loop)(u32, void *, void *, u64);

struct bpf_iter_num_kern {
	int cur;
	int end;
};

struct btf_iter_num;

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
};

enum {
	BPF_F_NO_PREALLOC = 1,
	BPF_F_NO_COMMON_LRU = 2,
	BPF_F_NUMA_NODE = 4,
	BPF_F_RDONLY = 8,
	BPF_F_WRONLY = 16,
	BPF_F_STACK_BUILD_ID = 32,
	BPF_F_ZERO_SEED = 64,
	BPF_F_RDONLY_PROG = 128,
	BPF_F_WRONLY_PROG = 256,
	BPF_F_CLONE = 512,
	BPF_F_MMAPABLE = 1024,
	BPF_F_PRESERVE_ELEMS = 2048,
	BPF_F_INNER_MAP = 4096,
	BPF_F_LINK = 8192,
};

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};

struct bpf_mem_caches;

struct bpf_mem_cache;

struct bpf_mem_alloc {
	struct bpf_mem_caches *caches;
	struct bpf_mem_cache *cache;
	struct work_struct work;
};

struct bpf_iter__bpf_map_elem {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_map *map;
	};
	union {
		void *key;
	};
	union {
		void *value;
	};
};

struct pcpu_freelist_node;

struct pcpu_freelist_head {
	struct pcpu_freelist_node *first;
	raw_spinlock_t lock;
};

struct pcpu_freelist_node {
	struct pcpu_freelist_node *next;
};

struct pcpu_freelist {
	struct pcpu_freelist_head *freelist;
	struct pcpu_freelist_head extralist;
};

struct bpf_lru_node {
	struct list_head list;
	u16 cpu;
	u8 type;
	u8 ref;
};

struct bpf_lru_list {
	struct list_head lists[3];
	unsigned int counts[2];
	struct list_head *next_inactive_rotation;
	raw_spinlock_t lock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct bpf_lru_locallist {
	struct list_head lists[2];
	u16 next_steal;
	raw_spinlock_t lock;
};

struct bpf_common_lru {
	struct bpf_lru_list lru_list;
	struct bpf_lru_locallist *local_list;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef bool (*del_from_htab_func)(void *, struct bpf_lru_node *);

struct bpf_lru {
	union {
		struct bpf_common_lru common_lru;
		struct bpf_lru_list *percpu_lru;
	};
	del_from_htab_func del_from_htab;
	void *del_arg;
	unsigned int hash_offset;
	unsigned int nr_scans;
	bool percpu;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct bucket {
	struct hlist_nulls_head head;
	raw_spinlock_t raw_lock;
};

struct htab_elem;

struct bpf_htab {
	struct bpf_map map;
	struct bpf_mem_alloc ma;
	struct bpf_mem_alloc pcpu_ma;
	struct bucket *buckets;
	void *elems;
	long: 64;
	long: 64;
	union {
		struct pcpu_freelist freelist;
		struct bpf_lru lru;
	};
	struct htab_elem **extra_elems;
	struct percpu_counter pcount;
	atomic_t count;
	bool use_percpu_counter;
	u32 n_buckets;
	u32 elem_size;
	u32 hashrnd;
	struct lock_class_key lockdep_key;
	int *map_locked[8];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct htab_elem {
	union {
		struct hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct pcpu_freelist_node fnode;
				struct htab_elem *batch_flink;
			};
		};
	};
	union {
		void *ptr_to_pptr;
		struct bpf_lru_node lru_node;
	};
	u32 hash;
	long: 0;
	char key[0];
};

struct bpf_iter_seq_hash_map_info {
	struct bpf_map *map;
	struct bpf_htab *htab;
	void *percpu_value_buf;
	u32 bucket_id;
	u32 skip_elems;
};

enum vm_fault_reason {
	VM_FAULT_OOM = 1,
	VM_FAULT_SIGBUS = 2,
	VM_FAULT_MAJOR = 4,
	VM_FAULT_HWPOISON = 16,
	VM_FAULT_HWPOISON_LARGE = 32,
	VM_FAULT_SIGSEGV = 64,
	VM_FAULT_NOPAGE = 256,
	VM_FAULT_LOCKED = 512,
	VM_FAULT_RETRY = 1024,
	VM_FAULT_FALLBACK = 2048,
	VM_FAULT_DONE_COW = 4096,
	VM_FAULT_NEEDDSYNC = 8192,
	VM_FAULT_COMPLETED = 16384,
	VM_FAULT_HINDEX_MASK = 983040,
};

struct cpu_topology {
	int thread_id;
	int core_id;
	int cluster_id;
	int package_id;
	cpumask_t thread_sibling;
	cpumask_t core_sibling;
	cpumask_t cluster_sibling;
	cpumask_t llc_sibling;
};

enum perf_event_task_context {
	perf_invalid_context = -1,
	perf_hw_context = 0,
	perf_sw_context = 1,
	perf_nr_task_contexts = 2,
};

enum perf_event_sample_format {
	PERF_SAMPLE_IP = 1,
	PERF_SAMPLE_TID = 2,
	PERF_SAMPLE_TIME = 4,
	PERF_SAMPLE_ADDR = 8,
	PERF_SAMPLE_READ = 16,
	PERF_SAMPLE_CALLCHAIN = 32,
	PERF_SAMPLE_ID = 64,
	PERF_SAMPLE_CPU = 128,
	PERF_SAMPLE_PERIOD = 256,
	PERF_SAMPLE_STREAM_ID = 512,
	PERF_SAMPLE_RAW = 1024,
	PERF_SAMPLE_BRANCH_STACK = 2048,
	PERF_SAMPLE_REGS_USER = 4096,
	PERF_SAMPLE_STACK_USER = 8192,
	PERF_SAMPLE_WEIGHT = 16384,
	PERF_SAMPLE_DATA_SRC = 32768,
	PERF_SAMPLE_IDENTIFIER = 65536,
	PERF_SAMPLE_TRANSACTION = 131072,
	PERF_SAMPLE_REGS_INTR = 262144,
	PERF_SAMPLE_PHYS_ADDR = 524288,
	PERF_SAMPLE_AUX = 1048576,
	PERF_SAMPLE_CGROUP = 2097152,
	PERF_SAMPLE_DATA_PAGE_SIZE = 4194304,
	PERF_SAMPLE_CODE_PAGE_SIZE = 8388608,
	PERF_SAMPLE_WEIGHT_STRUCT = 16777216,
	PERF_SAMPLE_MAX = 33554432,
};

enum perf_branch_sample_type {
	PERF_SAMPLE_BRANCH_USER = 1,
	PERF_SAMPLE_BRANCH_KERNEL = 2,
	PERF_SAMPLE_BRANCH_HV = 4,
	PERF_SAMPLE_BRANCH_ANY = 8,
	PERF_SAMPLE_BRANCH_ANY_CALL = 16,
	PERF_SAMPLE_BRANCH_ANY_RETURN = 32,
	PERF_SAMPLE_BRANCH_IND_CALL = 64,
	PERF_SAMPLE_BRANCH_ABORT_TX = 128,
	PERF_SAMPLE_BRANCH_IN_TX = 256,
	PERF_SAMPLE_BRANCH_NO_TX = 512,
	PERF_SAMPLE_BRANCH_COND = 1024,
	PERF_SAMPLE_BRANCH_CALL_STACK = 2048,
	PERF_SAMPLE_BRANCH_IND_JUMP = 4096,
	PERF_SAMPLE_BRANCH_CALL = 8192,
	PERF_SAMPLE_BRANCH_NO_FLAGS = 16384,
	PERF_SAMPLE_BRANCH_NO_CYCLES = 32768,
	PERF_SAMPLE_BRANCH_TYPE_SAVE = 65536,
	PERF_SAMPLE_BRANCH_HW_INDEX = 131072,
	PERF_SAMPLE_BRANCH_PRIV_SAVE = 262144,
	PERF_SAMPLE_BRANCH_MAX = 524288,
};

enum perf_sample_regs_abi {
	PERF_SAMPLE_REGS_ABI_NONE = 0,
	PERF_SAMPLE_REGS_ABI_32 = 1,
	PERF_SAMPLE_REGS_ABI_64 = 2,
};

enum perf_event_read_format {
	PERF_FORMAT_TOTAL_TIME_ENABLED = 1,
	PERF_FORMAT_TOTAL_TIME_RUNNING = 2,
	PERF_FORMAT_ID = 4,
	PERF_FORMAT_GROUP = 8,
	PERF_FORMAT_LOST = 16,
	PERF_FORMAT_MAX = 32,
};

enum perf_event_ioc_flags {
	PERF_IOC_FLAG_GROUP = 1,
};

struct perf_event_mmap_page {
	__u32 version;
	__u32 compat_version;
	__u32 lock;
	__u32 index;
	__s64 offset;
	__u64 time_enabled;
	__u64 time_running;
	union {
		__u64 capabilities;
		struct {
			__u64 cap_bit0: 1;
			__u64 cap_bit0_is_deprecated: 1;
			__u64 cap_user_rdpmc: 1;
			__u64 cap_user_time: 1;
			__u64 cap_user_time_zero: 1;
			__u64 cap_user_time_short: 1;
			__u64 cap_____res: 58;
		};
	};
	__u16 pmc_width;
	__u16 time_shift;
	__u32 time_mult;
	__u64 time_offset;
	__u64 time_zero;
	__u32 size;
	__u32 __reserved_1;
	__u64 time_cycles;
	__u64 time_mask;
	__u8 __reserved[928];
	__u64 data_head;
	__u64 data_tail;
	__u64 data_offset;
	__u64 data_size;
	__u64 aux_head;
	__u64 aux_tail;
	__u64 aux_offset;
	__u64 aux_size;
};

struct perf_event_header {
	__u32 type;
	__u16 misc;
	__u16 size;
};

struct perf_ns_link_info {
	__u64 dev;
	__u64 ino;
};

enum {
	NET_NS_INDEX = 0,
	UTS_NS_INDEX = 1,
	IPC_NS_INDEX = 2,
	PID_NS_INDEX = 3,
	USER_NS_INDEX = 4,
	MNT_NS_INDEX = 5,
	CGROUP_NS_INDEX = 6,
	NR_NAMESPACES = 7,
};

enum perf_event_type {
	PERF_RECORD_MMAP = 1,
	PERF_RECORD_LOST = 2,
	PERF_RECORD_COMM = 3,
	PERF_RECORD_EXIT = 4,
	PERF_RECORD_THROTTLE = 5,
	PERF_RECORD_UNTHROTTLE = 6,
	PERF_RECORD_FORK = 7,
	PERF_RECORD_READ = 8,
	PERF_RECORD_SAMPLE = 9,
	PERF_RECORD_MMAP2 = 10,
	PERF_RECORD_AUX = 11,
	PERF_RECORD_ITRACE_START = 12,
	PERF_RECORD_LOST_SAMPLES = 13,
	PERF_RECORD_SWITCH = 14,
	PERF_RECORD_SWITCH_CPU_WIDE = 15,
	PERF_RECORD_NAMESPACES = 16,
	PERF_RECORD_KSYMBOL = 17,
	PERF_RECORD_BPF_EVENT = 18,
	PERF_RECORD_CGROUP = 19,
	PERF_RECORD_TEXT_POKE = 20,
	PERF_RECORD_AUX_OUTPUT_HW_ID = 21,
	PERF_RECORD_MAX = 22,
};

enum perf_bpf_event_type {
	PERF_BPF_EVENT_UNKNOWN = 0,
	PERF_BPF_EVENT_PROG_LOAD = 1,
	PERF_BPF_EVENT_PROG_UNLOAD = 2,
	PERF_BPF_EVENT_MAX = 3,
};

typedef struct user_pt_regs bpf_user_pt_regs_t;

enum perf_event_arm_regs {
	PERF_REG_ARM64_X0 = 0,
	PERF_REG_ARM64_X1 = 1,
	PERF_REG_ARM64_X2 = 2,
	PERF_REG_ARM64_X3 = 3,
	PERF_REG_ARM64_X4 = 4,
	PERF_REG_ARM64_X5 = 5,
	PERF_REG_ARM64_X6 = 6,
	PERF_REG_ARM64_X7 = 7,
	PERF_REG_ARM64_X8 = 8,
	PERF_REG_ARM64_X9 = 9,
	PERF_REG_ARM64_X10 = 10,
	PERF_REG_ARM64_X11 = 11,
	PERF_REG_ARM64_X12 = 12,
	PERF_REG_ARM64_X13 = 13,
	PERF_REG_ARM64_X14 = 14,
	PERF_REG_ARM64_X15 = 15,
	PERF_REG_ARM64_X16 = 16,
	PERF_REG_ARM64_X17 = 17,
	PERF_REG_ARM64_X18 = 18,
	PERF_REG_ARM64_X19 = 19,
	PERF_REG_ARM64_X20 = 20,
	PERF_REG_ARM64_X21 = 21,
	PERF_REG_ARM64_X22 = 22,
	PERF_REG_ARM64_X23 = 23,
	PERF_REG_ARM64_X24 = 24,
	PERF_REG_ARM64_X25 = 25,
	PERF_REG_ARM64_X26 = 26,
	PERF_REG_ARM64_X27 = 27,
	PERF_REG_ARM64_X28 = 28,
	PERF_REG_ARM64_X29 = 29,
	PERF_REG_ARM64_LR = 30,
	PERF_REG_ARM64_SP = 31,
	PERF_REG_ARM64_PC = 32,
	PERF_REG_ARM64_MAX = 33,
	PERF_REG_ARM64_VG = 46,
	PERF_REG_ARM64_EXTENDED_MAX = 47,
};

enum perf_addr_filter_action_t {
	PERF_ADDR_FILTER_ACTION_STOP = 0,
	PERF_ADDR_FILTER_ACTION_START = 1,
	PERF_ADDR_FILTER_ACTION_FILTER = 2,
};

struct perf_addr_filter {
	struct list_head entry;
	struct path path;
	long unsigned int offset;
	long unsigned int size;
	enum perf_addr_filter_action_t action;
};

struct swevent_hlist {
	struct hlist_head heads[256];
	struct callback_head callback_head;
};

struct pmu_event_list {
	raw_spinlock_t lock;
	struct list_head list;
};

struct perf_buffer {
	refcount_t refcount;
	struct callback_head callback_head;
	int nr_pages;
	int overwrite;
	int paused;
	atomic_t poll;
	local_t head;
	unsigned int nest;
	local_t events;
	local_t wakeup;
	local_t lost;
	long int watermark;
	long int aux_watermark;
	spinlock_t event_lock;
	struct list_head event_list;
	atomic_t mmap_count;
	long unsigned int mmap_locked;
	struct user_struct *mmap_user;
	long int aux_head;
	unsigned int aux_nest;
	long int aux_wakeup;
	long unsigned int aux_pgoff;
	int aux_nr_pages;
	int aux_overwrite;
	atomic_t aux_mmap_count;
	long unsigned int aux_mmap_locked;
	void (*free_aux)(void *);
	refcount_t aux_refcount;
	int aux_in_sampling;
	void **aux_pages;
	void *aux_priv;
	struct perf_event_mmap_page *user_page;
	void *data_pages[0];
};

struct perf_cpu_context {
	struct perf_event_context ctx;
	struct perf_event_context *task_ctx;
	int online;
	int heap_size;
	struct perf_event **heap;
	struct perf_event *heap_default[2];
};

struct bpf_perf_event_data_kern {
	bpf_user_pt_regs_t *regs;
	struct perf_sample_data *data;
	struct perf_event *event;
};

struct perf_pmu_events_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str;
};

struct min_heap {
	void *data;
	int nr;
	int size;
};

struct min_heap_callbacks {
	int elem_size;
	bool (*less)(const void *, const void *);
	void (*swp)(void *, void *);
};

typedef int (*remote_function_f)(void *);

struct remote_function_call {
	struct task_struct *p;
	remote_function_f func;
	void *info;
	int ret;
};

typedef void (*event_f)(struct perf_event *, struct perf_cpu_context *, struct perf_event_context *, void *);

struct event_function_struct {
	struct perf_event *event;
	event_f func;
	void *data;
};

enum event_type_t {
	EVENT_FLEXIBLE = 1,
	EVENT_PINNED = 2,
	EVENT_TIME = 4,
	EVENT_CPU = 8,
	EVENT_ALL = 3,
};

struct __group_key {
	int cpu;
	struct pmu *pmu;
	struct cgroup *cgroup;
};

struct stop_event_data {
	struct perf_event *event;
	unsigned int restart;
};

struct perf_read_data {
	struct perf_event *event;
	bool group;
	int ret;
};

struct perf_read_event {
	struct perf_event_header header;
	u32 pid;
	u32 tid;
};

typedef void perf_iterate_f(struct perf_event *, void *);

struct remote_output {
	struct perf_buffer *rb;
	int err;
};

struct perf_task_event {
	struct task_struct *task;
	struct perf_event_context *task_ctx;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 ppid;
		u32 tid;
		u32 ptid;
		u64 time;
	} event_id;
};

struct perf_comm_event {
	struct task_struct *task;
	char *comm;
	int comm_size;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
	} event_id;
};

struct perf_namespaces_event {
	struct task_struct *task;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
		u64 nr_namespaces;
		struct perf_ns_link_info link_info[7];
	} event_id;
};

struct perf_mmap_event {
	struct vm_area_struct *vma;
	const char *file_name;
	int file_size;
	int maj;
	int min;
	u64 ino;
	u64 ino_generation;
	u32 prot;
	u32 flags;
	u8 build_id[20];
	u32 build_id_size;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
		u64 start;
		u64 len;
		u64 pgoff;
	} event_id;
};

struct perf_switch_event {
	struct task_struct *task;
	struct task_struct *next_prev;
	struct {
		struct perf_event_header header;
		u32 next_prev_pid;
		u32 next_prev_tid;
	} event_id;
};

struct perf_ksymbol_event {
	const char *name;
	int name_len;
	struct {
		struct perf_event_header header;
		u64 addr;
		u32 len;
		u16 ksym_type;
		u16 flags;
	} event_id;
};

struct perf_bpf_event {
	struct bpf_prog *prog;
	struct {
		struct perf_event_header header;
		u16 type;
		u16 flags;
		u32 id;
		u8 tag[8];
	} event_id;
};

struct perf_text_poke_event {
	const void *old_bytes;
	const void *new_bytes;
	size_t pad;
	u16 old_len;
	u16 new_len;
	struct {
		struct perf_event_header header;
		u64 addr;
	} event_id;
};

struct swevent_htable {
	struct swevent_hlist *swevent_hlist;
	struct mutex hlist_mutex;
	int hlist_refcount;
	int recursion[4];
};

enum perf_probe_config {
	PERF_PROBE_CONFIG_IS_RETPROBE = 1,
	PERF_UPROBE_REF_CTR_OFFSET_BITS = 32,
	PERF_UPROBE_REF_CTR_OFFSET_SHIFT = 32,
};

enum {
	IF_ACT_NONE = -1,
	IF_ACT_FILTER = 0,
	IF_ACT_START = 1,
	IF_ACT_STOP = 2,
	IF_SRC_FILE = 3,
	IF_SRC_KERNEL = 4,
	IF_SRC_FILEADDR = 5,
	IF_SRC_KERNELADDR = 6,
};

enum {
	IF_STATE_ACTION = 0,
	IF_STATE_SOURCE = 1,
	IF_STATE_END = 2,
};

struct perf_aux_event {
	struct perf_event_header header;
	u64 hw_id;
};

struct perf_aux_event___2 {
	struct perf_event_header header;
	u32 pid;
	u32 tid;
};

struct perf_aux_event___3 {
	struct perf_event_header header;
	u64 offset;
	u64 size;
	u64 flags;
};

struct dma_block {
	struct dma_block *next_block;
	dma_addr_t dma;
};

struct dma_pool {
	struct list_head page_list;
	spinlock_t lock;
	struct dma_block *next_block;
	size_t nr_blocks;
	size_t nr_active;
	size_t nr_pages;
	struct device *dev;
	unsigned int size;
	unsigned int allocation;
	unsigned int boundary;
	char name[32];
	struct list_head pools;
};

struct dma_page {
	struct list_head page_list;
	void *vaddr;
	dma_addr_t dma;
};

typedef __kernel_long_t __kernel_off_t;

typedef __kernel_off_t off_t;

struct pipe_buffer;

struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	bool poll_usage;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
};

enum iter_type {
	ITER_IOVEC = 0,
	ITER_KVEC = 1,
	ITER_BVEC = 2,
	ITER_XARRAY = 3,
	ITER_DISCARD = 4,
	ITER_UBUF = 5,
};

enum {
	IOPRIO_CLASS_NONE = 0,
	IOPRIO_CLASS_RT = 1,
	IOPRIO_CLASS_BE = 2,
	IOPRIO_CLASS_IDLE = 3,
};

typedef int __kernel_rwf_t;

typedef __kernel_rwf_t rwf_t;

struct pipe_buf_operations;

struct pipe_buffer {
	struct page *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations {
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

enum dentry_d_lock_class {
	DENTRY_D_LOCK_NORMAL = 0,
	DENTRY_D_LOCK_NESTED = 1,
};

enum lru_status {
	LRU_REMOVED = 0,
	LRU_REMOVED_RETRY = 1,
	LRU_ROTATE = 2,
	LRU_SKIP = 3,
	LRU_RETRY = 4,
};

typedef enum lru_status (*list_lru_walk_cb)(struct list_head *, struct list_lru_one *, spinlock_t *, void *);

struct mount;

struct mnt_namespace {
	struct ns_common ns;
	struct mount *root;
	struct list_head list;
	spinlock_t ns_lock;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	u64 seq;
	wait_queue_head_t poll;
	u64 event;
	unsigned int mounts;
	unsigned int pending_mounts;
};

struct mnt_pcp;

struct mountpoint;

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct callback_head mnt_rcu;
		struct llist_node mnt_llist;
	};
	struct mnt_pcp *mnt_pcp;
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	struct list_head mnt_instance;
	const char *mnt_devname;
	struct list_head mnt_list;
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct mount *mnt_master;
	struct mnt_namespace *mnt_ns;
	struct mountpoint *mnt_mp;
	union {
		struct hlist_node mnt_mp_list;
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting;
	int mnt_id;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

struct external_name {
	union {
		atomic_t count;
		struct callback_head head;
	} u;
	unsigned char name[0];
};

enum d_walk_ret {
	D_WALK_CONTINUE = 0,
	D_WALK_QUIT = 1,
	D_WALK_NORETRY = 2,
	D_WALK_SKIP = 3,
};

struct check_mount {
	struct vfsmount *mnt;
	unsigned int mounted;
};

struct select_data {
	struct dentry *start;
	union {
		long int found;
		struct dentry *victim;
	};
	struct list_head dispose;
};

struct va_format {
	const char *fmt;
	va_list *va;
};

struct constant_table {
	const char *name;
	int value;
};

enum legacy_fs_param {
	LEGACY_FS_UNSET_PARAMS = 0,
	LEGACY_FS_MONOLITHIC_PARAMS = 1,
	LEGACY_FS_INDIVIDUAL_PARAMS = 2,
};

struct legacy_fs_context {
	char *legacy_data;
	size_t data_size;
	enum legacy_fs_param param_type;
};

typedef int (*list_cmp_func_t)(void *, const struct list_head *, const struct list_head *);

typedef unsigned int iov_iter_extraction_t;

struct iov_iter_state {
	size_t iov_offset;
	size_t count;
	long unsigned int nr_segs;
};

struct csum_state {
	__wsum csum;
	size_t off;
};

typedef u32 compat_size_t;

typedef s32 compat_ssize_t;

typedef u32 compat_uptr_t;

struct compat_iovec {
	compat_uptr_t iov_base;
	compat_size_t iov_len;
};

typedef u16 ucs2_char_t;

typedef phys_addr_t resource_size_t;

struct resource {
	resource_size_t start;
	resource_size_t end;
	const char *name;
	long unsigned int flags;
	long unsigned int desc;
	struct resource *parent;
	struct resource *sibling;
	struct resource *child;
};

struct pdev_archdata {};

struct platform_device_id {
	char name[20];
	kernel_ulong_t driver_data;
};

struct mfd_cell;

struct platform_device {
	const char *name;
	int id;
	bool id_auto;
	struct device dev;
	u64 platform_dma_mask;
	struct device_dma_parameters dma_parms;
	u32 num_resources;
	struct resource *resource;
	const struct platform_device_id *id_entry;
	const char *driver_override;
	struct mfd_cell *mfd_cell;
	struct pdev_archdata archdata;
};

typedef int (*of_irq_init_cb_t)(struct device_node *, struct device_node *);

enum kobject_action {
	KOBJ_ADD = 0,
	KOBJ_REMOVE = 1,
	KOBJ_CHANGE = 2,
	KOBJ_MOVE = 3,
	KOBJ_ONLINE = 4,
	KOBJ_OFFLINE = 5,
	KOBJ_BIND = 6,
	KOBJ_UNBIND = 7,
};

enum rpm_status {
	RPM_INVALID = -1,
	RPM_ACTIVE = 0,
	RPM_RESUMING = 1,
	RPM_SUSPENDED = 2,
	RPM_SUSPENDING = 3,
};

struct iommu_group {};

struct amba_id {
	unsigned int id;
	unsigned int mask;
	void *data;
};

struct amba_cs_uci_id {
	unsigned int devarch;
	unsigned int devarch_mask;
	unsigned int devtype;
	void *data;
};

struct amba_device {
	struct device dev;
	struct resource res;
	struct clk *pclk;
	struct device_dma_parameters dma_parms;
	unsigned int periphid;
	struct mutex periphid_lock;
	unsigned int cid;
	struct amba_cs_uci_id uci;
	unsigned int irq[9];
	const char *driver_override;
};

struct amba_driver {
	struct device_driver drv;
	int (*probe)(struct amba_device *, const struct amba_id *);
	void (*remove)(struct amba_device *);
	void (*shutdown)(struct amba_device *);
	const struct amba_id *id_table;
	bool driver_managed_dma;
};

struct reset_control;

struct acpi_device;

struct of_phandle_args {
	struct device_node *np;
	int args_count;
	uint32_t args[16];
};

struct gpio_desc;

enum gpiod_flags {
	GPIOD_ASIS = 0,
	GPIOD_IN = 1,
	GPIOD_OUT_LOW = 3,
	GPIOD_OUT_HIGH = 7,
	GPIOD_OUT_LOW_OPEN_DRAIN = 11,
	GPIOD_OUT_HIGH_OPEN_DRAIN = 15,
};

struct platform_driver {
	int (*probe)(struct platform_device *);
	int (*remove)(struct platform_device *);
	void (*remove_new)(struct platform_device *);
	void (*shutdown)(struct platform_device *);
	int (*suspend)(struct platform_device *, pm_message_t);
	int (*resume)(struct platform_device *);
	struct device_driver driver;
	const struct platform_device_id *id_table;
	bool prevent_deferred_probe;
	bool driver_managed_dma;
};

struct clk_gpio {
	struct clk_hw hw;
	struct gpio_desc *gpiod;
};

typedef void (*exitcall_t)();

typedef u64 async_cookie_t;

typedef void (*async_func_t)(void *, async_cookie_t);

struct device_attach_data {
	struct device *dev;
	bool check_async;
	bool want_async;
	bool have_async;
};

struct attribute_container {
	struct list_head node;
	struct klist containers;
	struct class *class;
	const struct attribute_group *grp;
	struct device_attribute **attrs;
	int (*match)(struct attribute_container *, struct device *);
	long unsigned int flags;
};

struct transport_container;

struct transport_class {
	struct class class;
	int (*setup)(struct transport_container *, struct device *, struct device *);
	int (*configure)(struct transport_container *, struct device *, struct device *);
	int (*remove)(struct transport_container *, struct device *, struct device *);
};

struct transport_container {
	struct attribute_container ac;
	const struct attribute_group *statistics;
};

struct anon_transport_class {
	struct transport_class tclass;
	struct attribute_container container;
};

struct trace_event_raw_devres {
	struct trace_entry ent;
	u32 __data_loc_devname;
	struct device *dev;
	const char *op;
	void *node;
	const char *name;
	size_t size;
	char __data[0];
};

struct trace_event_data_offsets_devres {
	u32 devname;
};

typedef void (*btf_trace_devres_log)(void *, struct device *, const char *, void *, const char *, size_t);

typedef __u64 __le64;

struct midr_range {
	u32 model;
	u32 rv_min;
	u32 rv_max;
};

struct cyclecounter {
	u64 (*read)(const struct cyclecounter *);
	u64 mask;
	u32 mult;
	u32 shift;
};

struct timecounter {
	const struct cyclecounter *cc;
	u64 cycle_last;
	u64 nsec;
	u64 mask;
	u64 frac;
};

enum arch_timer_reg {
	ARCH_TIMER_REG_CTRL = 0,
	ARCH_TIMER_REG_CVAL = 1,
};

enum arch_timer_ppi_nr {
	ARCH_TIMER_PHYS_SECURE_PPI = 0,
	ARCH_TIMER_PHYS_NONSECURE_PPI = 1,
	ARCH_TIMER_VIRT_PPI = 2,
	ARCH_TIMER_HYP_PPI = 3,
	ARCH_TIMER_HYP_VIRT_PPI = 4,
	ARCH_TIMER_MAX_TIMER_PPI = 5,
};

enum arch_timer_spi_nr {
	ARCH_TIMER_PHYS_SPI = 0,
	ARCH_TIMER_VIRT_SPI = 1,
	ARCH_TIMER_MAX_TIMER_SPI = 2,
};

struct arch_timer_kvm_info {
	struct timecounter timecounter;
	int virtual_irq;
	int physical_irq;
};

struct arch_timer_mem_frame {
	bool valid;
	phys_addr_t cntbase;
	size_t size;
	int phys_irq;
	int virt_irq;
};

struct arch_timer_mem {
	phys_addr_t cntctlbase;
	size_t size;
	struct arch_timer_mem_frame frame[8];
};

enum arch_timer_erratum_match_type {
	ate_match_dt = 0,
	ate_match_local_cap_id = 1,
	ate_match_acpi_oem_info = 2,
};

struct arch_timer_erratum_workaround {
	enum arch_timer_erratum_match_type match_type;
	const void *id;
	const char *desc;
	u64 (*read_cntpct_el0)();
	u64 (*read_cntvct_el0)();
	int (*set_next_event_phys)(long unsigned int, struct clock_event_device *);
	int (*set_next_event_virt)(long unsigned int, struct clock_event_device *);
	bool disable_compat_vdso;
};

typedef int (*of_init_fn_1_ret)(struct device_node *);

struct acpi_table_header {
	char signature[4];
	u32 length;
	u8 revision;
	u8 checksum;
	char oem_id[6];
	char oem_table_id[8];
	u32 oem_revision;
	char asl_compiler_id[4];
	u32 asl_compiler_revision;
};

enum arm_smccc_conduit {
	SMCCC_CONDUIT_NONE = 0,
	SMCCC_CONDUIT_SMC = 1,
	SMCCC_CONDUIT_HVC = 2,
};

struct arm_smccc_res {
	long unsigned int a0;
	long unsigned int a1;
	long unsigned int a2;
	long unsigned int a3;
};

struct arch_timer {
	void *base;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct clock_event_device evt;
};

struct ate_acpi_oem_info {
	char oem_id[7];
	char oem_table_id[9];
	u32 oem_revision;
};

typedef bool (*ate_match_fn_t)(const struct arch_timer_erratum_workaround *, const void *);

typedef __u32 Elf32_Addr;

typedef __u16 Elf32_Half;

typedef __u32 Elf32_Off;

typedef __u32 Elf32_Word;

struct elf32_hdr {
	unsigned char e_ident[16];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
};

typedef struct elf32_hdr Elf32_Ehdr;

struct elf32_phdr {
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
};

typedef struct elf32_phdr Elf32_Phdr;

struct elf64_phdr {
	Elf64_Word p_type;
	Elf64_Word p_flags;
	Elf64_Off p_offset;
	Elf64_Addr p_vaddr;
	Elf64_Addr p_paddr;
	Elf64_Xword p_filesz;
	Elf64_Xword p_memsz;
	Elf64_Xword p_align;
};

typedef struct elf64_phdr Elf64_Phdr;

struct elf32_note {
	Elf32_Word n_namesz;
	Elf32_Word n_descsz;
	Elf32_Word n_type;
};

typedef struct elf32_note Elf32_Nhdr;

typedef u16 uint16_t;

typedef __kernel_long_t __kernel_ptrdiff_t;

typedef __u16 __le16;

typedef __kernel_ptrdiff_t ptrdiff_t;

struct tm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	long int tm_year;
	int tm_wday;
	int tm_yday;
};

struct clk {
	struct clk_core *core;
	struct device *dev;
	const char *dev_id;
	const char *con_id;
	long unsigned int min_rate;
	long unsigned int max_rate;
	unsigned int exclusive_count;
	struct hlist_node clks_node;
};

struct rtc_time {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

struct sockaddr_in6 {
	short unsigned int sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

struct ipv6_stable_secret {
	bool initialized;
	struct in6_addr secret;
};

struct ipv6_devconf {
	__s32 forwarding;
	__s32 hop_limit;
	__s32 mtu6;
	__s32 accept_ra;
	__s32 accept_redirects;
	__s32 autoconf;
	__s32 dad_transmits;
	__s32 rtr_solicits;
	__s32 rtr_solicit_interval;
	__s32 rtr_solicit_max_interval;
	__s32 rtr_solicit_delay;
	__s32 force_mld_version;
	__s32 mldv1_unsolicited_report_interval;
	__s32 mldv2_unsolicited_report_interval;
	__s32 use_tempaddr;
	__s32 temp_valid_lft;
	__s32 temp_prefered_lft;
	__s32 regen_max_retry;
	__s32 max_desync_factor;
	__s32 max_addresses;
	__s32 accept_ra_defrtr;
	__u32 ra_defrtr_metric;
	__s32 accept_ra_min_hop_limit;
	__s32 accept_ra_pinfo;
	__s32 ignore_routes_with_linkdown;
	__s32 proxy_ndp;
	__s32 accept_source_route;
	__s32 accept_ra_from_local;
	__s32 disable_ipv6;
	__s32 drop_unicast_in_l2_multicast;
	__s32 accept_dad;
	__s32 force_tllao;
	__s32 ndisc_notify;
	__s32 suppress_frag_ndisc;
	__s32 accept_ra_mtu;
	__s32 drop_unsolicited_na;
	__s32 accept_untracked_na;
	struct ipv6_stable_secret stable_secret;
	__s32 use_oif_addrs_only;
	__s32 keep_addr_on_down;
	__s32 seg6_enabled;
	__u32 enhanced_dad;
	__u32 addr_gen_mode;
	__s32 disable_policy;
	__s32 ndisc_tclass;
	__s32 rpl_seg_enabled;
	__u32 ioam6_id;
	__u32 ioam6_id_wide;
	__u8 ioam6_enabled;
	__u8 ndisc_evict_nocarrier;
	struct ctl_table_header *sysctl_header;
};

struct icmpv6_mib_device {
	atomic_long_t mibs[7];
};

struct icmpv6msg_mib_device {
	atomic_long_t mibs[512];
};

struct fib6_info;

struct ipv6_devstat {
	struct proc_dir_entry *proc_dir_entry;
	struct ipstats_mib *ipv6;
	struct icmpv6_mib_device *icmpv6dev;
	struct icmpv6msg_mib_device *icmpv6msgdev;
};

struct ifmcaddr6;

struct ifacaddr6;

struct inet6_dev {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head addr_list;
	struct ifmcaddr6 *mc_list;
	struct ifmcaddr6 *mc_tomb;
	unsigned char mc_qrv;
	unsigned char mc_gq_running;
	unsigned char mc_ifc_count;
	unsigned char mc_dad_count;
	long unsigned int mc_v1_seen;
	long unsigned int mc_qi;
	long unsigned int mc_qri;
	long unsigned int mc_maxdelay;
	struct delayed_work mc_gq_work;
	struct delayed_work mc_ifc_work;
	struct delayed_work mc_dad_work;
	struct delayed_work mc_query_work;
	struct delayed_work mc_report_work;
	struct sk_buff_head mc_query_queue;
	struct sk_buff_head mc_report_queue;
	spinlock_t mc_query_lock;
	spinlock_t mc_report_lock;
	struct mutex mc_lock;
	struct ifacaddr6 *ac_list;
	rwlock_t lock;
	refcount_t refcnt;
	__u32 if_flags;
	int dead;
	u32 desync_factor;
	struct list_head tempaddr_list;
	struct in6_addr token;
	struct neigh_parms *nd_parms;
	struct ipv6_devconf cnf;
	struct ipv6_devstat stats;
	struct timer_list rs_timer;
	__s32 rs_interval;
	__u8 rs_probes;
	long unsigned int tstamp;
	struct callback_head rcu;
	unsigned int ra_mtu;
};

struct request_sock;

struct request_sock_ops {
	int family;
	unsigned int obj_size;
	struct kmem_cache *slab;
	char *slab_name;
	int (*rtx_syn_ack)(const struct sock *, struct request_sock *);
	void (*send_ack)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*send_reset)(const struct sock *, struct sk_buff *);
	void (*destructor)(struct request_sock *);
	void (*syn_ack_timeout)(const struct request_sock *);
};

struct timewait_sock_ops {
	struct kmem_cache *twsk_slab;
	char *twsk_slab_name;
	unsigned int twsk_obj_size;
	int (*twsk_unique)(struct sock *, struct sock *, void *);
	void (*twsk_destructor)(struct sock *);
};

struct saved_syn;

struct request_sock {
	struct sock_common __req_common;
	struct request_sock *dl_next;
	u16 mss;
	u8 num_retrans;
	u8 syncookie: 1;
	u8 num_timeout: 7;
	u32 ts_recent;
	struct timer_list rsk_timer;
	const struct request_sock_ops *rsk_ops;
	struct sock *sk;
	struct saved_syn *saved_syn;
	u32 secid;
	u32 peer_secid;
	u32 timeout;
};

struct saved_syn {
	u32 mac_hdrlen;
	u32 network_hdrlen;
	u32 tcp_hdrlen;
	u8 data[0];
};

struct ip6_sf_list {
	struct ip6_sf_list *sf_next;
	struct in6_addr sf_addr;
	long unsigned int sf_count[2];
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
	struct callback_head rcu;
};

struct ifmcaddr6 {
	struct in6_addr mca_addr;
	struct inet6_dev *idev;
	struct ifmcaddr6 *next;
	struct ip6_sf_list *mca_sources;
	struct ip6_sf_list *mca_tomb;
	unsigned int mca_sfmode;
	unsigned char mca_crcount;
	long unsigned int mca_sfcount[2];
	struct delayed_work mca_work;
	unsigned int mca_flags;
	int mca_users;
	refcount_t mca_refcnt;
	long unsigned int mca_cstamp;
	long unsigned int mca_tstamp;
	struct callback_head rcu;
};

struct ifacaddr6 {
	struct in6_addr aca_addr;
	struct fib6_info *aca_rt;
	struct ifacaddr6 *aca_next;
	struct hlist_node aca_addr_lst;
	int aca_users;
	refcount_t aca_refcnt;
	long unsigned int aca_cstamp;
	long unsigned int aca_tstamp;
	struct callback_head rcu;
};

enum format_type {
	FORMAT_TYPE_NONE = 0,
	FORMAT_TYPE_WIDTH = 1,
	FORMAT_TYPE_PRECISION = 2,
	FORMAT_TYPE_CHAR = 3,
	FORMAT_TYPE_STR = 4,
	FORMAT_TYPE_PTR = 5,
	FORMAT_TYPE_PERCENT_CHAR = 6,
	FORMAT_TYPE_INVALID = 7,
	FORMAT_TYPE_LONG_LONG = 8,
	FORMAT_TYPE_ULONG = 9,
	FORMAT_TYPE_LONG = 10,
	FORMAT_TYPE_UBYTE = 11,
	FORMAT_TYPE_BYTE = 12,
	FORMAT_TYPE_USHORT = 13,
	FORMAT_TYPE_SHORT = 14,
	FORMAT_TYPE_UINT = 15,
	FORMAT_TYPE_INT = 16,
	FORMAT_TYPE_SIZE_T = 17,
	FORMAT_TYPE_PTRDIFF = 18,
};

struct printf_spec {
	unsigned int type: 8;
	int field_width: 24;
	unsigned int flags: 8;
	unsigned int base: 8;
	int precision: 16;
};

struct page_flags_fields {
	int width;
	int shift;
	int mask;
	const struct printf_spec *spec;
	const char *name;
};

struct sigcontext {
	__u64 fault_address;
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
	long: 64;
	__u8 __reserved[4096];
};

struct _aarch64_ctx {
	__u32 magic;
	__u32 size;
};

struct fpsimd_context {
	struct _aarch64_ctx head;
	__u32 fpsr;
	__u32 fpcr;
	__int128 unsigned vregs[32];
};

struct esr_context {
	struct _aarch64_ctx head;
	__u64 esr;
};

struct extra_context {
	struct _aarch64_ctx head;
	__u64 datap;
	__u32 size;
	__u32 __reserved[3];
};

struct sve_context {
	struct _aarch64_ctx head;
	__u16 vl;
	__u16 flags;
	__u16 __reserved[2];
};

struct tpidr2_context {
	struct _aarch64_ctx head;
	__u64 tpidr2;
};

struct za_context {
	struct _aarch64_ctx head;
	__u16 vl;
	__u16 __reserved[3];
};

struct zt_context {
	struct _aarch64_ctx head;
	__u16 nregs;
	__u16 __reserved[3];
};

struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	__kernel_size_t ss_size;
};

typedef struct sigaltstack stack_t;

struct siginfo {
	union {
		struct {
			int si_signo;
			int si_errno;
			int si_code;
			union __sifields _sifields;
		};
		int _si_pad[32];
	};
};

typedef struct siginfo siginfo_t;

struct ksignal {
	struct k_sigaction ka;
	kernel_siginfo_t info;
	int sig;
};

struct ucontext {
	long unsigned int uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	sigset_t uc_sigmask;
	__u8 __unused[120];
	long: 64;
	struct sigcontext uc_mcontext;
};

struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
};

struct frame_record {
	u64 fp;
	u64 lr;
};

struct rt_sigframe_user_layout {
	struct rt_sigframe *sigframe;
	struct frame_record *next_frame;
	long unsigned int size;
	long unsigned int limit;
	long unsigned int fpsimd_offset;
	long unsigned int esr_offset;
	long unsigned int sve_offset;
	long unsigned int tpidr2_offset;
	long unsigned int za_offset;
	long unsigned int zt_offset;
	long unsigned int extra_offset;
	long unsigned int end_offset;
};

struct user_ctxs {
	struct fpsimd_context *fpsimd;
	u32 fpsimd_size;
	struct sve_context *sve;
	u32 sve_size;
	struct tpidr2_context *tpidr2;
	u32 tpidr2_size;
	struct za_context *za;
	u32 za_size;
	struct zt_context *zt;
	u32 zt_size;
};

enum {
	IORES_DESC_NONE = 0,
	IORES_DESC_CRASH_KERNEL = 1,
	IORES_DESC_ACPI_TABLES = 2,
	IORES_DESC_ACPI_NV_STORAGE = 3,
	IORES_DESC_PERSISTENT_MEMORY = 4,
	IORES_DESC_PERSISTENT_MEMORY_LEGACY = 5,
	IORES_DESC_DEVICE_PRIVATE_MEMORY = 6,
	IORES_DESC_RESERVED = 7,
	IORES_DESC_SOFT_RESERVED = 8,
	IORES_DESC_CXL = 9,
};

enum {
	REGION_INTERSECTS = 0,
	REGION_DISJOINT = 1,
	REGION_MIXED = 2,
};

struct pseudo_fs_context {
	const struct super_operations *ops;
	const struct xattr_handler **xattr;
	const struct dentry_operations *dops;
	long unsigned int magic;
};

struct resource_entry {
	struct list_head node;
	struct resource *res;
	resource_size_t offset;
	struct resource __res;
};

struct resource_constraint {
	resource_size_t min;
	resource_size_t max;
	resource_size_t align;
	resource_size_t (*alignf)(void *, const struct resource *, resource_size_t, resource_size_t);
	void *alignf_data;
};

struct region_devres {
	struct resource *parent;
	resource_size_t start;
	resource_size_t n;
};

struct wq_flusher;

struct worker;

struct workqueue_attrs;

struct pool_workqueue;

struct workqueue_struct {
	struct list_head pwqs;
	struct list_head list;
	struct mutex mutex;
	int work_color;
	int flush_color;
	atomic_t nr_pwqs_to_flush;
	struct wq_flusher *first_flusher;
	struct list_head flusher_queue;
	struct list_head flusher_overflow;
	struct list_head maydays;
	struct worker *rescuer;
	int nr_drainers;
	int saved_max_active;
	struct workqueue_attrs *unbound_attrs;
	struct pool_workqueue *dfl_pwq;
	char name[24];
	struct callback_head rcu;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	unsigned int flags;
	struct pool_workqueue *cpu_pwqs;
	struct pool_workqueue *numa_pwq_tbl[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct workqueue_attrs {
	int nice;
	cpumask_var_t cpumask;
	bool no_numa;
};

struct execute_work {
	struct work_struct work;
};

enum xa_lock_type {
	XA_LOCK_IRQ = 1,
	XA_LOCK_BH = 2,
};

struct worker_pool;

struct worker {
	union {
		struct list_head entry;
		struct hlist_node hentry;
	};
	struct work_struct *current_work;
	work_func_t current_func;
	struct pool_workqueue *current_pwq;
	unsigned int current_color;
	struct list_head scheduled;
	struct task_struct *task;
	struct worker_pool *pool;
	struct list_head node;
	long unsigned int last_active;
	unsigned int flags;
	int id;
	int sleeping;
	char desc[24];
	struct workqueue_struct *rescue_wq;
	work_func_t last_func;
};

struct pool_workqueue {
	struct worker_pool *pool;
	struct workqueue_struct *wq;
	int work_color;
	int flush_color;
	int refcnt;
	int nr_in_flight[16];
	int nr_active;
	int max_active;
	struct list_head inactive_works;
	struct list_head pwqs_node;
	struct list_head mayday_node;
	struct work_struct unbound_release_work;
	struct callback_head rcu;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct worker_pool {
	raw_spinlock_t lock;
	int cpu;
	int node;
	int id;
	unsigned int flags;
	long unsigned int watchdog_ts;
	bool cpu_stall;
	int nr_running;
	struct list_head worklist;
	int nr_workers;
	int nr_idle;
	struct list_head idle_list;
	struct timer_list idle_timer;
	struct work_struct idle_cull_work;
	struct timer_list mayday_timer;
	struct hlist_head busy_hash[64];
	struct worker *manager;
	struct list_head workers;
	struct list_head dying_workers;
	struct completion *detach_completion;
	struct ida worker_ida;
	struct workqueue_attrs *attrs;
	struct hlist_node hash_node;
	int refcnt;
	struct callback_head rcu;
};

enum {
	POOL_MANAGER_ACTIVE = 1,
	POOL_DISASSOCIATED = 4,
	WORKER_DIE = 2,
	WORKER_IDLE = 4,
	WORKER_PREP = 8,
	WORKER_CPU_INTENSIVE = 64,
	WORKER_UNBOUND = 128,
	WORKER_REBOUND = 256,
	WORKER_NOT_RUNNING = 456,
	NR_STD_WORKER_POOLS = 2,
	UNBOUND_POOL_HASH_ORDER = 6,
	BUSY_WORKER_HASH_ORDER = 6,
	MAX_IDLE_WORKERS_RATIO = 4,
	IDLE_WORKER_TIMEOUT = 75000,
	MAYDAY_INITIAL_TIMEOUT = 2,
	MAYDAY_INTERVAL = 25,
	CREATE_COOLDOWN = 250,
	RESCUER_NICE_LEVEL = -20,
	HIGHPRI_NICE_LEVEL = -20,
	WQ_NAME_LEN = 24,
};

struct wq_flusher {
	struct list_head list;
	int flush_color;
	struct completion done;
};

struct trace_event_raw_workqueue_queue_work {
	struct trace_entry ent;
	void *work;
	void *function;
	u32 __data_loc_workqueue;
	int req_cpu;
	int cpu;
	char __data[0];
};

struct trace_event_raw_workqueue_activate_work {
	struct trace_entry ent;
	void *work;
	char __data[0];
};

struct trace_event_raw_workqueue_execute_start {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_workqueue_execute_end {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_data_offsets_workqueue_queue_work {
	u32 workqueue;
};

struct trace_event_data_offsets_workqueue_activate_work {};

struct trace_event_data_offsets_workqueue_execute_start {};

struct trace_event_data_offsets_workqueue_execute_end {};

typedef void (*btf_trace_workqueue_queue_work)(void *, int, struct pool_workqueue *, struct work_struct *);

typedef void (*btf_trace_workqueue_activate_work)(void *, struct work_struct *);

typedef void (*btf_trace_workqueue_execute_start)(void *, struct work_struct *);

typedef void (*btf_trace_workqueue_execute_end)(void *, struct work_struct *, work_func_t);

struct wq_barrier {
	struct work_struct work;
	struct completion done;
	struct task_struct *task;
};

struct cwt_wait {
	wait_queue_entry_t wait;
	struct work_struct *work;
};

struct apply_wqattrs_ctx {
	struct workqueue_struct *wq;
	struct workqueue_attrs *attrs;
	struct list_head list;
	struct pool_workqueue *dfl_pwq;
	struct pool_workqueue *pwq_tbl[0];
};

struct pr_cont_work_struct {
	bool comma;
	work_func_t func;
	long int ctr;
};

struct work_for_cpu {
	struct work_struct work;
	long int (*fn)(void *);
	void *arg;
	long int ret;
};

enum {
	MEMREMAP_WB = 1,
	MEMREMAP_WT = 2,
	MEMREMAP_WC = 4,
	MEMREMAP_ENC = 8,
	MEMREMAP_DEC = 16,
};

struct dma_coherent_mem {
	void *virt_base;
	dma_addr_t device_base;
	long unsigned int pfn_base;
	int size;
	long unsigned int *bitmap;
	spinlock_t spinlock;
	bool use_dev_dma_pfn_offset;
};

struct reserved_mem_ops;

struct reserved_mem {
	const char *name;
	long unsigned int fdt_node;
	long unsigned int phandle;
	const struct reserved_mem_ops *ops;
	phys_addr_t base;
	phys_addr_t size;
	void *priv;
};

struct reserved_mem_ops {
	int (*device_init)(struct reserved_mem *, struct device *);
	void (*device_release)(struct reserved_mem *, struct device *);
};

typedef int (*reservedmem_of_init_fn)(struct reserved_mem *);

typedef int (*cmp_func_t)(const void *, const void *);

struct load_info {
	const char *name;
	struct module *mod;
	Elf64_Ehdr *hdr;
	long unsigned int len;
	Elf64_Shdr *sechdrs;
	char *secstrings;
	char *strtab;
	long unsigned int symoffs;
	long unsigned int stroffs;
	long unsigned int init_typeoffs;
	long unsigned int core_typeoffs;
	bool sig_ok;
	long unsigned int mod_kallsyms_init_off;
	struct {
		unsigned int sym;
		unsigned int str;
		unsigned int mod;
		unsigned int vers;
		unsigned int info;
		unsigned int pcpu;
	} index;
};

enum alarmtimer_type {
	ALARM_REALTIME = 0,
	ALARM_BOOTTIME = 1,
	ALARM_NUMTYPE = 2,
	ALARM_REALTIME_FREEZER = 3,
	ALARM_BOOTTIME_FREEZER = 4,
};

enum alarmtimer_restart {
	ALARMTIMER_NORESTART = 0,
	ALARMTIMER_RESTART = 1,
};

struct alarm {
	struct timerqueue_node node;
	struct hrtimer timer;
	enum alarmtimer_restart (*function)(struct alarm *, ktime_t);
	enum alarmtimer_type type;
	int state;
	void *data;
};

struct trace_event_raw_alarmtimer_suspend {
	struct trace_entry ent;
	s64 expires;
	unsigned char alarm_type;
	char __data[0];
};

struct trace_event_raw_alarm_class {
	struct trace_entry ent;
	void *alarm;
	unsigned char alarm_type;
	s64 expires;
	s64 now;
	char __data[0];
};

struct trace_event_data_offsets_alarmtimer_suspend {};

struct trace_event_data_offsets_alarm_class {};

typedef void (*btf_trace_alarmtimer_suspend)(void *, ktime_t, int);

typedef void (*btf_trace_alarmtimer_fired)(void *, struct alarm *, ktime_t);

typedef void (*btf_trace_alarmtimer_start)(void *, struct alarm *, ktime_t);

typedef void (*btf_trace_alarmtimer_cancel)(void *, struct alarm *, ktime_t);

struct alarm_base {
	spinlock_t lock;
	struct timerqueue_head timerqueue;
	ktime_t (*get_ktime)();
	void (*get_timespec)(struct timespec64 *);
	clockid_t base_clockid;
};

struct proc_ops {
	unsigned int proc_flags;
	int (*proc_open)(struct inode *, struct file *);
	ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*proc_read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*proc_write)(struct file *, const char *, size_t, loff_t *);
	loff_t (*proc_lseek)(struct file *, loff_t, int);
	int (*proc_release)(struct inode *, struct file *);
	__poll_t (*proc_poll)(struct file *, struct poll_table_struct *);
	long int (*proc_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*proc_mmap)(struct file *, struct vm_area_struct *);
	long unsigned int (*proc_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
};

struct kallsym_iter {
	loff_t pos;
	loff_t pos_arch_end;
	loff_t pos_mod_end;
	loff_t pos_ftrace_mod_end;
	loff_t pos_bpf_end;
	long unsigned int value;
	unsigned int nameoff;
	char type;
	char name[512];
	char module_name[56];
	int exported;
	int show_value;
};

struct bpf_iter__ksym {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct kallsym_iter *ksym;
	};
};

enum {
	FTRACE_OPS_FL_ENABLED = 1,
	FTRACE_OPS_FL_DYNAMIC = 2,
	FTRACE_OPS_FL_SAVE_REGS = 4,
	FTRACE_OPS_FL_SAVE_REGS_IF_SUPPORTED = 8,
	FTRACE_OPS_FL_RECURSION = 16,
	FTRACE_OPS_FL_STUB = 32,
	FTRACE_OPS_FL_INITIALIZED = 64,
	FTRACE_OPS_FL_DELETED = 128,
	FTRACE_OPS_FL_ADDING = 256,
	FTRACE_OPS_FL_REMOVING = 512,
	FTRACE_OPS_FL_MODIFYING = 1024,
	FTRACE_OPS_FL_ALLOC_TRAMP = 2048,
	FTRACE_OPS_FL_IPMODIFY = 4096,
	FTRACE_OPS_FL_PID = 8192,
	FTRACE_OPS_FL_RCU = 16384,
	FTRACE_OPS_FL_TRACE_ARRAY = 32768,
	FTRACE_OPS_FL_PERMANENT = 65536,
	FTRACE_OPS_FL_DIRECT = 131072,
};

enum {
	FTRACE_UPDATE_CALLS = 1,
	FTRACE_DISABLE_CALLS = 2,
	FTRACE_UPDATE_TRACE_FUNC = 4,
	FTRACE_START_FUNC_RET = 8,
	FTRACE_STOP_FUNC_RET = 16,
	FTRACE_MAY_SLEEP = 32,
};

struct ftrace_graph_ent {
	long unsigned int func;
	int depth;
} __attribute__((packed));

struct ftrace_graph_ret {
	long unsigned int func;
	int depth;
	unsigned int overrun;
	long long unsigned int calltime;
	long long unsigned int rettime;
};

typedef void (*trace_func_graph_ret_t)(struct ftrace_graph_ret *);

typedef int (*trace_func_graph_ent_t)(struct ftrace_graph_ent *);

struct fgraph_ops {
	trace_func_graph_ent_t entryfunc;
	trace_func_graph_ret_t retfunc;
};

enum dynevent_type {
	DYNEVENT_TYPE_SYNTH = 1,
	DYNEVENT_TYPE_KPROBE = 2,
	DYNEVENT_TYPE_NONE = 3,
};

struct dynevent_cmd;

typedef int (*dynevent_create_fn_t)(struct dynevent_cmd *);

struct dynevent_cmd {
	struct seq_buf seq;
	const char *event_name;
	unsigned int n_fields;
	enum dynevent_type type;
	dynevent_create_fn_t run_command;
	void *private_data;
};

typedef int (*dynevent_check_arg_fn_t)(void *);

struct dynevent_arg {
	const char *str;
	char separator;
};

struct dynevent_arg_pair {
	const char *lhs;
	const char *rhs;
	char operator;
	char separator;
};

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
	long unsigned int *close_on_exec;
	long unsigned int *open_fds;
	long unsigned int *full_fds_bits;
	struct callback_head rcu;
};

struct files_struct {
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;
	struct fdtable *fdt;
	struct fdtable fdtab;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t file_lock;
	unsigned int next_fd;
	long unsigned int close_on_exec_init[1];
	long unsigned int open_fds_init[1];
	long unsigned int full_fds_bits_init[1];
	struct file *fd_array[64];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

enum {
	BTF_TRACING_TYPE_TASK = 0,
	BTF_TRACING_TYPE_FILE = 1,
	BTF_TRACING_TYPE_VMA = 2,
	MAX_BTF_TRACING_TYPE = 3,
};

struct mmap_unlock_irq_work {
	struct irq_work irq_work;
	struct mm_struct *mm;
};

struct bpf_iter_seq_task_common {
	struct pid_namespace *ns;
	enum bpf_iter_task_type type;
	u32 pid;
	u32 pid_visiting;
};

struct bpf_iter_seq_task_info {
	struct bpf_iter_seq_task_common common;
	u32 tid;
};

struct bpf_iter__task {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
};

struct bpf_iter_seq_task_file_info {
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	u32 tid;
	u32 fd;
};

struct bpf_iter__task_file {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
	u32 fd;
	union {
		struct file *file;
	};
};

struct bpf_iter_seq_task_vma_info {
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	u32 tid;
	long unsigned int prev_vm_start;
	long unsigned int prev_vm_end;
};

enum bpf_task_vma_iter_find_op {
	task_vma_iter_first_vma = 0,
	task_vma_iter_next_vma = 1,
	task_vma_iter_find_vma = 2,
};

struct bpf_iter__task_vma {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
	union {
		struct vm_area_struct *vma;
	};
};

typedef u64 (*btf_bpf_find_vma)(struct task_struct *, u64, bpf_callback_t, void *, u64);

enum {
	BPF_RB_NO_WAKEUP = 1,
	BPF_RB_FORCE_WAKEUP = 2,
};

enum {
	BPF_RB_AVAIL_DATA = 0,
	BPF_RB_RING_SIZE = 1,
	BPF_RB_CONS_POS = 2,
	BPF_RB_PROD_POS = 3,
};

enum {
	BPF_RINGBUF_BUSY_BIT = 2147483648,
	BPF_RINGBUF_DISCARD_BIT = 1073741824,
	BPF_RINGBUF_HDR_SZ = 8,
};

enum bpf_type_flag {
	PTR_MAYBE_NULL = 256,
	MEM_RDONLY = 512,
	MEM_RINGBUF = 1024,
	MEM_USER = 2048,
	MEM_PERCPU = 4096,
	OBJ_RELEASE = 8192,
	PTR_UNTRUSTED = 16384,
	MEM_UNINIT = 32768,
	DYNPTR_TYPE_LOCAL = 65536,
	DYNPTR_TYPE_RINGBUF = 131072,
	MEM_FIXED_SIZE = 262144,
	MEM_ALLOC = 524288,
	PTR_TRUSTED = 1048576,
	MEM_RCU = 2097152,
	NON_OWN_REF = 4194304,
	DYNPTR_TYPE_SKB = 8388608,
	DYNPTR_TYPE_XDP = 16777216,
	__BPF_TYPE_FLAG_MAX = 16777217,
	__BPF_TYPE_LAST_FLAG = 16777216,
};

struct bpf_dynptr_kern {
	void *data;
	u32 size;
	u32 offset;
};

struct bpf_ringbuf {
	wait_queue_head_t waitq;
	struct irq_work work;
	u64 mask;
	struct page **pages;
	int nr_pages;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	spinlock_t spinlock;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	atomic_t busy;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int consumer_pos;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long unsigned int producer_pos;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	char data[0];
};

struct bpf_ringbuf_map {
	struct bpf_map map;
	struct bpf_ringbuf *rb;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct bpf_ringbuf_hdr {
	u32 len;
	u32 pg_off;
};

typedef u64 (*btf_bpf_ringbuf_reserve)(struct bpf_map *, u64, u64);

typedef u64 (*btf_bpf_ringbuf_submit)(void *, u64);

typedef u64 (*btf_bpf_ringbuf_discard)(void *, u64);

typedef u64 (*btf_bpf_ringbuf_output)(struct bpf_map *, void *, u64, u64);

typedef u64 (*btf_bpf_ringbuf_query)(struct bpf_map *, u64);

typedef u64 (*btf_bpf_ringbuf_reserve_dynptr)(struct bpf_map *, u32, u64, struct bpf_dynptr_kern *);

typedef u64 (*btf_bpf_ringbuf_submit_dynptr)(struct bpf_dynptr_kern *, u64);

typedef u64 (*btf_bpf_ringbuf_discard_dynptr)(struct bpf_dynptr_kern *, u64);

typedef u64 (*btf_bpf_user_ringbuf_drain)(struct bpf_map *, void *, void *, u64);

struct bp_slots_histogram {
	atomic_t *count;
};

struct bp_cpuinfo {
	unsigned int cpu_pinned;
	struct bp_slots_histogram tsk_pinned;
};

struct anon_vma_chain {
	struct vm_area_struct *vma;
	struct anon_vma *anon_vma;
	struct list_head same_vma;
	struct rb_node rb;
	long unsigned int rb_subtree_last;
};

struct rb_augment_callbacks {
	void (*propagate)(struct rb_node *, struct rb_node *);
	void (*copy)(struct rb_node *, struct rb_node *);
	void (*rotate)(struct rb_node *, struct rb_node *);
};

enum fsnotify_iter_type {
	FSNOTIFY_ITER_TYPE_INODE = 0,
	FSNOTIFY_ITER_TYPE_VFSMOUNT = 1,
	FSNOTIFY_ITER_TYPE_SB = 2,
	FSNOTIFY_ITER_TYPE_PARENT = 3,
	FSNOTIFY_ITER_TYPE_INODE2 = 4,
	FSNOTIFY_ITER_TYPE_COUNT = 5,
};

struct file_lock_context {
	spinlock_t flc_lock;
	struct list_head flc_flock;
	struct list_head flc_posix;
	struct list_head flc_lease;
};

struct nlm_lockowner;

struct nfs_lock_info {
	u32 state;
	struct nlm_lockowner *owner;
	struct list_head list;
};

struct nfs4_lock_state;

struct nfs4_lock_info {
	struct nfs4_lock_state *owner;
};

struct file_lock_operations;

struct lock_manager_operations;

struct file_lock {
	struct file_lock *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations *fl_ops;
	const struct lock_manager_operations *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
		struct {
			struct inode *inode;
		} ceph;
	} fl_u;
};

struct file_lock_operations {
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};

struct lock_manager_operations {
	void *lm_mod_owner;
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock *);
	int (*lm_grant)(struct file_lock *, int);
	bool (*lm_break)(struct file_lock *);
	int (*lm_change)(struct file_lock *, int, struct list_head *);
	void (*lm_setup)(struct file_lock *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock *);
	bool (*lm_lock_expirable)(struct file_lock *);
	void (*lm_expire_lock)();
};

enum hash_algo {
	HASH_ALGO_MD4 = 0,
	HASH_ALGO_MD5 = 1,
	HASH_ALGO_SHA1 = 2,
	HASH_ALGO_RIPE_MD_160 = 3,
	HASH_ALGO_SHA256 = 4,
	HASH_ALGO_SHA384 = 5,
	HASH_ALGO_SHA512 = 6,
	HASH_ALGO_SHA224 = 7,
	HASH_ALGO_RIPE_MD_128 = 8,
	HASH_ALGO_RIPE_MD_256 = 9,
	HASH_ALGO_RIPE_MD_320 = 10,
	HASH_ALGO_WP_256 = 11,
	HASH_ALGO_WP_384 = 12,
	HASH_ALGO_WP_512 = 13,
	HASH_ALGO_TGR_128 = 14,
	HASH_ALGO_TGR_160 = 15,
	HASH_ALGO_TGR_192 = 16,
	HASH_ALGO_SM3_256 = 17,
	HASH_ALGO_STREEBOG_256 = 18,
	HASH_ALGO_STREEBOG_512 = 19,
	HASH_ALGO__LAST = 20,
};

struct mnt_idmap {
	struct user_namespace *owner;
	refcount_t count;
};

struct vfs_cap_data {
	__le32 magic_etc;
	struct {
		__le32 permitted;
		__le32 inheritable;
	} data[2];
};

struct vfs_ns_cap_data {
	__le32 magic_etc;
	struct {
		__le32 permitted;
		__le32 inheritable;
	} data[2];
	__le32 rootid;
};

struct cpu_vfs_cap_data {
	__u32 magic_etc;
	kuid_t rootid;
	kernel_cap_t permitted;
	kernel_cap_t inheritable;
};

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

struct reciprocal_value {
	u32 m;
	u8 sh1;
	u8 sh2;
};

struct reciprocal_value_adv {
	u32 m;
	u8 sh;
	u8 exp;
	bool is_wide_m;
};

struct gen_pool_chunk {
	struct list_head next_chunk;
	atomic_long_t avail;
	phys_addr_t phys_addr;
	void *owner;
	long unsigned int start_addr;
	long unsigned int end_addr;
	long unsigned int bits[0];
};

struct genpool_data_align {
	int align;
};

struct genpool_data_fixed {
	long unsigned int offset;
};

enum {
	PCI_STD_RESOURCES = 0,
	PCI_STD_RESOURCE_END = 5,
	PCI_ROM_RESOURCE = 6,
	PCI_BRIDGE_RESOURCES = 7,
	PCI_BRIDGE_RESOURCE_END = 10,
	PCI_NUM_RESOURCES = 11,
	DEVICE_COUNT_RESOURCE = 11,
};

typedef unsigned int pci_channel_state_t;

typedef unsigned int pcie_reset_state_t;

typedef short unsigned int pci_dev_flags_t;

typedef short unsigned int pci_bus_flags_t;

typedef unsigned int pci_ers_result_t;

struct clk_gate {
	struct clk_hw hw;
	void *reg;
	u8 bit_idx;
	u8 flags;
	spinlock_t *lock;
};

struct miscdevice {
	int minor;
	const char *name;
	const struct file_operations *fops;
	struct list_head list;
	struct device *parent;
	struct device *this_device;
	const struct attribute_group **groups;
	const char *nodename;
	umode_t mode;
};

struct cpu {
	int node_id;
	int hotpluggable;
	struct device dev;
};

struct cpu_attr {
	struct device_attribute attr;
	const struct cpumask * const map;
};

struct pm_clk_notifier_block {
	struct notifier_block nb;
	struct dev_pm_domain *pm_domain;
	char *con_ids[0];
};

typedef struct {
	__u8 b[16];
} guid_t;

enum reboot_mode {
	REBOOT_UNDEFINED = -1,
	REBOOT_COLD = 0,
	REBOOT_WARM = 1,
	REBOOT_HARD = 2,
	REBOOT_SOFT = 3,
	REBOOT_GPIO = 4,
};

enum sys_off_mode {
	SYS_OFF_MODE_POWER_OFF_PREPARE = 0,
	SYS_OFF_MODE_POWER_OFF = 1,
	SYS_OFF_MODE_RESTART_PREPARE = 2,
	SYS_OFF_MODE_RESTART = 3,
};

struct sys_off_data {
	int mode;
	void *cb_data;
	const char *cmd;
};

typedef u8 efi_bool_t;

typedef u16 efi_char16_t;

typedef guid_t efi_guid_t;

typedef struct {
	u64 signature;
	u32 revision;
	u32 headersize;
	u32 crc32;
	u32 reserved;
} efi_table_hdr_t;

typedef struct {
	u32 type;
	u32 pad;
	u64 phys_addr;
	u64 virt_addr;
	u64 num_pages;
	u64 attribute;
} efi_memory_desc_t;

typedef struct {
	efi_guid_t guid;
	u32 headersize;
	u32 flags;
	u32 imagesize;
} efi_capsule_header_t;

typedef struct {
	u16 year;
	u8 month;
	u8 day;
	u8 hour;
	u8 minute;
	u8 second;
	u8 pad1;
	u32 nanosecond;
	s16 timezone;
	u8 daylight;
	u8 pad2;
} efi_time_t;

typedef struct {
	u32 resolution;
	u32 accuracy;
	u8 sets_to_zero;
} efi_time_cap_t;

typedef struct {
	efi_table_hdr_t hdr;
	u32 get_time;
	u32 set_time;
	u32 get_wakeup_time;
	u32 set_wakeup_time;
	u32 set_virtual_address_map;
	u32 convert_pointer;
	u32 get_variable;
	u32 get_next_variable;
	u32 set_variable;
	u32 get_next_high_mono_count;
	u32 reset_system;
	u32 update_capsule;
	u32 query_capsule_caps;
	u32 query_variable_info;
} efi_runtime_services_32_t;

typedef efi_status_t efi_get_time_t(efi_time_t *, efi_time_cap_t *);

typedef efi_status_t efi_set_time_t(efi_time_t *);

typedef efi_status_t efi_get_wakeup_time_t(efi_bool_t *, efi_bool_t *, efi_time_t *);

typedef efi_status_t efi_set_wakeup_time_t(efi_bool_t, efi_time_t *);

typedef efi_status_t efi_get_variable_t(efi_char16_t *, efi_guid_t *, u32 *, long unsigned int *, void *);

typedef efi_status_t efi_get_next_variable_t(long unsigned int *, efi_char16_t *, efi_guid_t *);

typedef efi_status_t efi_set_variable_t(efi_char16_t *, efi_guid_t *, u32, long unsigned int, void *);

typedef efi_status_t efi_get_next_high_mono_count_t(u32 *);

typedef void efi_reset_system_t(int, efi_status_t, long unsigned int, efi_char16_t *);

typedef efi_status_t efi_set_virtual_address_map_t(long unsigned int, long unsigned int, u32, efi_memory_desc_t *);

typedef efi_status_t efi_query_variable_info_t(u32, u64 *, u64 *, u64 *);

typedef efi_status_t efi_update_capsule_t(efi_capsule_header_t **, long unsigned int, long unsigned int);

typedef efi_status_t efi_query_capsule_caps_t(efi_capsule_header_t **, long unsigned int, u64 *, int *);

typedef union {
	struct {
		efi_table_hdr_t hdr;
		efi_get_time_t *get_time;
		efi_set_time_t *set_time;
		efi_get_wakeup_time_t *get_wakeup_time;
		efi_set_wakeup_time_t *set_wakeup_time;
		efi_set_virtual_address_map_t *set_virtual_address_map;
		void *convert_pointer;
		efi_get_variable_t *get_variable;
		efi_get_next_variable_t *get_next_variable;
		efi_set_variable_t *set_variable;
		efi_get_next_high_mono_count_t *get_next_high_mono_count;
		efi_reset_system_t *reset_system;
		efi_update_capsule_t *update_capsule;
		efi_query_capsule_caps_t *query_capsule_caps;
		efi_query_variable_info_t *query_variable_info;
	};
	efi_runtime_services_32_t mixed_mode;
} efi_runtime_services_t;

struct efi_memory_map {
	phys_addr_t phys_map;
	void *map;
	void *map_end;
	int nr_map;
	long unsigned int desc_version;
	long unsigned int desc_size;
	long unsigned int flags;
};

struct efi {
	const efi_runtime_services_t *runtime;
	unsigned int runtime_version;
	unsigned int runtime_supported_mask;
	long unsigned int acpi;
	long unsigned int acpi20;
	long unsigned int smbios;
	long unsigned int smbios3;
	long unsigned int esrt;
	long unsigned int tpm_log;
	long unsigned int tpm_final_log;
	long unsigned int mokvar_table;
	long unsigned int coco_secret;
	long unsigned int unaccepted;
	efi_get_time_t *get_time;
	efi_set_time_t *set_time;
	efi_get_wakeup_time_t *get_wakeup_time;
	efi_set_wakeup_time_t *set_wakeup_time;
	efi_get_variable_t *get_variable;
	efi_get_next_variable_t *get_next_variable;
	efi_set_variable_t *set_variable;
	efi_set_variable_t *set_variable_nonblocking;
	efi_query_variable_info_t *query_variable_info;
	efi_query_variable_info_t *query_variable_info_nonblocking;
	efi_update_capsule_t *update_capsule;
	efi_query_capsule_caps_t *query_capsule_caps;
	efi_get_next_high_mono_count_t *get_next_high_mono_count;
	efi_reset_system_t *reset_system;
	struct efi_memory_map memmap;
	long unsigned int flags;
};

typedef __u64 __be64;

struct efi_memory_map_data {
	phys_addr_t phys_map;
	long unsigned int size;
	long unsigned int desc_version;
	long unsigned int desc_size;
	long unsigned int flags;
};

enum {
	SYSTAB = 0,
	MMBASE = 1,
	MMSIZE = 2,
	DCSIZE = 3,
	DCVERS = 4,
	PARAMCOUNT = 5,
};

typedef int (*efi_memattr_perm_setter)(struct mm_struct *, efi_memory_desc_t *, bool);

struct of_dev_auxdata {
	char *compatible;
	resource_size_t phys_addr;
	char *name;
	void *platform_data;
};

struct cpio_data {
	void *data;
	size_t size;
	char name[18];
};

enum cpio_fields {
	C_MAGIC = 0,
	C_INO = 1,
	C_MODE = 2,
	C_UID = 3,
	C_GID = 4,
	C_NLINK = 5,
	C_MTIME = 6,
	C_FILESIZE = 7,
	C_MAJ = 8,
	C_MIN = 9,
	C_RMAJ = 10,
	C_RMIN = 11,
	C_NAMESIZE = 12,
	C_CHKSUM = 13,
	C_NFIELDS = 14,
};

typedef u8 uint8_t;

typedef s32 int32_t;

typedef __be64 fdt64_t;

struct fdt_header {
	fdt32_t magic;
	fdt32_t totalsize;
	fdt32_t off_dt_struct;
	fdt32_t off_dt_strings;
	fdt32_t off_mem_rsvmap;
	fdt32_t version;
	fdt32_t last_comp_version;
	fdt32_t boot_cpuid_phys;
	fdt32_t size_dt_strings;
	fdt32_t size_dt_struct;
};

struct fdt_reserve_entry {
	fdt64_t address;
	fdt64_t size;
};

struct fdt_node_header {
	fdt32_t tag;
	char name[0];
};

enum {
	ASSUME_PERFECT = 255,
	ASSUME_VALID_DTB = 1,
	ASSUME_VALID_INPUT = 2,
	ASSUME_LATEST = 4,
	ASSUME_NO_ROLLBACK = 8,
	ASSUME_LIBFDT_ORDER = 16,
	ASSUME_LIBFDT_FLAWLESS = 32,
};

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct kobj_attribute *, char *);
	ssize_t (*store)(struct kobject *, struct kobj_attribute *, const char *, size_t);
};

typedef struct {
	long unsigned int key[2];
} hsiphash_key_t;

struct screen_info {
	__u8 orig_x;
	__u8 orig_y;
	__u16 ext_mem_k;
	__u16 orig_video_page;
	__u8 orig_video_mode;
	__u8 orig_video_cols;
	__u8 flags;
	__u8 unused2;
	__u16 orig_video_ega_bx;
	__u16 unused3;
	__u8 orig_video_lines;
	__u8 orig_video_isVGA;
	__u16 orig_video_points;
	__u16 lfb_width;
	__u16 lfb_height;
	__u16 lfb_depth;
	__u32 lfb_base;
	__u32 lfb_size;
	__u16 cl_magic;
	__u16 cl_offset;
	__u16 lfb_linelength;
	__u8 red_size;
	__u8 red_pos;
	__u8 green_size;
	__u8 green_pos;
	__u8 blue_size;
	__u8 blue_pos;
	__u8 rsvd_size;
	__u8 rsvd_pos;
	__u16 vesapm_seg;
	__u16 vesapm_off;
	__u16 pages;
	__u16 vesa_attributes;
	__u32 capabilities;
	__u32 ext_lfb_base;
	__u8 _reserved[2];
} __attribute__((packed));

typedef u64 efi_physical_addr_t;

typedef void *efi_handle_t;

typedef void *efi_event_t;

typedef void (*efi_event_notify_t)(efi_event_t, void *);

typedef enum {
	EfiTimerCancel = 0,
	EfiTimerPeriodic = 1,
	EfiTimerRelative = 2,
} EFI_TIMER_DELAY;

struct efi_generic_dev_path;

typedef struct efi_generic_dev_path efi_device_path_protocol_t;

union efi_boot_services {
	struct {
		efi_table_hdr_t hdr;
		void *raise_tpl;
		void *restore_tpl;
		efi_status_t (*allocate_pages)(int, int, long unsigned int, efi_physical_addr_t *);
		efi_status_t (*free_pages)(efi_physical_addr_t, long unsigned int);
		efi_status_t (*get_memory_map)(long unsigned int *, void *, long unsigned int *, long unsigned int *, u32 *);
		efi_status_t (*allocate_pool)(int, long unsigned int, void **);
		efi_status_t (*free_pool)(void *);
		efi_status_t (*create_event)(u32, long unsigned int, efi_event_notify_t, void *, efi_event_t *);
		efi_status_t (*set_timer)(efi_event_t, EFI_TIMER_DELAY, u64);
		efi_status_t (*wait_for_event)(long unsigned int, efi_event_t *, long unsigned int *);
		void *signal_event;
		efi_status_t (*close_event)(efi_event_t);
		void *check_event;
		void *install_protocol_interface;
		void *reinstall_protocol_interface;
		void *uninstall_protocol_interface;
		efi_status_t (*handle_protocol)(efi_handle_t, efi_guid_t *, void **);
		void *__reserved;
		void *register_protocol_notify;
		efi_status_t (*locate_handle)(int, efi_guid_t *, void *, long unsigned int *, efi_handle_t *);
		efi_status_t (*locate_device_path)(efi_guid_t *, efi_device_path_protocol_t **, efi_handle_t *);
		efi_status_t (*install_configuration_table)(efi_guid_t *, void *);
		efi_status_t (*load_image)(bool, efi_handle_t, efi_device_path_protocol_t *, void *, long unsigned int, efi_handle_t *);
		efi_status_t (*start_image)(efi_handle_t, long unsigned int *, efi_char16_t **);
		efi_status_t (*exit)(efi_handle_t, efi_status_t, long unsigned int, efi_char16_t *);
		efi_status_t (*unload_image)(efi_handle_t);
		efi_status_t (*exit_boot_services)(efi_handle_t, long unsigned int);
		void *get_next_monotonic_count;
		efi_status_t (*stall)(long unsigned int);
		void *set_watchdog_timer;
		void *connect_controller;
		efi_status_t (*disconnect_controller)(efi_handle_t, efi_handle_t, efi_handle_t);
		void *open_protocol;
		void *close_protocol;
		void *open_protocol_information;
		void *protocols_per_handle;
		void *locate_handle_buffer;
		efi_status_t (*locate_protocol)(efi_guid_t *, void *, void **);
		efi_status_t (*install_multiple_protocol_interfaces)(efi_handle_t *, ...);
		efi_status_t (*uninstall_multiple_protocol_interfaces)(efi_handle_t, ...);
		void *calculate_crc32;
		void (*copy_mem)(void *, const void *, long unsigned int);
		void (*set_mem)(void *, long unsigned int, unsigned char);
		void *create_event_ex;
	};
	struct {
		efi_table_hdr_t hdr;
		u32 raise_tpl;
		u32 restore_tpl;
		u32 allocate_pages;
		u32 free_pages;
		u32 get_memory_map;
		u32 allocate_pool;
		u32 free_pool;
		u32 create_event;
		u32 set_timer;
		u32 wait_for_event;
		u32 signal_event;
		u32 close_event;
		u32 check_event;
		u32 install_protocol_interface;
		u32 reinstall_protocol_interface;
		u32 uninstall_protocol_interface;
		u32 handle_protocol;
		u32 __reserved;
		u32 register_protocol_notify;
		u32 locate_handle;
		u32 locate_device_path;
		u32 install_configuration_table;
		u32 load_image;
		u32 start_image;
		u32 exit;
		u32 unload_image;
		u32 exit_boot_services;
		u32 get_next_monotonic_count;
		u32 stall;
		u32 set_watchdog_timer;
		u32 connect_controller;
		u32 disconnect_controller;
		u32 open_protocol;
		u32 close_protocol;
		u32 open_protocol_information;
		u32 protocols_per_handle;
		u32 locate_handle_buffer;
		u32 locate_protocol;
		u32 install_multiple_protocol_interfaces;
		u32 uninstall_multiple_protocol_interfaces;
		u32 calculate_crc32;
		u32 copy_mem;
		u32 set_mem;
		u32 create_event_ex;
	} mixed_mode;
};

typedef union efi_boot_services efi_boot_services_t;

typedef struct {
	efi_table_hdr_t hdr;
	u32 fw_vendor;
	u32 fw_revision;
	u32 con_in_handle;
	u32 con_in;
	u32 con_out_handle;
	u32 con_out;
	u32 stderr_handle;
	u32 stderr;
	u32 runtime;
	u32 boottime;
	u32 nr_tables;
	u32 tables;
} efi_system_table_32_t;

typedef struct {
	u16 scan_code;
	efi_char16_t unicode_char;
} efi_input_key_t;

union efi_simple_text_input_protocol;

typedef union efi_simple_text_input_protocol efi_simple_text_input_protocol_t;

union efi_simple_text_input_protocol {
	struct {
		void *reset;
		efi_status_t (*read_keystroke)(efi_simple_text_input_protocol_t *, efi_input_key_t *);
		efi_event_t wait_for_key;
	};
	struct {
		u32 reset;
		u32 read_keystroke;
		u32 wait_for_key;
	} mixed_mode;
};

union efi_simple_text_output_protocol;

typedef union efi_simple_text_output_protocol efi_simple_text_output_protocol_t;

union efi_simple_text_output_protocol {
	struct {
		void *reset;
		efi_status_t (*output_string)(efi_simple_text_output_protocol_t *, efi_char16_t *);
		void *test_string;
	};
	struct {
		u32 reset;
		u32 output_string;
		u32 test_string;
	} mixed_mode;
};

typedef union {
	struct {
		efi_table_hdr_t hdr;
		long unsigned int fw_vendor;
		u32 fw_revision;
		long unsigned int con_in_handle;
		efi_simple_text_input_protocol_t *con_in;
		long unsigned int con_out_handle;
		efi_simple_text_output_protocol_t *con_out;
		long unsigned int stderr_handle;
		long unsigned int stderr;
		efi_runtime_services_t *runtime;
		efi_boot_services_t *boottime;
		long unsigned int nr_tables;
		long unsigned int tables;
	};
	efi_system_table_32_t mixed_mode;
} efi_system_table_t;

struct efi_generic_dev_path {
	u8 type;
	u8 sub_type;
	u16 length;
};

typedef union {
	struct {
		u32 revision;
		efi_handle_t parent_handle;
		efi_system_table_t *system_table;
		efi_handle_t device_handle;
		void *file_path;
		void *reserved;
		u32 load_options_size;
		void *load_options;
		void *image_base;
		__u64 image_size;
		unsigned int image_code_type;
		unsigned int image_data_type;
		efi_status_t (*unload)(efi_handle_t);
	};
	struct {
		u32 revision;
		u32 parent_handle;
		u32 system_table;
		u32 device_handle;
		u32 file_path;
		u32 reserved;
		u32 load_options_size;
		u32 load_options;
		u32 image_base;
		__u64 image_size;
		u32 image_code_type;
		u32 image_data_type;
		u32 unload;
	} mixed_mode;
} efi_loaded_image_t;

struct efi_boot_memmap {
	long unsigned int map_size;
	long unsigned int desc_size;
	u32 desc_ver;
	long unsigned int map_key;
	long unsigned int buff_size;
	efi_memory_desc_t map[0];
};

enum efi_secureboot_mode {
	efi_secureboot_mode_unset = 0,
	efi_secureboot_mode_unknown = 1,
	efi_secureboot_mode_disabled = 2,
	efi_secureboot_mode_enabled = 3,
};

typedef efi_status_t (*efi_exit_boot_map_processing)(struct efi_boot_memmap *, void *);

struct exit_boot_struct {
	struct efi_boot_memmap *boot_memmap;
	efi_memory_desc_t *runtime_map;
	int runtime_entry_count;
	void *new_fdt_addr;
};

struct step_hook {
	struct list_head node;
	int (*fn)(struct pt_regs *, long unsigned int);
};

struct break_hook {
	struct list_head node;
	int (*fn)(struct pt_regs *, long unsigned int);
	u16 imm;
	u16 mask;
};

enum dbg_active_el {
	DBG_ACTIVE_EL0 = 0,
	DBG_ACTIVE_EL1 = 1,
};

enum lockdep_ok {
	LOCKDEP_STILL_OK = 0,
	LOCKDEP_NOW_UNRELIABLE = 1,
};

enum bug_trap_type {
	BUG_TRAP_TYPE_NONE = 0,
	BUG_TRAP_TYPE_WARN = 1,
	BUG_TRAP_TYPE_BUG = 2,
};

enum ftr_type {
	FTR_EXACT = 0,
	FTR_LOWER_SAFE = 1,
	FTR_HIGHER_SAFE = 2,
	FTR_HIGHER_OR_ZERO_SAFE = 3,
};

struct arm64_ftr_bits {
	bool sign;
	bool visible;
	bool strict;
	enum ftr_type type;
	u8 shift;
	u8 width;
	s64 safe_val;
};

struct arm64_ftr_override {
	u64 val;
	u64 mask;
};

struct arm64_ftr_reg {
	const char *name;
	u64 strict_mask;
	u64 user_mask;
	u64 sys_val;
	u64 user_val;
	struct arm64_ftr_override *override;
	const struct arm64_ftr_bits *ftr_bits;
};

enum siginfo_layout {
	SIL_KILL = 0,
	SIL_TIMER = 1,
	SIL_POLL = 2,
	SIL_FAULT = 3,
	SIL_FAULT_TRAPNO = 4,
	SIL_FAULT_MCEERR = 5,
	SIL_FAULT_BNDERR = 6,
	SIL_FAULT_PKUERR = 7,
	SIL_FAULT_PERF_EVENT = 8,
	SIL_CHLD = 9,
	SIL_RT = 10,
	SIL_SYS = 11,
};

typedef bool pstate_check_t(long unsigned int);

enum die_val {
	DIE_UNUSED = 0,
	DIE_OOPS = 1,
};

struct sys64_hook {
	long unsigned int esr_mask;
	long unsigned int esr_val;
	void (*handler)(long unsigned int, struct pt_regs *);
};

struct arm_cpuidle_irq_context {};

enum aarch64_insn_hint_cr_op {
	AARCH64_INSN_HINT_NOP = 0,
	AARCH64_INSN_HINT_YIELD = 32,
	AARCH64_INSN_HINT_WFE = 64,
	AARCH64_INSN_HINT_WFI = 96,
	AARCH64_INSN_HINT_SEV = 128,
	AARCH64_INSN_HINT_SEVL = 160,
	AARCH64_INSN_HINT_XPACLRI = 224,
	AARCH64_INSN_HINT_PACIA_1716 = 256,
	AARCH64_INSN_HINT_PACIB_1716 = 320,
	AARCH64_INSN_HINT_AUTIA_1716 = 384,
	AARCH64_INSN_HINT_AUTIB_1716 = 448,
	AARCH64_INSN_HINT_PACIAZ = 768,
	AARCH64_INSN_HINT_PACIASP = 800,
	AARCH64_INSN_HINT_PACIBZ = 832,
	AARCH64_INSN_HINT_PACIBSP = 864,
	AARCH64_INSN_HINT_AUTIAZ = 896,
	AARCH64_INSN_HINT_AUTIASP = 928,
	AARCH64_INSN_HINT_AUTIBZ = 960,
	AARCH64_INSN_HINT_AUTIBSP = 992,
	AARCH64_INSN_HINT_ESB = 512,
	AARCH64_INSN_HINT_PSB = 544,
	AARCH64_INSN_HINT_TSB = 576,
	AARCH64_INSN_HINT_CSDB = 640,
	AARCH64_INSN_HINT_CLEARBHB = 704,
	AARCH64_INSN_HINT_BTI = 1024,
	AARCH64_INSN_HINT_BTIC = 1088,
	AARCH64_INSN_HINT_BTIJ = 1152,
	AARCH64_INSN_HINT_BTIJC = 1216,
};

enum aarch64_insn_register {
	AARCH64_INSN_REG_0 = 0,
	AARCH64_INSN_REG_1 = 1,
	AARCH64_INSN_REG_2 = 2,
	AARCH64_INSN_REG_3 = 3,
	AARCH64_INSN_REG_4 = 4,
	AARCH64_INSN_REG_5 = 5,
	AARCH64_INSN_REG_6 = 6,
	AARCH64_INSN_REG_7 = 7,
	AARCH64_INSN_REG_8 = 8,
	AARCH64_INSN_REG_9 = 9,
	AARCH64_INSN_REG_10 = 10,
	AARCH64_INSN_REG_11 = 11,
	AARCH64_INSN_REG_12 = 12,
	AARCH64_INSN_REG_13 = 13,
	AARCH64_INSN_REG_14 = 14,
	AARCH64_INSN_REG_15 = 15,
	AARCH64_INSN_REG_16 = 16,
	AARCH64_INSN_REG_17 = 17,
	AARCH64_INSN_REG_18 = 18,
	AARCH64_INSN_REG_19 = 19,
	AARCH64_INSN_REG_20 = 20,
	AARCH64_INSN_REG_21 = 21,
	AARCH64_INSN_REG_22 = 22,
	AARCH64_INSN_REG_23 = 23,
	AARCH64_INSN_REG_24 = 24,
	AARCH64_INSN_REG_25 = 25,
	AARCH64_INSN_REG_26 = 26,
	AARCH64_INSN_REG_27 = 27,
	AARCH64_INSN_REG_28 = 28,
	AARCH64_INSN_REG_29 = 29,
	AARCH64_INSN_REG_FP = 29,
	AARCH64_INSN_REG_30 = 30,
	AARCH64_INSN_REG_LR = 30,
	AARCH64_INSN_REG_ZR = 31,
	AARCH64_INSN_REG_SP = 31,
};

enum aarch64_insn_variant {
	AARCH64_INSN_VARIANT_32BIT = 0,
	AARCH64_INSN_VARIANT_64BIT = 1,
};

struct dyn_arch_ftrace {};

struct dyn_ftrace {
	long unsigned int ip;
	long unsigned int flags;
	struct dyn_arch_ftrace arch;
};

struct fregs_offset {
	const char *name;
	int offset;
};

struct perf_callchain_entry_ctx {
	struct perf_callchain_entry *entry;
	u32 max_stack;
	u32 nr;
	short int contexts;
	bool contexts_maxed;
};

struct frame_tail {
	struct frame_tail *fp;
	long unsigned int lr;
};

enum aarch64_insn_condition {
	AARCH64_INSN_COND_EQ = 0,
	AARCH64_INSN_COND_NE = 1,
	AARCH64_INSN_COND_CS = 2,
	AARCH64_INSN_COND_CC = 3,
	AARCH64_INSN_COND_MI = 4,
	AARCH64_INSN_COND_PL = 5,
	AARCH64_INSN_COND_VS = 6,
	AARCH64_INSN_COND_VC = 7,
	AARCH64_INSN_COND_HI = 8,
	AARCH64_INSN_COND_LS = 9,
	AARCH64_INSN_COND_GE = 10,
	AARCH64_INSN_COND_LT = 11,
	AARCH64_INSN_COND_GT = 12,
	AARCH64_INSN_COND_LE = 13,
	AARCH64_INSN_COND_AL = 14,
};

enum aarch64_insn_size_type {
	AARCH64_INSN_SIZE_8 = 0,
	AARCH64_INSN_SIZE_16 = 1,
	AARCH64_INSN_SIZE_32 = 2,
	AARCH64_INSN_SIZE_64 = 3,
};

enum aarch64_insn_ldst_type {
	AARCH64_INSN_LDST_LOAD_REG_OFFSET = 0,
	AARCH64_INSN_LDST_STORE_REG_OFFSET = 1,
	AARCH64_INSN_LDST_LOAD_IMM_OFFSET = 2,
	AARCH64_INSN_LDST_STORE_IMM_OFFSET = 3,
	AARCH64_INSN_LDST_LOAD_PAIR_PRE_INDEX = 4,
	AARCH64_INSN_LDST_STORE_PAIR_PRE_INDEX = 5,
	AARCH64_INSN_LDST_LOAD_PAIR_POST_INDEX = 6,
	AARCH64_INSN_LDST_STORE_PAIR_POST_INDEX = 7,
	AARCH64_INSN_LDST_LOAD_EX = 8,
	AARCH64_INSN_LDST_LOAD_ACQ_EX = 9,
	AARCH64_INSN_LDST_STORE_EX = 10,
	AARCH64_INSN_LDST_STORE_REL_EX = 11,
};

enum aarch64_insn_adsb_type {
	AARCH64_INSN_ADSB_ADD = 0,
	AARCH64_INSN_ADSB_SUB = 1,
	AARCH64_INSN_ADSB_ADD_SETFLAGS = 2,
	AARCH64_INSN_ADSB_SUB_SETFLAGS = 3,
};

enum aarch64_insn_movewide_type {
	AARCH64_INSN_MOVEWIDE_ZERO = 0,
	AARCH64_INSN_MOVEWIDE_KEEP = 1,
	AARCH64_INSN_MOVEWIDE_INVERSE = 2,
};

enum aarch64_insn_bitfield_type {
	AARCH64_INSN_BITFIELD_MOVE = 0,
	AARCH64_INSN_BITFIELD_MOVE_UNSIGNED = 1,
	AARCH64_INSN_BITFIELD_MOVE_SIGNED = 2,
};

enum aarch64_insn_data1_type {
	AARCH64_INSN_DATA1_REVERSE_16 = 0,
	AARCH64_INSN_DATA1_REVERSE_32 = 1,
	AARCH64_INSN_DATA1_REVERSE_64 = 2,
};

enum aarch64_insn_data2_type {
	AARCH64_INSN_DATA2_UDIV = 0,
	AARCH64_INSN_DATA2_SDIV = 1,
	AARCH64_INSN_DATA2_LSLV = 2,
	AARCH64_INSN_DATA2_LSRV = 3,
	AARCH64_INSN_DATA2_ASRV = 4,
	AARCH64_INSN_DATA2_RORV = 5,
};

enum aarch64_insn_data3_type {
	AARCH64_INSN_DATA3_MADD = 0,
	AARCH64_INSN_DATA3_MSUB = 1,
};

enum aarch64_insn_logic_type {
	AARCH64_INSN_LOGIC_AND = 0,
	AARCH64_INSN_LOGIC_BIC = 1,
	AARCH64_INSN_LOGIC_ORR = 2,
	AARCH64_INSN_LOGIC_ORN = 3,
	AARCH64_INSN_LOGIC_EOR = 4,
	AARCH64_INSN_LOGIC_EON = 5,
	AARCH64_INSN_LOGIC_AND_SETFLAGS = 6,
	AARCH64_INSN_LOGIC_BIC_SETFLAGS = 7,
};

enum aarch64_insn_adr_type {
	AARCH64_INSN_ADR_TYPE_ADRP = 0,
	AARCH64_INSN_ADR_TYPE_ADR = 1,
};

enum aarch64_insn_mem_atomic_op {
	AARCH64_INSN_MEM_ATOMIC_ADD = 0,
	AARCH64_INSN_MEM_ATOMIC_CLR = 1,
	AARCH64_INSN_MEM_ATOMIC_EOR = 2,
	AARCH64_INSN_MEM_ATOMIC_SET = 3,
	AARCH64_INSN_MEM_ATOMIC_SWP = 4,
};

enum aarch64_insn_mem_order_type {
	AARCH64_INSN_MEM_ORDER_NONE = 0,
	AARCH64_INSN_MEM_ORDER_ACQ = 1,
	AARCH64_INSN_MEM_ORDER_REL = 2,
	AARCH64_INSN_MEM_ORDER_ACQREL = 3,
};

enum aarch64_insn_mb_type {
	AARCH64_INSN_MB_SY = 0,
	AARCH64_INSN_MB_ST = 1,
	AARCH64_INSN_MB_LD = 2,
	AARCH64_INSN_MB_ISH = 3,
	AARCH64_INSN_MB_ISHST = 4,
	AARCH64_INSN_MB_ISHLD = 5,
	AARCH64_INSN_MB_NSH = 6,
	AARCH64_INSN_MB_NSHST = 7,
	AARCH64_INSN_MB_NSHLD = 8,
	AARCH64_INSN_MB_OSH = 9,
	AARCH64_INSN_MB_OSHST = 10,
	AARCH64_INSN_MB_OSHLD = 11,
};

struct bpf_binary_header {
	u32 size;
	long: 0;
	u8 image[0];
};

typedef void (*bpf_jit_fill_hole_t)(void *, unsigned int);

struct jit_ctx {
	const struct bpf_prog *prog;
	int idx;
	int epilogue_offset;
	int *offset;
	int exentry_idx;
	__le32 *image;
	u32 stack_size;
	int fpb_offset;
};

struct bpf_plt {
	u32 insn_ldr;
	u32 insn_br;
	u64 target;
};

struct arm64_jit_data {
	struct bpf_binary_header *header;
	u8 *image;
	struct jit_ctx ctx;
};

struct kthread_work;

typedef void (*kthread_work_func_t)(struct kthread_work *);

struct kthread_worker;

struct kthread_work {
	struct list_head node;
	kthread_work_func_t func;
	struct kthread_worker *worker;
	int canceling;
};

enum {
	KTW_FREEZABLE = 1,
};

struct kthread_worker {
	unsigned int flags;
	raw_spinlock_t lock;
	struct list_head work_list;
	struct list_head delayed_work_list;
	struct task_struct *task;
	struct kthread_work *current_work;
};

struct kthread_delayed_work {
	struct kthread_work work;
	struct timer_list timer;
};

struct kthread_create_info {
	char *full_name;
	int (*threadfn)(void *);
	void *data;
	int node;
	struct task_struct *result;
	struct completion *done;
	struct list_head list;
};

struct kthread {
	long unsigned int flags;
	unsigned int cpu;
	int result;
	int (*threadfn)(void *);
	void *data;
	struct completion parked;
	struct completion exited;
	char *full_name;
};

enum KTHREAD_BITS {
	KTHREAD_IS_PER_CPU = 0,
	KTHREAD_SHOULD_STOP = 1,
	KTHREAD_SHOULD_PARK = 2,
};

struct kthread_flush_work {
	struct kthread_work work;
	struct completion done;
};

typedef void (*swap_func_t)(void *, void *, int);

struct pin_cookie {};

typedef int (*task_call_f)(struct task_struct *, void *);

struct dl_bw {
	raw_spinlock_t lock;
	u64 bw;
	u64 total_bw;
};

struct cpudl_item;

struct cpudl {
	raw_spinlock_t lock;
	int size;
	cpumask_var_t free_cpus;
	struct cpudl_item *elements;
};

struct cpupri_vec {
	atomic_t count;
	cpumask_var_t mask;
};

struct cpupri {
	struct cpupri_vec pri_to_cpu[101];
	int *cpu_to_pri;
};

struct perf_domain;

struct root_domain {
	atomic_t refcount;
	atomic_t rto_count;
	struct callback_head rcu;
	cpumask_var_t span;
	cpumask_var_t online;
	int overload;
	int overutilized;
	cpumask_var_t dlo_mask;
	atomic_t dlo_count;
	struct dl_bw dl_bw;
	struct cpudl cpudl;
	u64 visit_gen;
	struct irq_work rto_push_work;
	raw_spinlock_t rto_lock;
	int rto_loop;
	int rto_cpu;
	atomic_t rto_loop_next;
	atomic_t rto_loop_start;
	cpumask_var_t rto_mask;
	struct cpupri cpupri;
	long unsigned int max_cpu_capacity;
	struct perf_domain *pd;
};

struct kernel_clone_args {
	u64 flags;
	int *pidfd;
	int *child_tid;
	int *parent_tid;
	const char *name;
	int exit_signal;
	u32 kthread: 1;
	u32 io_thread: 1;
	u32 user_worker: 1;
	u32 no_files: 1;
	long unsigned int stack;
	long unsigned int stack_size;
	long unsigned int tls;
	pid_t *set_tid;
	size_t set_tid_size;
	int cgroup;
	int idle;
	int (*fn)(void *);
	void *fn_arg;
	struct cgroup *cgrp;
	struct css_set *cset;
};

struct sched_domain_attr {
	int relax_domain_level;
};

struct sched_domain_shared {
	atomic_t ref;
	atomic_t nr_busy_cpus;
	int has_idle_cores;
	int nr_idle_scan;
};

struct sched_group;

struct sched_domain {
	struct sched_domain *parent;
	struct sched_domain *child;
	struct sched_group *groups;
	long unsigned int min_interval;
	long unsigned int max_interval;
	unsigned int busy_factor;
	unsigned int imbalance_pct;
	unsigned int cache_nice_tries;
	unsigned int imb_numa_nr;
	int nohz_idle;
	int flags;
	int level;
	long unsigned int last_balance;
	unsigned int balance_interval;
	unsigned int nr_balance_failed;
	u64 max_newidle_lb_cost;
	long unsigned int last_decay_max_lb_cost;
	u64 avg_scan_cost;
	char *name;
	union {
		void *private;
		struct callback_head rcu;
	};
	struct sched_domain_shared *shared;
	unsigned int span_weight;
	long unsigned int span[0];
};

struct sched_group_capacity;

struct sched_group {
	struct sched_group *next;
	atomic_t ref;
	unsigned int group_weight;
	struct sched_group_capacity *sgc;
	int asym_prefer_cpu;
	int flags;
	long unsigned int cpumask[0];
};

struct sched_group_capacity {
	atomic_t ref;
	long unsigned int capacity;
	long unsigned int min_capacity;
	long unsigned int max_capacity;
	long unsigned int next_update;
	int imbalance;
	int id;
	long unsigned int cpumask[0];
};

struct em_perf_state {
	long unsigned int frequency;
	long unsigned int power;
	long unsigned int cost;
	long unsigned int flags;
};

struct em_perf_domain {
	struct em_perf_state *table;
	int nr_perf_states;
	long unsigned int flags;
	long unsigned int cpus[0];
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

struct sched_attr {
	__u32 size;
	__u32 sched_policy;
	__u64 sched_flags;
	__s32 sched_nice;
	__u32 sched_priority;
	__u64 sched_runtime;
	__u64 sched_deadline;
	__u64 sched_period;
	__u32 sched_util_min;
	__u32 sched_util_max;
};

struct trace_event_raw_sched_kthread_stop {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	char __data[0];
};

struct trace_event_raw_sched_kthread_stop_ret {
	struct trace_entry ent;
	int ret;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_queue_work {
	struct trace_entry ent;
	void *work;
	void *function;
	void *worker;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_execute_start {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_execute_end {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_sched_wakeup_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int target_cpu;
	char __data[0];
};

struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};

struct trace_event_raw_sched_migrate_task {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int orig_cpu;
	int dest_cpu;
	char __data[0];
};

struct trace_event_raw_sched_process_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_process_wait {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	char parent_comm[16];
	pid_t parent_pid;
	char child_comm[16];
	pid_t child_pid;
	char __data[0];
};

struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
};

struct trace_event_raw_sched_stat_runtime {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 runtime;
	u64 vruntime;
	char __data[0];
};

struct trace_event_raw_sched_pi_setprio {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int oldprio;
	int newprio;
	char __data[0];
};

struct trace_event_raw_sched_move_numa {
	struct trace_entry ent;
	pid_t pid;
	pid_t tgid;
	pid_t ngid;
	int src_cpu;
	int src_nid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};

struct trace_event_raw_sched_numa_pair_template {
	struct trace_entry ent;
	pid_t src_pid;
	pid_t src_tgid;
	pid_t src_ngid;
	int src_cpu;
	int src_nid;
	pid_t dst_pid;
	pid_t dst_tgid;
	pid_t dst_ngid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};

struct trace_event_raw_sched_wake_idle_without_ipi {
	struct trace_entry ent;
	int cpu;
	char __data[0];
};

struct trace_event_data_offsets_sched_kthread_stop {};

struct trace_event_data_offsets_sched_kthread_stop_ret {};

struct trace_event_data_offsets_sched_kthread_work_queue_work {};

struct trace_event_data_offsets_sched_kthread_work_execute_start {};

struct trace_event_data_offsets_sched_kthread_work_execute_end {};

struct trace_event_data_offsets_sched_wakeup_template {};

struct trace_event_data_offsets_sched_switch {};

struct trace_event_data_offsets_sched_migrate_task {};

struct trace_event_data_offsets_sched_process_template {};

struct trace_event_data_offsets_sched_process_wait {};

struct trace_event_data_offsets_sched_process_fork {};

struct trace_event_data_offsets_sched_process_exec {
	u32 filename;
};

struct trace_event_data_offsets_sched_stat_runtime {};

struct trace_event_data_offsets_sched_pi_setprio {};

struct trace_event_data_offsets_sched_move_numa {};

struct trace_event_data_offsets_sched_numa_pair_template {};

struct trace_event_data_offsets_sched_wake_idle_without_ipi {};

typedef void (*btf_trace_sched_kthread_stop)(void *, struct task_struct *);

typedef void (*btf_trace_sched_kthread_stop_ret)(void *, int);

typedef void (*btf_trace_sched_kthread_work_queue_work)(void *, struct kthread_worker *, struct kthread_work *);

typedef void (*btf_trace_sched_kthread_work_execute_start)(void *, struct kthread_work *);

typedef void (*btf_trace_sched_kthread_work_execute_end)(void *, struct kthread_work *, kthread_work_func_t);

typedef void (*btf_trace_sched_waking)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wakeup)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wakeup_new)(void *, struct task_struct *);

typedef void (*btf_trace_sched_switch)(void *, bool, struct task_struct *, struct task_struct *, unsigned int);

typedef void (*btf_trace_sched_migrate_task)(void *, struct task_struct *, int);

typedef void (*btf_trace_sched_process_free)(void *, struct task_struct *);

typedef void (*btf_trace_sched_process_exit)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wait_task)(void *, struct task_struct *);

typedef void (*btf_trace_sched_process_wait)(void *, struct pid *);

typedef void (*btf_trace_sched_process_fork)(void *, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_process_exec)(void *, struct task_struct *, pid_t, struct linux_binprm *);

typedef void (*btf_trace_sched_stat_runtime)(void *, struct task_struct *, u64, u64);

typedef void (*btf_trace_sched_pi_setprio)(void *, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_move_numa)(void *, struct task_struct *, int, int);

typedef void (*btf_trace_sched_stick_numa)(void *, struct task_struct *, int, struct task_struct *, int);

typedef void (*btf_trace_sched_swap_numa)(void *, struct task_struct *, int, struct task_struct *, int);

typedef void (*btf_trace_sched_wake_idle_without_ipi)(void *, int);

struct cfs_rq;

typedef void (*btf_trace_pelt_cfs_tp)(void *, struct cfs_rq *);

struct cfs_rq {
	struct load_weight load;
	unsigned int nr_running;
	unsigned int h_nr_running;
	unsigned int idle_nr_running;
	unsigned int idle_h_nr_running;
	u64 exec_clock;
	u64 min_vruntime;
	struct rb_root_cached tasks_timeline;
	struct sched_entity *curr;
	struct sched_entity *next;
	struct sched_entity *last;
	struct sched_entity *skip;
	unsigned int nr_spread_over;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg;
	struct {
		raw_spinlock_t lock;
		int nr;
		long unsigned int load_avg;
		long unsigned int util_avg;
		long unsigned int runnable_avg;
		long: 64;
		long: 64;
		long: 64;
		long: 64;
	} removed;
};

typedef void (*btf_trace_pelt_rt_tp)(void *, struct rq *);

struct rt_prio_array {
	long unsigned int bitmap[2];
	struct list_head queue[100];
};

struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
	struct {
		int curr;
		int next;
	} highest_prio;
	unsigned int rt_nr_migratory;
	unsigned int rt_nr_total;
	int overloaded;
	struct plist_head pushable_tasks;
	int rt_queued;
	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	raw_spinlock_t rt_runtime_lock;
};

struct dl_rq {
	struct rb_root_cached root;
	unsigned int dl_nr_running;
	struct {
		u64 curr;
		u64 next;
	} earliest_dl;
	unsigned int dl_nr_migratory;
	int overloaded;
	struct rb_root_cached pushable_dl_tasks_root;
	u64 running_bw;
	u64 this_bw;
	u64 extra_bw;
	u64 bw_ratio;
};

typedef int (*cpu_stop_fn_t)(void *);

struct cpu_stop_done;

struct cpu_stop_work {
	struct list_head list;
	cpu_stop_fn_t fn;
	long unsigned int caller;
	void *arg;
	struct cpu_stop_done *done;
};

struct balance_callback;

struct rq {
	raw_spinlock_t __lock;
	unsigned int nr_running;
	unsigned int ttwu_pending;
	u64 nr_switches;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;
	unsigned int nr_uninterruptible;
	struct task_struct *curr;
	struct task_struct *idle;
	struct task_struct *stop;
	long unsigned int next_balance;
	struct mm_struct *prev_mm;
	unsigned int clock_update_flags;
	u64 clock;
	u64 clock_task;
	u64 clock_pelt;
	long unsigned int lost_idle_time;
	u64 clock_pelt_idle;
	u64 clock_idle;
	atomic_t nr_iowait;
	u64 last_seen_need_resched_ns;
	int ticks_without_resched;
	struct root_domain *rd;
	struct sched_domain *sd;
	long unsigned int cpu_capacity;
	long unsigned int cpu_capacity_orig;
	struct balance_callback *balance_callback;
	unsigned char nohz_idle_balance;
	unsigned char idle_balance;
	long unsigned int misfit_task_load;
	int active_balance;
	int push_cpu;
	struct cpu_stop_work active_balance_work;
	int cpu;
	int online;
	struct list_head cfs_tasks;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct sched_avg avg_rt;
	struct sched_avg avg_dl;
	u64 idle_stamp;
	u64 avg_idle;
	long unsigned int wake_stamp;
	u64 wake_avg_idle;
	u64 max_idle_balance_cost;
	struct rcuwait hotplug_wait;
	long unsigned int calc_load_update;
	long int calc_load_active;
	unsigned int nr_pinned;
	unsigned int push_busy;
	struct cpu_stop_work push_work;
	cpumask_var_t scratch_mask;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

typedef void (*btf_trace_pelt_dl_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_thermal_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_irq_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_se_tp)(void *, struct sched_entity *);

typedef void (*btf_trace_sched_cpu_capacity_tp)(void *, struct rq *);

typedef void (*btf_trace_sched_overutilized_tp)(void *, struct root_domain *, bool);

typedef void (*btf_trace_sched_util_est_cfs_tp)(void *, struct cfs_rq *);

typedef void (*btf_trace_sched_util_est_se_tp)(void *, struct sched_entity *);

typedef void (*btf_trace_sched_update_nr_running_tp)(void *, struct rq *, int);

struct trace_event_raw_ipi_raise {
	struct trace_entry ent;
	u32 __data_loc_target_cpus;
	const char *reason;
	char __data[0];
};

struct trace_event_raw_ipi_send_cpu {
	struct trace_entry ent;
	unsigned int cpu;
	void *callsite;
	void *callback;
	char __data[0];
};

struct trace_event_raw_ipi_send_cpumask {
	struct trace_entry ent;
	u32 __data_loc_cpumask;
	void *callsite;
	void *callback;
	char __data[0];
};

struct trace_event_raw_ipi_handler {
	struct trace_entry ent;
	const char *reason;
	char __data[0];
};

struct trace_event_data_offsets_ipi_raise {
	u32 target_cpus;
};

struct trace_event_data_offsets_ipi_send_cpu {};

struct trace_event_data_offsets_ipi_send_cpumask {
	u32 cpumask;
};

struct trace_event_data_offsets_ipi_handler {};

typedef void (*btf_trace_ipi_raise)(void *, const struct cpumask *, const char *);

typedef void (*btf_trace_ipi_send_cpu)(void *, const unsigned int, long unsigned int, void *);

typedef void (*btf_trace_ipi_send_cpumask)(void *, const struct cpumask *, long unsigned int, void *);

typedef void (*btf_trace_ipi_entry)(void *, const char *);

typedef void (*btf_trace_ipi_exit)(void *, const char *);

struct cpudl_item {
	u64 dl;
	int cpu;
	int idx;
};

struct rt_bandwidth {
	raw_spinlock_t rt_runtime_lock;
	ktime_t rt_period;
	u64 rt_runtime;
	struct hrtimer rt_period_timer;
	unsigned int rt_period_active;
};

struct perf_domain {
	struct em_perf_domain *em_pd;
	struct perf_domain *next;
	struct callback_head rcu;
};

struct balance_callback {
	struct balance_callback *next;
	void (*func)(struct rq *);
};

struct rq_flags {
	long unsigned int flags;
	struct pin_cookie cookie;
	unsigned int clock_update_flags;
};

enum {
	__SCHED_FEAT_GENTLE_FAIR_SLEEPERS = 0,
	__SCHED_FEAT_START_DEBIT = 1,
	__SCHED_FEAT_NEXT_BUDDY = 2,
	__SCHED_FEAT_LAST_BUDDY = 3,
	__SCHED_FEAT_CACHE_HOT_BUDDY = 4,
	__SCHED_FEAT_WAKEUP_PREEMPTION = 5,
	__SCHED_FEAT_HRTICK = 6,
	__SCHED_FEAT_HRTICK_DL = 7,
	__SCHED_FEAT_DOUBLE_TICK = 8,
	__SCHED_FEAT_NONTASK_CAPACITY = 9,
	__SCHED_FEAT_TTWU_QUEUE = 10,
	__SCHED_FEAT_SIS_PROP = 11,
	__SCHED_FEAT_SIS_UTIL = 12,
	__SCHED_FEAT_WARN_DOUBLE_CLOCK = 13,
	__SCHED_FEAT_RT_PUSH_IPI = 14,
	__SCHED_FEAT_RT_RUNTIME_SHARE = 15,
	__SCHED_FEAT_LB_MIN = 16,
	__SCHED_FEAT_ATTACH_AGE_LOAD = 17,
	__SCHED_FEAT_WA_IDLE = 18,
	__SCHED_FEAT_WA_WEIGHT = 19,
	__SCHED_FEAT_WA_BIAS = 20,
	__SCHED_FEAT_UTIL_EST = 21,
	__SCHED_FEAT_UTIL_EST_FASTUP = 22,
	__SCHED_FEAT_LATENCY_WARN = 23,
	__SCHED_FEAT_ALT_PERIOD = 24,
	__SCHED_FEAT_BASE_SLICE = 25,
	__SCHED_FEAT_NR = 26,
};

struct affinity_context {
	const struct cpumask *new_mask;
	struct cpumask *user_mask;
	unsigned int flags;
};

enum cpu_util_type {
	FREQUENCY_UTIL = 0,
	ENERGY_UTIL = 1,
};

enum {
	IOSQE_FIXED_FILE_BIT = 0,
	IOSQE_IO_DRAIN_BIT = 1,
	IOSQE_IO_LINK_BIT = 2,
	IOSQE_IO_HARDLINK_BIT = 3,
	IOSQE_ASYNC_BIT = 4,
	IOSQE_BUFFER_SELECT_BIT = 5,
	IOSQE_CQE_SKIP_SUCCESS_BIT = 6,
};

enum io_uring_op {
	IORING_OP_NOP = 0,
	IORING_OP_READV = 1,
	IORING_OP_WRITEV = 2,
	IORING_OP_FSYNC = 3,
	IORING_OP_READ_FIXED = 4,
	IORING_OP_WRITE_FIXED = 5,
	IORING_OP_POLL_ADD = 6,
	IORING_OP_POLL_REMOVE = 7,
	IORING_OP_SYNC_FILE_RANGE = 8,
	IORING_OP_SENDMSG = 9,
	IORING_OP_RECVMSG = 10,
	IORING_OP_TIMEOUT = 11,
	IORING_OP_TIMEOUT_REMOVE = 12,
	IORING_OP_ACCEPT = 13,
	IORING_OP_ASYNC_CANCEL = 14,
	IORING_OP_LINK_TIMEOUT = 15,
	IORING_OP_CONNECT = 16,
	IORING_OP_FALLOCATE = 17,
	IORING_OP_OPENAT = 18,
	IORING_OP_CLOSE = 19,
	IORING_OP_FILES_UPDATE = 20,
	IORING_OP_STATX = 21,
	IORING_OP_READ = 22,
	IORING_OP_WRITE = 23,
	IORING_OP_FADVISE = 24,
	IORING_OP_MADVISE = 25,
	IORING_OP_SEND = 26,
	IORING_OP_RECV = 27,
	IORING_OP_OPENAT2 = 28,
	IORING_OP_EPOLL_CTL = 29,
	IORING_OP_SPLICE = 30,
	IORING_OP_PROVIDE_BUFFERS = 31,
	IORING_OP_REMOVE_BUFFERS = 32,
	IORING_OP_TEE = 33,
	IORING_OP_SHUTDOWN = 34,
	IORING_OP_RENAMEAT = 35,
	IORING_OP_UNLINKAT = 36,
	IORING_OP_MKDIRAT = 37,
	IORING_OP_SYMLINKAT = 38,
	IORING_OP_LINKAT = 39,
	IORING_OP_MSG_RING = 40,
	IORING_OP_FSETXATTR = 41,
	IORING_OP_SETXATTR = 42,
	IORING_OP_FGETXATTR = 43,
	IORING_OP_GETXATTR = 44,
	IORING_OP_SOCKET = 45,
	IORING_OP_URING_CMD = 46,
	IORING_OP_SEND_ZC = 47,
	IORING_OP_SENDMSG_ZC = 48,
	IORING_OP_LAST = 49,
};

enum {
	IORING_REGISTER_BUFFERS = 0,
	IORING_UNREGISTER_BUFFERS = 1,
	IORING_REGISTER_FILES = 2,
	IORING_UNREGISTER_FILES = 3,
	IORING_REGISTER_EVENTFD = 4,
	IORING_UNREGISTER_EVENTFD = 5,
	IORING_REGISTER_FILES_UPDATE = 6,
	IORING_REGISTER_EVENTFD_ASYNC = 7,
	IORING_REGISTER_PROBE = 8,
	IORING_REGISTER_PERSONALITY = 9,
	IORING_UNREGISTER_PERSONALITY = 10,
	IORING_REGISTER_RESTRICTIONS = 11,
	IORING_REGISTER_ENABLE_RINGS = 12,
	IORING_REGISTER_FILES2 = 13,
	IORING_REGISTER_FILES_UPDATE2 = 14,
	IORING_REGISTER_BUFFERS2 = 15,
	IORING_REGISTER_BUFFERS_UPDATE = 16,
	IORING_REGISTER_IOWQ_AFF = 17,
	IORING_UNREGISTER_IOWQ_AFF = 18,
	IORING_REGISTER_IOWQ_MAX_WORKERS = 19,
	IORING_REGISTER_RING_FDS = 20,
	IORING_UNREGISTER_RING_FDS = 21,
	IORING_REGISTER_PBUF_RING = 22,
	IORING_UNREGISTER_PBUF_RING = 23,
	IORING_REGISTER_SYNC_CANCEL = 24,
	IORING_REGISTER_FILE_ALLOC_RANGE = 25,
	IORING_REGISTER_LAST = 26,
	IORING_REGISTER_USE_REGISTERED_RING = 2147483648,
};

enum {
	REQ_F_FIXED_FILE_BIT = 0,
	REQ_F_IO_DRAIN_BIT = 1,
	REQ_F_LINK_BIT = 2,
	REQ_F_HARDLINK_BIT = 3,
	REQ_F_FORCE_ASYNC_BIT = 4,
	REQ_F_BUFFER_SELECT_BIT = 5,
	REQ_F_CQE_SKIP_BIT = 6,
	REQ_F_FAIL_BIT = 8,
	REQ_F_INFLIGHT_BIT = 9,
	REQ_F_CUR_POS_BIT = 10,
	REQ_F_NOWAIT_BIT = 11,
	REQ_F_LINK_TIMEOUT_BIT = 12,
	REQ_F_NEED_CLEANUP_BIT = 13,
	REQ_F_POLLED_BIT = 14,
	REQ_F_BUFFER_SELECTED_BIT = 15,
	REQ_F_BUFFER_RING_BIT = 16,
	REQ_F_REISSUE_BIT = 17,
	REQ_F_CREDS_BIT = 18,
	REQ_F_REFCOUNT_BIT = 19,
	REQ_F_ARM_LTIMEOUT_BIT = 20,
	REQ_F_ASYNC_DATA_BIT = 21,
	REQ_F_SKIP_LINK_CQES_BIT = 22,
	REQ_F_SINGLE_POLL_BIT = 23,
	REQ_F_DOUBLE_POLL_BIT = 24,
	REQ_F_PARTIAL_IO_BIT = 25,
	REQ_F_CQE32_INIT_BIT = 26,
	REQ_F_APOLL_MULTISHOT_BIT = 27,
	REQ_F_CLEAR_POLLIN_BIT = 28,
	REQ_F_HASH_LOCKED_BIT = 29,
	REQ_F_SUPPORT_NOWAIT_BIT = 30,
	REQ_F_ISREG_BIT = 31,
	__REQ_F_LAST_BIT = 32,
};

struct set_affinity_pending;

struct migration_arg {
	struct task_struct *task;
	int dest_cpu;
	struct set_affinity_pending *pending;
};

struct set_affinity_pending {
	refcount_t refs;
	unsigned int stop_pending;
	struct completion done;
	struct cpu_stop_work stop_work;
	struct migration_arg arg;
};

enum {
	cpuset = 0,
	possible = 1,
	fail = 2,
};

union cpumask_rcuhead {
	cpumask_t cpumask;
	struct callback_head rcu;
};

enum {
	TRACE_FTRACE_BIT = 0,
	TRACE_FTRACE_NMI_BIT = 1,
	TRACE_FTRACE_IRQ_BIT = 2,
	TRACE_FTRACE_SIRQ_BIT = 3,
	TRACE_FTRACE_TRANSITION_BIT = 4,
	TRACE_INTERNAL_BIT = 5,
	TRACE_INTERNAL_NMI_BIT = 6,
	TRACE_INTERNAL_IRQ_BIT = 7,
	TRACE_INTERNAL_SIRQ_BIT = 8,
	TRACE_INTERNAL_TRANSITION_BIT = 9,
	TRACE_BRANCH_BIT = 10,
	TRACE_IRQ_BIT = 11,
	TRACE_GRAPH_BIT = 12,
	TRACE_GRAPH_DEPTH_START_BIT = 13,
	TRACE_GRAPH_DEPTH_END_BIT = 14,
	TRACE_GRAPH_NOTRACE_BIT = 15,
	TRACE_RECORD_RECURSION_BIT = 16,
};

enum {
	TRACE_CTX_NMI = 0,
	TRACE_CTX_IRQ = 1,
	TRACE_CTX_SOFTIRQ = 2,
	TRACE_CTX_NORMAL = 3,
	TRACE_CTX_TRANSITION = 4,
};

enum trace_flag_type {
	TRACE_FLAG_IRQS_OFF = 1,
	TRACE_FLAG_IRQS_NOSUPPORT = 2,
	TRACE_FLAG_NEED_RESCHED = 4,
	TRACE_FLAG_HARDIRQ = 8,
	TRACE_FLAG_SOFTIRQ = 16,
	TRACE_FLAG_PREEMPT_RESCHED = 32,
	TRACE_FLAG_NMI = 64,
	TRACE_FLAG_BH_OFF = 128,
};

enum trace_type {
	__TRACE_FIRST_TYPE = 0,
	TRACE_FN = 1,
	TRACE_CTX = 2,
	TRACE_WAKE = 3,
	TRACE_STACK = 4,
	TRACE_PRINT = 5,
	TRACE_BPRINT = 6,
	TRACE_MMIO_RW = 7,
	TRACE_MMIO_MAP = 8,
	TRACE_BRANCH = 9,
	TRACE_GRAPH_RET = 10,
	TRACE_GRAPH_ENT = 11,
	TRACE_USER_STACK = 12,
	TRACE_BLK = 13,
	TRACE_BPUTS = 14,
	TRACE_HWLAT = 15,
	TRACE_OSNOISE = 16,
	TRACE_TIMERLAT = 17,
	TRACE_RAW_DATA = 18,
	TRACE_FUNC_REPEATS = 19,
	__TRACE_LAST_TYPE = 20,
};

struct ftrace_entry {
	struct trace_entry ent;
	long unsigned int ip;
	long unsigned int parent_ip;
};

typedef long unsigned int perf_trace_t[1024];

struct bpf_preload_info {
	char link_name[16];
	struct bpf_link *link;
};

struct bpf_preload_ops {
	int (*preload)(struct bpf_preload_info *);
	struct module *owner;
};

enum bpf_type {
	BPF_TYPE_UNSPEC = 0,
	BPF_TYPE_PROG = 1,
	BPF_TYPE_MAP = 2,
	BPF_TYPE_LINK = 3,
};

struct map_iter {
	void *key;
	bool done;
};

enum {
	OPT_MODE = 0,
};

struct bpf_mount_opts {
	umode_t mode;
};

struct bpf_iter_seq_link_info {
	u32 link_id;
};

struct bpf_iter__bpf_link {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_link *link;
	};
};

struct bpf_lpm_trie_key {
	__u32 prefixlen;
	__u8 data[0];
};

enum {
	BTF_KIND_UNKN = 0,
	BTF_KIND_INT = 1,
	BTF_KIND_PTR = 2,
	BTF_KIND_ARRAY = 3,
	BTF_KIND_STRUCT = 4,
	BTF_KIND_UNION = 5,
	BTF_KIND_ENUM = 6,
	BTF_KIND_FWD = 7,
	BTF_KIND_TYPEDEF = 8,
	BTF_KIND_VOLATILE = 9,
	BTF_KIND_CONST = 10,
	BTF_KIND_RESTRICT = 11,
	BTF_KIND_FUNC = 12,
	BTF_KIND_FUNC_PROTO = 13,
	BTF_KIND_VAR = 14,
	BTF_KIND_DATASEC = 15,
	BTF_KIND_FLOAT = 16,
	BTF_KIND_DECL_TAG = 17,
	BTF_KIND_TYPE_TAG = 18,
	BTF_KIND_ENUM64 = 19,
	NR_BTF_KINDS = 20,
	BTF_KIND_MAX = 19,
};

struct lpm_trie_node {
	struct callback_head rcu;
	struct lpm_trie_node *child[2];
	u32 prefixlen;
	u32 flags;
	u8 data[0];
};

struct lpm_trie {
	struct bpf_map map;
	struct lpm_trie_node *root;
	size_t n_entries;
	size_t max_prefixlen;
	size_t data_size;
	spinlock_t lock;
	long: 64;
	long: 64;
	long: 64;
};

struct btf_id_set8 {
	u32 cnt;
	u32 flags;
	struct {
		u32 id;
		u32 flags;
	} pairs[0];
};

struct btf_kfunc_id_set {
	struct module *owner;
	struct btf_id_set8 *set;
};

struct btf_id_dtor_kfunc {
	u32 btf_id;
	u32 kfunc_btf_id;
};

enum bpf_cgroup_storage_type {
	BPF_CGROUP_STORAGE_SHARED = 0,
	BPF_CGROUP_STORAGE_PERCPU = 1,
	__BPF_CGROUP_STORAGE_MAX = 2,
};

struct bpf_cpumask {
	cpumask_t cpumask;
	struct callback_head rcu;
	refcount_t usage;
};

typedef struct {
	int val[2];
} __kernel_fsid_t;

struct fileattr {
	u32 flags;
	u32 fsx_xflags;
	u32 fsx_extsize;
	u32 fsx_nextents;
	u32 fsx_projid;
	u32 fsx_cowextsize;
	bool flags_valid: 1;
	bool fsx_valid: 1;
};

struct kstatfs {
	long int f_type;
	long int f_bsize;
	u64 f_blocks;
	u64 f_bfree;
	u64 f_bavail;
	u64 f_files;
	u64 f_ffree;
	__kernel_fsid_t f_fsid;
	long int f_namelen;
	long int f_frsize;
	long int f_flags;
	long int f_spare[4];
};

enum meminit_context {
	MEMINIT_EARLY = 0,
	MEMINIT_HOTPLUG = 1,
};

struct kmem_cache_order_objects {
	unsigned int x;
};

struct kmem_cache_cpu;

struct kmem_cache_node;

struct kmem_cache {
	struct kmem_cache_cpu *cpu_slab;
	slab_flags_t flags;
	long unsigned int min_partial;
	unsigned int size;
	unsigned int object_size;
	struct reciprocal_value reciprocal_size;
	unsigned int offset;
	unsigned int cpu_partial;
	unsigned int cpu_partial_slabs;
	struct kmem_cache_order_objects oo;
	struct kmem_cache_order_objects min;
	gfp_t allocflags;
	int refcount;
	void (*ctor)(void *);
	unsigned int inuse;
	unsigned int align;
	unsigned int red_left_pad;
	const char *name;
	struct list_head list;
	struct kmem_cache_node *node[1];
};

struct slab {
	long unsigned int __page_flags;
	struct kmem_cache *slab_cache;
	union {
		struct {
			union {
				struct list_head slab_list;
				struct {
					struct slab *next;
					int slabs;
				};
			};
			void *freelist;
			union {
				long unsigned int counters;
				struct {
					unsigned int inuse: 16;
					unsigned int objects: 15;
					unsigned int frozen: 1;
				};
			};
		};
		struct callback_head callback_head;
	};
	unsigned int __unused;
	atomic_t __page_refcount;
};

struct kmem_cache_cpu {
	void **freelist;
	long unsigned int tid;
	struct slab *slab;
	struct slab *partial;
	local_lock_t lock;
};

struct kmem_cache_node {
	spinlock_t list_lock;
	long unsigned int nr_partial;
	struct list_head partial;
};

typedef struct {
	long unsigned int pd;
} hugepd_t;

typedef struct page *new_page_t(struct page *, long unsigned int);

typedef void free_page_t(struct page *, long unsigned int);

struct migration_target_control {
	int nid;
	nodemask_t *nmask;
	gfp_t gfp_mask;
};

enum {
	FOLL_TOUCH = 65536,
	FOLL_TRIED = 131072,
	FOLL_REMOTE = 262144,
	FOLL_PIN = 524288,
	FOLL_FAST_ONLY = 1048576,
	FOLL_UNLOCKABLE = 2097152,
};

struct follow_page_context {
	struct dev_pagemap *pgmap;
	unsigned int page_mask;
};

struct hstate {};

enum pgt_entry {
	NORMAL_PMD = 0,
	HPAGE_PMD = 1,
	NORMAL_PUD = 2,
	HPAGE_PUD = 3,
};

typedef unsigned int isolate_mode_t;

enum vm_event_item {
	PGPGIN = 0,
	PGPGOUT = 1,
	PSWPIN = 2,
	PSWPOUT = 3,
	PGALLOC_DMA = 4,
	PGALLOC_DMA32 = 5,
	PGALLOC_NORMAL = 6,
	PGALLOC_MOVABLE = 7,
	ALLOCSTALL_DMA = 8,
	ALLOCSTALL_DMA32 = 9,
	ALLOCSTALL_NORMAL = 10,
	ALLOCSTALL_MOVABLE = 11,
	PGSCAN_SKIP_DMA = 12,
	PGSCAN_SKIP_DMA32 = 13,
	PGSCAN_SKIP_NORMAL = 14,
	PGSCAN_SKIP_MOVABLE = 15,
	PGFREE = 16,
	PGACTIVATE = 17,
	PGDEACTIVATE = 18,
	PGLAZYFREE = 19,
	PGFAULT = 20,
	PGMAJFAULT = 21,
	PGLAZYFREED = 22,
	PGREFILL = 23,
	PGREUSE = 24,
	PGSTEAL_KSWAPD = 25,
	PGSTEAL_DIRECT = 26,
	PGSTEAL_KHUGEPAGED = 27,
	PGDEMOTE_KSWAPD = 28,
	PGDEMOTE_DIRECT = 29,
	PGDEMOTE_KHUGEPAGED = 30,
	PGSCAN_KSWAPD = 31,
	PGSCAN_DIRECT = 32,
	PGSCAN_KHUGEPAGED = 33,
	PGSCAN_DIRECT_THROTTLE = 34,
	PGSCAN_ANON = 35,
	PGSCAN_FILE = 36,
	PGSTEAL_ANON = 37,
	PGSTEAL_FILE = 38,
	PGINODESTEAL = 39,
	SLABS_SCANNED = 40,
	KSWAPD_INODESTEAL = 41,
	KSWAPD_LOW_WMARK_HIT_QUICKLY = 42,
	KSWAPD_HIGH_WMARK_HIT_QUICKLY = 43,
	PAGEOUTRUN = 44,
	PGROTATED = 45,
	DROP_PAGECACHE = 46,
	DROP_SLAB = 47,
	OOM_KILL = 48,
	PGMIGRATE_SUCCESS = 49,
	PGMIGRATE_FAIL = 50,
	THP_MIGRATION_SUCCESS = 51,
	THP_MIGRATION_FAIL = 52,
	THP_MIGRATION_SPLIT = 53,
	UNEVICTABLE_PGCULLED = 54,
	UNEVICTABLE_PGSCANNED = 55,
	UNEVICTABLE_PGRESCUED = 56,
	UNEVICTABLE_PGMLOCKED = 57,
	UNEVICTABLE_PGMUNLOCKED = 58,
	UNEVICTABLE_PGCLEARED = 59,
	UNEVICTABLE_PGSTRANDED = 60,
	NR_VM_EVENT_ITEMS = 61,
};

struct movable_operations {
	bool (*isolate_page)(struct page *, isolate_mode_t);
	int (*migrate_page)(struct page *, struct page *, enum migrate_mode);
	void (*putback_page)(struct page *);
};

enum ttu_flags {
	TTU_SPLIT_HUGE_PMD = 4,
	TTU_IGNORE_MLOCK = 8,
	TTU_SYNC = 16,
	TTU_HWPOISON = 32,
	TTU_BATCH_FLUSH = 64,
	TTU_RMAP_LOCKED = 128,
};

typedef int rmap_t;

struct page_vma_mapped_walk {
	long unsigned int pfn;
	long unsigned int nr_pages;
	long unsigned int pgoff;
	struct vm_area_struct *vma;
	long unsigned int address;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned int flags;
};

struct rmap_walk_control {
	void *arg;
	bool try_lock;
	bool contended;
	bool (*rmap_one)(struct folio *, struct vm_area_struct *, long unsigned int, void *);
	int (*done)(struct folio *);
	struct anon_vma * (*anon_lock)(struct folio *, struct rmap_walk_control *);
	bool (*invalid_vma)(struct vm_area_struct *, void *);
};

union migration_ptr {
	struct anon_vma *anon_vma;
	struct address_space *mapping;
};

struct migrate_pages_stats {
	int nr_succeeded;
	int nr_failed_pages;
	int nr_thp_succeeded;
	int nr_thp_failed;
	int nr_thp_split;
};

struct hugepage_subpool;

struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	short unsigned int d_reclen;
	unsigned char d_type;
	char d_name[0];
};

struct linux_dirent {
	long unsigned int d_ino;
	long unsigned int d_off;
	short unsigned int d_reclen;
	char d_name[0];
};

struct getdents_callback {
	struct dir_context ctx;
	struct linux_dirent *current_dir;
	int prev_reclen;
	int count;
	int error;
};

struct getdents_callback64 {
	struct dir_context ctx;
	struct linux_dirent64 *current_dir;
	int prev_reclen;
	int count;
	int error;
};

typedef struct ns_common *ns_get_path_helper_t(void *);

struct ns_get_path_task_args {
	const struct proc_ns_operations *ns_ops;
	struct task_struct *task;
};

struct file_dedupe_range_info {
	__s64 dest_fd;
	__u64 dest_offset;
	__u64 bytes_deduped;
	__s32 status;
	__u32 reserved;
};

struct file_dedupe_range {
	__u64 src_offset;
	__u64 src_length;
	__u16 dest_count;
	__u16 reserved1;
	__u32 reserved2;
	struct file_dedupe_range_info info[0];
};

typedef int filler_t(struct file *, struct folio *);

struct iomap_ops;

enum {
	PERCPU_REF_INIT_ATOMIC = 1,
	PERCPU_REF_INIT_DEAD = 2,
	PERCPU_REF_ALLOW_REINIT = 4,
};

struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};

struct syscall_info {
	__u64 sp;
	struct seccomp_data data;
};

enum {
	MSI_FLAG_USE_DEF_DOM_OPS = 1,
	MSI_FLAG_USE_DEF_CHIP_OPS = 2,
	MSI_FLAG_ACTIVATE_EARLY = 4,
	MSI_FLAG_MUST_REACTIVATE = 8,
	MSI_FLAG_DEV_SYSFS = 16,
	MSI_FLAG_ALLOC_SIMPLE_MSI_DESCS = 32,
	MSI_FLAG_FREE_MSI_DESCS = 64,
	MSI_FLAG_NOMASK_QUIRK = 128,
	MSI_GENERIC_FLAGS_MASK = 65535,
	MSI_DOMAIN_FLAGS_MASK = 4294901760,
	MSI_FLAG_MULTI_PCI_MSI = 65536,
	MSI_FLAG_PCI_MSIX = 131072,
	MSI_FLAG_LEVEL_CAPABLE = 262144,
	MSI_FLAG_MSIX_CONTIGUOUS = 524288,
	MSI_FLAG_PCI_MSIX_ALLOC_DYN = 1048576,
	MSI_FLAG_PCI_IMS = 2097152,
};

struct clk_div_table {
	unsigned int val;
	unsigned int div;
};

struct clk_divider {
	struct clk_hw hw;
	void *reg;
	u8 shift;
	u8 width;
	u8 flags;
	const struct clk_div_table *table;
	spinlock_t *lock;
};

struct splice_desc {
	size_t total_len;
	unsigned int len;
	unsigned int flags;
	union {
		void *userptr;
		struct file *file;
		void *data;
	} u;
	loff_t pos;
	loff_t *opos;
	size_t num_spliced;
	bool need_wakeup;
};

typedef int splice_actor(struct pipe_inode_info *, struct pipe_buffer *, struct splice_desc *);

struct memdev {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
	fmode_t fmode;
};

typedef void * (*devcon_match_fn_t)(const struct fwnode_handle *, const char *, void *);

enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_10baseT_Half_BIT = 0,
	ETHTOOL_LINK_MODE_10baseT_Full_BIT = 1,
	ETHTOOL_LINK_MODE_100baseT_Half_BIT = 2,
	ETHTOOL_LINK_MODE_100baseT_Full_BIT = 3,
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT = 4,
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT = 5,
	ETHTOOL_LINK_MODE_Autoneg_BIT = 6,
	ETHTOOL_LINK_MODE_TP_BIT = 7,
	ETHTOOL_LINK_MODE_AUI_BIT = 8,
	ETHTOOL_LINK_MODE_MII_BIT = 9,
	ETHTOOL_LINK_MODE_FIBRE_BIT = 10,
	ETHTOOL_LINK_MODE_BNC_BIT = 11,
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT = 12,
	ETHTOOL_LINK_MODE_Pause_BIT = 13,
	ETHTOOL_LINK_MODE_Asym_Pause_BIT = 14,
	ETHTOOL_LINK_MODE_2500baseX_Full_BIT = 15,
	ETHTOOL_LINK_MODE_Backplane_BIT = 16,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT = 17,
	ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT = 18,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT = 19,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT = 20,
	ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT = 21,
	ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT = 22,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT = 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT = 24,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT = 25,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT = 26,
	ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT = 27,
	ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT = 28,
	ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT = 29,
	ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT = 30,
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT = 31,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT = 32,
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT = 33,
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT = 34,
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT = 35,
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT = 36,
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT = 37,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT = 38,
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT = 39,
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT = 40,
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT = 41,
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT = 42,
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT = 43,
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT = 44,
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT = 45,
	ETHTOOL_LINK_MODE_10000baseER_Full_BIT = 46,
	ETHTOOL_LINK_MODE_2500baseT_Full_BIT = 47,
	ETHTOOL_LINK_MODE_5000baseT_Full_BIT = 48,
	ETHTOOL_LINK_MODE_FEC_NONE_BIT = 49,
	ETHTOOL_LINK_MODE_FEC_RS_BIT = 50,
	ETHTOOL_LINK_MODE_FEC_BASER_BIT = 51,
	ETHTOOL_LINK_MODE_50000baseKR_Full_BIT = 52,
	ETHTOOL_LINK_MODE_50000baseSR_Full_BIT = 53,
	ETHTOOL_LINK_MODE_50000baseCR_Full_BIT = 54,
	ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT = 55,
	ETHTOOL_LINK_MODE_50000baseDR_Full_BIT = 56,
	ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT = 57,
	ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT = 58,
	ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT = 59,
	ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT = 60,
	ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT = 61,
	ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT = 62,
	ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT = 63,
	ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT = 64,
	ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT = 65,
	ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT = 66,
	ETHTOOL_LINK_MODE_100baseT1_Full_BIT = 67,
	ETHTOOL_LINK_MODE_1000baseT1_Full_BIT = 68,
	ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT = 69,
	ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT = 70,
	ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT = 71,
	ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT = 72,
	ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT = 73,
	ETHTOOL_LINK_MODE_FEC_LLRS_BIT = 74,
	ETHTOOL_LINK_MODE_100000baseKR_Full_BIT = 75,
	ETHTOOL_LINK_MODE_100000baseSR_Full_BIT = 76,
	ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT = 77,
	ETHTOOL_LINK_MODE_100000baseCR_Full_BIT = 78,
	ETHTOOL_LINK_MODE_100000baseDR_Full_BIT = 79,
	ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT = 80,
	ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT = 81,
	ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT = 82,
	ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT = 83,
	ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT = 84,
	ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT = 85,
	ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT = 86,
	ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT = 87,
	ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT = 88,
	ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT = 89,
	ETHTOOL_LINK_MODE_100baseFX_Half_BIT = 90,
	ETHTOOL_LINK_MODE_100baseFX_Full_BIT = 91,
	ETHTOOL_LINK_MODE_10baseT1L_Full_BIT = 92,
	ETHTOOL_LINK_MODE_800000baseCR8_Full_BIT = 93,
	ETHTOOL_LINK_MODE_800000baseKR8_Full_BIT = 94,
	ETHTOOL_LINK_MODE_800000baseDR8_Full_BIT = 95,
	ETHTOOL_LINK_MODE_800000baseDR8_2_Full_BIT = 96,
	ETHTOOL_LINK_MODE_800000baseSR8_Full_BIT = 97,
	ETHTOOL_LINK_MODE_800000baseVR8_Full_BIT = 98,
	ETHTOOL_LINK_MODE_10baseT1S_Full_BIT = 99,
	ETHTOOL_LINK_MODE_10baseT1S_Half_BIT = 100,
	ETHTOOL_LINK_MODE_10baseT1S_P2MP_Half_BIT = 101,
	__ETHTOOL_LINK_MODE_MASK_NBITS = 102,
};

typedef enum {
	PHY_INTERFACE_MODE_NA = 0,
	PHY_INTERFACE_MODE_INTERNAL = 1,
	PHY_INTERFACE_MODE_MII = 2,
	PHY_INTERFACE_MODE_GMII = 3,
	PHY_INTERFACE_MODE_SGMII = 4,
	PHY_INTERFACE_MODE_TBI = 5,
	PHY_INTERFACE_MODE_REVMII = 6,
	PHY_INTERFACE_MODE_RMII = 7,
	PHY_INTERFACE_MODE_REVRMII = 8,
	PHY_INTERFACE_MODE_RGMII = 9,
	PHY_INTERFACE_MODE_RGMII_ID = 10,
	PHY_INTERFACE_MODE_RGMII_RXID = 11,
	PHY_INTERFACE_MODE_RGMII_TXID = 12,
	PHY_INTERFACE_MODE_RTBI = 13,
	PHY_INTERFACE_MODE_SMII = 14,
	PHY_INTERFACE_MODE_XGMII = 15,
	PHY_INTERFACE_MODE_XLGMII = 16,
	PHY_INTERFACE_MODE_MOCA = 17,
	PHY_INTERFACE_MODE_QSGMII = 18,
	PHY_INTERFACE_MODE_TRGMII = 19,
	PHY_INTERFACE_MODE_100BASEX = 20,
	PHY_INTERFACE_MODE_1000BASEX = 21,
	PHY_INTERFACE_MODE_2500BASEX = 22,
	PHY_INTERFACE_MODE_5GBASER = 23,
	PHY_INTERFACE_MODE_RXAUI = 24,
	PHY_INTERFACE_MODE_XAUI = 25,
	PHY_INTERFACE_MODE_10GBASER = 26,
	PHY_INTERFACE_MODE_25GBASER = 27,
	PHY_INTERFACE_MODE_USXGMII = 28,
	PHY_INTERFACE_MODE_10GKR = 29,
	PHY_INTERFACE_MODE_QUSGMII = 30,
	PHY_INTERFACE_MODE_1000BASEKX = 31,
	PHY_INTERFACE_MODE_MAX = 32,
} phy_interface_t;

typedef struct {
	u32 version;
	u32 num_entries;
	u32 desc_size;
	u32 flags;
	efi_memory_desc_t entry[0];
} efi_memory_attributes_table_t;

struct arm_pmu;

struct pmu_hw_events {
	struct perf_event *events[32];
	long unsigned int used_mask[1];
	raw_spinlock_t pmu_lock;
	struct arm_pmu *percpu_pmu;
	int irq;
};

struct arm_pmu {
	struct pmu pmu;
	cpumask_t supported_cpus;
	char *name;
	int pmuver;
	irqreturn_t (*handle_irq)(struct arm_pmu *);
	void (*enable)(struct perf_event *);
	void (*disable)(struct perf_event *);
	int (*get_event_idx)(struct pmu_hw_events *, struct perf_event *);
	void (*clear_event_idx)(struct pmu_hw_events *, struct perf_event *);
	int (*set_event_filter)(struct hw_perf_event *, struct perf_event_attr *);
	u64 (*read_counter)(struct perf_event *);
	void (*write_counter)(struct perf_event *, u64);
	void (*start)(struct arm_pmu *);
	void (*stop)(struct arm_pmu *);
	void (*reset)(void *);
	int (*map_event)(struct perf_event *);
	int num_events;
	bool secure_access;
	long unsigned int pmceid_bitmap[1];
	long unsigned int pmceid_ext_bitmap[1];
	struct platform_device *plat_device;
	struct pmu_hw_events *hw_events;
	struct hlist_node node;
	struct notifier_block cpu_pm_nb;
	const struct attribute_group *attr_groups[5];
	u64 reg_pmmir;
	long unsigned int acpi_cpuid;
};

typedef int (*armpmu_init_fn)(struct arm_pmu *);

struct pmu_probe_info {
	unsigned int cpuid;
	unsigned int mask;
	armpmu_init_fn init;
};

enum {
	PER_LINUX = 0,
	PER_LINUX_32BIT = 8388608,
	PER_LINUX_FDPIC = 524288,
	PER_SVR4 = 68157441,
	PER_SVR3 = 83886082,
	PER_SCOSVR3 = 117440515,
	PER_OSR5 = 100663299,
	PER_WYSEV386 = 83886084,
	PER_ISCR4 = 67108869,
	PER_BSD = 6,
	PER_SUNOS = 67108870,
	PER_XENIX = 83886087,
	PER_LINUX32 = 8,
	PER_LINUX32_3GB = 134217736,
	PER_IRIX32 = 67108873,
	PER_IRIXN32 = 67108874,
	PER_IRIX64 = 67108875,
	PER_RISCOS = 12,
	PER_SOLARIS = 67108877,
	PER_UW7 = 68157454,
	PER_OSF4 = 15,
	PER_HPUX = 16,
	PER_MASK = 255,
};

struct subprocess_info {
	struct work_struct work;
	struct completion *complete;
	const char *path;
	char **argv;
	char **envp;
	int wait;
	int retval;
	int (*init)(struct subprocess_info *, struct cred *);
	void (*cleanup)(struct subprocess_info *);
	void *data;
};

struct smpboot_thread_data {
	unsigned int cpu;
	unsigned int status;
	struct smp_hotplug_thread *ht;
};

enum {
	HP_THREAD_NONE = 0,
	HP_THREAD_ACTIVE = 1,
	HP_THREAD_PARKED = 2,
};

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE = 0,
	RWSEM_WAITING_FOR_READ = 1,
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
	long unsigned int timeout;
	bool handoff_set;
};

enum rwsem_wake_type {
	RWSEM_WAKE_ANY = 0,
	RWSEM_WAKE_READERS = 1,
	RWSEM_WAKE_READ_OWNED = 2,
};

enum owner_state {
	OWNER_NULL = 1,
	OWNER_WRITER = 2,
	OWNER_READER = 4,
	OWNER_NONSPINNABLE = 8,
};

struct irq_devres {
	unsigned int irq;
	void *dev_id;
};

struct irq_desc_devres {
	unsigned int from;
	unsigned int cnt;
};

struct trace_event_raw_rcu_utilization {
	struct trace_entry ent;
	const char *s;
	char __data[0];
};

struct trace_event_raw_rcu_stall_warning {
	struct trace_entry ent;
	const char *rcuname;
	const char *msg;
	char __data[0];
};

struct trace_event_data_offsets_rcu_utilization {};

struct trace_event_data_offsets_rcu_stall_warning {};

typedef void (*btf_trace_rcu_utilization)(void *, const char *);

typedef void (*btf_trace_rcu_stall_warning)(void *, const char *, const char *);

struct rcu_tasks;

typedef void (*rcu_tasks_gp_func_t)(struct rcu_tasks *);

typedef void (*pregp_func_t)(struct list_head *);

typedef void (*pertask_func_t)(struct task_struct *, struct list_head *);

typedef void (*postscan_func_t)(struct list_head *);

typedef void (*holdouts_func_t)(struct list_head *, bool, bool *);

typedef void (*postgp_func_t)(struct rcu_tasks *);

struct rcu_tasks_percpu;

struct rcu_tasks {
	struct rcuwait cbs_wait;
	raw_spinlock_t cbs_gbl_lock;
	struct mutex tasks_gp_mutex;
	int gp_state;
	int gp_sleep;
	int init_fract;
	long unsigned int gp_jiffies;
	long unsigned int gp_start;
	long unsigned int tasks_gp_seq;
	long unsigned int n_ipis;
	long unsigned int n_ipis_fails;
	struct task_struct *kthread_ptr;
	rcu_tasks_gp_func_t gp_func;
	pregp_func_t pregp_func;
	pertask_func_t pertask_func;
	postscan_func_t postscan_func;
	holdouts_func_t holdouts_func;
	postgp_func_t postgp_func;
	call_rcu_func_t call_func;
	struct rcu_tasks_percpu *rtpcpu;
	int percpu_enqueue_shift;
	int percpu_enqueue_lim;
	int percpu_dequeue_lim;
	long unsigned int percpu_dequeue_gpseq;
	struct mutex barrier_q_mutex;
	atomic_t barrier_q_count;
	struct completion barrier_q_completion;
	long unsigned int barrier_q_seq;
	char *name;
	char *kname;
};

struct rcu_tasks_percpu {
	struct rcu_segcblist cblist;
	raw_spinlock_t lock;
	long unsigned int rtp_jiffies;
	long unsigned int rtp_n_lock_retries;
	struct work_struct rtp_work;
	struct irq_work rtp_irq_work;
	struct callback_head barrier_q_head;
	struct list_head rtp_blkd_tasks;
	int cpu;
	struct rcu_tasks *rtpp;
};

struct trc_stall_chk_rdr {
	int nesting;
	int ipi_to_cpu;
	u8 needqs;
};

typedef bool (*smp_cond_func_t)(int, void *);

struct __call_single_data {
	struct __call_single_node node;
	smp_call_func_t func;
	void *info;
};

typedef struct __call_single_data call_single_data_t;

typedef struct {
	unsigned int __softirq_pending;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
} irq_cpustat_t;

struct trace_event_raw_csd_queue_cpu {
	struct trace_entry ent;
	unsigned int cpu;
	void *callsite;
	void *func;
	void *csd;
	char __data[0];
};

struct trace_event_raw_csd_function {
	struct trace_entry ent;
	void *func;
	void *csd;
	char __data[0];
};

struct trace_event_data_offsets_csd_queue_cpu {};

struct trace_event_data_offsets_csd_function {};

typedef void (*btf_trace_csd_queue_cpu)(void *, const unsigned int, long unsigned int, smp_call_func_t, struct __call_single_data *);

typedef void (*btf_trace_csd_function_entry)(void *, smp_call_func_t, struct __call_single_data *);

typedef void (*btf_trace_csd_function_exit)(void *, smp_call_func_t, struct __call_single_data *);

struct call_function_data {
	call_single_data_t *csd;
	cpumask_var_t cpumask;
	cpumask_var_t cpumask_ipi;
};

struct smp_call_on_cpu_struct {
	struct work_struct work;
	struct completion done;
	int (*func)(void *);
	void *data;
	int ret;
	int cpu;
};

enum event_trigger_type {
	ETT_NONE = 0,
	ETT_TRACE_ONOFF = 1,
	ETT_SNAPSHOT = 2,
	ETT_STACKTRACE = 4,
	ETT_EVENT_ENABLE = 8,
	ETT_EVENT_HIST = 16,
	ETT_HIST_ENABLE = 32,
	ETT_EVENT_EPROBE = 64,
};

enum {
	EVENT_TRIGGER_FL_PROBE = 1,
};

struct event_trigger_ops;

struct event_command;

struct event_trigger_data {
	long unsigned int count;
	int ref;
	int flags;
	struct event_trigger_ops *ops;
	struct event_command *cmd_ops;
	struct event_filter *filter;
	char *filter_str;
	void *private_data;
	bool paused;
	bool paused_tmp;
	struct list_head list;
	char *name;
	struct list_head named_list;
	struct event_trigger_data *named_data;
};

struct event_trigger_ops {
	void (*trigger)(struct event_trigger_data *, struct trace_buffer *, void *, struct ring_buffer_event *);
	int (*init)(struct event_trigger_data *);
	void (*free)(struct event_trigger_data *);
	int (*print)(struct seq_file *, struct event_trigger_data *);
};

struct event_command {
	struct list_head list;
	char *name;
	enum event_trigger_type trigger_type;
	int flags;
	int (*parse)(struct event_command *, struct trace_event_file *, char *, char *, char *);
	int (*reg)(char *, struct event_trigger_data *, struct trace_event_file *);
	void (*unreg)(char *, struct event_trigger_data *, struct trace_event_file *);
	void (*unreg_all)(struct trace_event_file *);
	int (*set_filter)(char *, struct event_trigger_data *, struct trace_event_file *);
	struct event_trigger_ops * (*get_trigger_ops)(char *, char *);
};

struct enable_trigger_data {
	struct trace_event_file *file;
	bool enable;
	bool hist;
};

enum event_command_flags {
	EVENT_CMD_FL_POST_TRIGGER = 1,
	EVENT_CMD_FL_NEEDS_REC = 2,
};

enum bpf_lru_list_type {
	BPF_LRU_LIST_T_ACTIVE = 0,
	BPF_LRU_LIST_T_INACTIVE = 1,
	BPF_LRU_LIST_T_FREE = 2,
	BPF_LRU_LOCAL_LIST_T_FREE = 3,
	BPF_LRU_LOCAL_LIST_T_PENDING = 4,
};

struct bpf_queue_stack {
	struct bpf_map map;
	raw_spinlock_t lock;
	u32 head;
	u32 tail;
	u32 size;
	char elements[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct bpf_dispatcher_prog {
	struct bpf_prog *prog;
	refcount_t users;
};

struct bpf_dispatcher {
	struct mutex mutex;
	void *func;
	struct bpf_dispatcher_prog progs[48];
	int num_progs;
	void *image;
	void *rw_image;
	u32 image_off;
	struct bpf_ksym ksym;
};

enum lruvec_flags {
	LRUVEC_CONGESTED = 0,
};

enum pgdat_flags {
	PGDAT_DIRTY = 0,
	PGDAT_WRITEBACK = 1,
	PGDAT_RECLAIM_LOCKED = 2,
};

enum zone_flags {
	ZONE_BOOSTED_WATERMARK = 0,
	ZONE_RECLAIM_ACTIVE = 1,
};

struct reclaim_stat {
	unsigned int nr_dirty;
	unsigned int nr_unqueued_dirty;
	unsigned int nr_congested;
	unsigned int nr_writeback;
	unsigned int nr_immediate;
	unsigned int nr_pageout;
	unsigned int nr_activate[2];
	unsigned int nr_ref_keep;
	unsigned int nr_unmap_fail;
	unsigned int nr_lazyfree_fail;
};

enum memcg_memory_event {
	MEMCG_LOW = 0,
	MEMCG_HIGH = 1,
	MEMCG_MAX = 2,
	MEMCG_OOM = 3,
	MEMCG_OOM_KILL = 4,
	MEMCG_OOM_GROUP_KILL = 5,
	MEMCG_SWAP_HIGH = 6,
	MEMCG_SWAP_MAX = 7,
	MEMCG_SWAP_FAIL = 8,
	MEMCG_NR_MEMORY_EVENTS = 9,
};

struct mem_cgroup_reclaim_cookie {
	pg_data_t *pgdat;
	unsigned int generation;
};

enum {
	SWP_USED = 1,
	SWP_WRITEOK = 2,
	SWP_DISCARDABLE = 4,
	SWP_DISCARDING = 8,
	SWP_SOLIDSTATE = 16,
	SWP_CONTINUED = 32,
	SWP_BLKDEV = 64,
	SWP_ACTIVATED = 128,
	SWP_FS_OPS = 256,
	SWP_AREA_DISCARD = 512,
	SWP_PAGE_DISCARD = 1024,
	SWP_STABLE_WRITES = 2048,
	SWP_SYNCHRONOUS_IO = 4096,
	SWP_SCANNING = 16384,
};

enum compact_result {
	COMPACT_NOT_SUITABLE_ZONE = 0,
	COMPACT_SKIPPED = 1,
	COMPACT_DEFERRED = 2,
	COMPACT_NO_SUITABLE_PAGE = 3,
	COMPACT_CONTINUE = 4,
	COMPACT_COMPLETE = 5,
	COMPACT_PARTIAL_SKIPPED = 6,
	COMPACT_CONTENDED = 7,
	COMPACT_SUCCESS = 8,
};

struct trace_event_raw_mm_vmscan_kswapd_sleep {
	struct trace_entry ent;
	int nid;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_kswapd_wake {
	struct trace_entry ent;
	int nid;
	int zid;
	int order;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_wakeup_kswapd {
	struct trace_entry ent;
	int nid;
	int zid;
	int order;
	long unsigned int gfp_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_direct_reclaim_begin_template {
	struct trace_entry ent;
	int order;
	long unsigned int gfp_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_direct_reclaim_end_template {
	struct trace_entry ent;
	long unsigned int nr_reclaimed;
	char __data[0];
};

struct trace_event_raw_mm_shrink_slab_start {
	struct trace_entry ent;
	struct shrinker *shr;
	void *shrink;
	int nid;
	long int nr_objects_to_shrink;
	long unsigned int gfp_flags;
	long unsigned int cache_items;
	long long unsigned int delta;
	long unsigned int total_scan;
	int priority;
	char __data[0];
};

struct trace_event_raw_mm_shrink_slab_end {
	struct trace_entry ent;
	struct shrinker *shr;
	int nid;
	void *shrink;
	long int unused_scan;
	long int new_scan;
	int retval;
	long int total_scan;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_lru_isolate {
	struct trace_entry ent;
	int highest_zoneidx;
	int order;
	long unsigned int nr_requested;
	long unsigned int nr_scanned;
	long unsigned int nr_skipped;
	long unsigned int nr_taken;
	unsigned int isolate_mode;
	int lru;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_write_folio {
	struct trace_entry ent;
	long unsigned int pfn;
	int reclaim_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_lru_shrink_inactive {
	struct trace_entry ent;
	int nid;
	long unsigned int nr_scanned;
	long unsigned int nr_reclaimed;
	long unsigned int nr_dirty;
	long unsigned int nr_writeback;
	long unsigned int nr_congested;
	long unsigned int nr_immediate;
	unsigned int nr_activate0;
	unsigned int nr_activate1;
	long unsigned int nr_ref_keep;
	long unsigned int nr_unmap_fail;
	int priority;
	int reclaim_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_lru_shrink_active {
	struct trace_entry ent;
	int nid;
	long unsigned int nr_taken;
	long unsigned int nr_active;
	long unsigned int nr_deactivated;
	long unsigned int nr_referenced;
	int priority;
	int reclaim_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_node_reclaim_begin {
	struct trace_entry ent;
	int nid;
	int order;
	long unsigned int gfp_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_throttled {
	struct trace_entry ent;
	int nid;
	int usec_timeout;
	int usec_delayed;
	int reason;
	char __data[0];
};

struct trace_event_data_offsets_mm_vmscan_kswapd_sleep {};

struct trace_event_data_offsets_mm_vmscan_kswapd_wake {};

struct trace_event_data_offsets_mm_vmscan_wakeup_kswapd {};

struct trace_event_data_offsets_mm_vmscan_direct_reclaim_begin_template {};

struct trace_event_data_offsets_mm_vmscan_direct_reclaim_end_template {};

struct trace_event_data_offsets_mm_shrink_slab_start {};

struct trace_event_data_offsets_mm_shrink_slab_end {};

struct trace_event_data_offsets_mm_vmscan_lru_isolate {};

struct trace_event_data_offsets_mm_vmscan_write_folio {};

struct trace_event_data_offsets_mm_vmscan_lru_shrink_inactive {};

struct trace_event_data_offsets_mm_vmscan_lru_shrink_active {};

struct trace_event_data_offsets_mm_vmscan_node_reclaim_begin {};

struct trace_event_data_offsets_mm_vmscan_throttled {};

typedef void (*btf_trace_mm_vmscan_kswapd_sleep)(void *, int);

typedef void (*btf_trace_mm_vmscan_kswapd_wake)(void *, int, int, int);

typedef void (*btf_trace_mm_vmscan_wakeup_kswapd)(void *, int, int, int, gfp_t);

typedef void (*btf_trace_mm_vmscan_direct_reclaim_begin)(void *, int, gfp_t);

typedef void (*btf_trace_mm_vmscan_direct_reclaim_end)(void *, long unsigned int);

typedef void (*btf_trace_mm_shrink_slab_start)(void *, struct shrinker *, struct shrink_control *, long int, long unsigned int, long long unsigned int, long unsigned int, int);

typedef void (*btf_trace_mm_shrink_slab_end)(void *, struct shrinker *, int, int, long int, long int, long int);

typedef void (*btf_trace_mm_vmscan_lru_isolate)(void *, int, int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, isolate_mode_t, int);

typedef void (*btf_trace_mm_vmscan_write_folio)(void *, struct folio *);

typedef void (*btf_trace_mm_vmscan_lru_shrink_inactive)(void *, int, long unsigned int, long unsigned int, struct reclaim_stat *, int, int);

typedef void (*btf_trace_mm_vmscan_lru_shrink_active)(void *, int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, int, int);

typedef void (*btf_trace_mm_vmscan_node_reclaim_begin)(void *, int, int, gfp_t);

typedef void (*btf_trace_mm_vmscan_node_reclaim_end)(void *, long unsigned int);

typedef void (*btf_trace_mm_vmscan_throttled)(void *, int, int, int, int);

struct scan_control {
	long unsigned int nr_to_reclaim;
	nodemask_t *nodemask;
	struct mem_cgroup *target_mem_cgroup;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	unsigned int may_deactivate: 2;
	unsigned int force_deactivate: 1;
	unsigned int skipped_deactivate: 1;
	unsigned int may_writepage: 1;
	unsigned int may_unmap: 1;
	unsigned int may_swap: 1;
	unsigned int proactive: 1;
	unsigned int memcg_low_reclaim: 1;
	unsigned int memcg_low_skipped: 1;
	unsigned int hibernation_mode: 1;
	unsigned int compaction_ready: 1;
	unsigned int cache_trim_mode: 1;
	unsigned int file_is_tiny: 1;
	unsigned int no_demotion: 1;
	s8 order;
	s8 priority;
	s8 reclaim_idx;
	gfp_t gfp_mask;
	long unsigned int nr_scanned;
	long unsigned int nr_reclaimed;
	struct {
		unsigned int dirty;
		unsigned int unqueued_dirty;
		unsigned int congested;
		unsigned int writeback;
		unsigned int immediate;
		unsigned int file_taken;
		unsigned int taken;
	} nr;
	struct reclaim_state reclaim_state;
};

typedef enum {
	PAGE_KEEP = 0,
	PAGE_ACTIVATE = 1,
	PAGE_SUCCESS = 2,
	PAGE_CLEAN = 3,
} pageout_t;

enum folio_references {
	FOLIOREF_RECLAIM = 0,
	FOLIOREF_RECLAIM_CLEAN = 1,
	FOLIOREF_KEEP = 2,
	FOLIOREF_ACTIVATE = 3,
};

enum scan_balance {
	SCAN_EQUAL = 0,
	SCAN_FRACT = 1,
	SCAN_ANON = 2,
	SCAN_FILE = 3,
};

struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

enum rw_hint {
	WRITE_LIFE_NOT_SET = 0,
	WRITE_LIFE_NONE = 1,
	WRITE_LIFE_SHORT = 2,
	WRITE_LIFE_MEDIUM = 3,
	WRITE_LIFE_LONG = 4,
	WRITE_LIFE_EXTREME = 5,
};

enum inode_i_mutex_lock_class {
	I_MUTEX_NORMAL = 0,
	I_MUTEX_PARENT = 1,
	I_MUTEX_CHILD = 2,
	I_MUTEX_XATTR = 3,
	I_MUTEX_NONDIR2 = 4,
	I_MUTEX_PARENT2 = 5,
};

struct posix_acl_entry {
	short int e_tag;
	short unsigned int e_perm;
	union {
		kuid_t e_uid;
		kgid_t e_gid;
	};
};

struct posix_acl {
	refcount_t a_refcount;
	struct callback_head a_rcu;
	unsigned int a_count;
	struct posix_acl_entry a_entries[0];
};

enum file_time_flags {
	S_ATIME = 1,
	S_MTIME = 2,
	S_CTIME = 4,
	S_VERSION = 8,
};

typedef union {
} release_pages_arg;

struct partial_page {
	unsigned int offset;
	unsigned int len;
	long unsigned int private;
};

struct splice_pipe_desc {
	struct page **pages;
	struct partial_page *partial;
	int nr_pages;
	unsigned int nr_pages_max;
	const struct pipe_buf_operations *ops;
	void (*spd_release)(struct splice_pipe_desc *, unsigned int);
};

typedef int splice_direct_actor(struct pipe_inode_info *, struct splice_desc *);

struct scatterlist {
	long unsigned int page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
	unsigned int dma_length;
};

struct sg_table {
	struct scatterlist *sgl;
	unsigned int nents;
	unsigned int orig_nents;
};

struct sg_append_table {
	struct sg_table sgt;
	struct scatterlist *prv;
	unsigned int total_nents;
};

typedef struct scatterlist *sg_alloc_fn(unsigned int, gfp_t);

typedef void sg_free_fn(struct scatterlist *, unsigned int);

struct sg_page_iter {
	struct scatterlist *sg;
	unsigned int sg_pgoffset;
	unsigned int __nents;
	int __pg_advance;
};

struct sg_dma_page_iter {
	struct sg_page_iter base;
};

struct sg_mapping_iter {
	struct page *page;
	void *addr;
	size_t length;
	size_t consumed;
	struct sg_page_iter piter;
	unsigned int __offset;
	unsigned int __remaining;
	unsigned int __flags;
};

struct property_entry;

struct platform_device_info {
	struct device *parent;
	struct fwnode_handle *fwnode;
	bool of_node_reused;
	const char *name;
	int id;
	const struct resource *res;
	unsigned int num_res;
	const void *data;
	size_t size_data;
	u64 dma_mask;
	const struct property_entry *properties;
};

enum dev_prop_type {
	DEV_PROP_U8 = 0,
	DEV_PROP_U16 = 1,
	DEV_PROP_U32 = 2,
	DEV_PROP_U64 = 3,
	DEV_PROP_STRING = 4,
	DEV_PROP_REF = 5,
};

struct property_entry {
	const char *name;
	size_t length;
	bool is_inline;
	enum dev_prop_type type;
	union {
		const void *pointer;
		union {
			u8 u8_data[8];
			u16 u16_data[4];
			u32 u32_data[2];
			u64 u64_data[1];
			const char *str[1];
		} value;
	};
};

struct software_node {
	const char *name;
	const struct software_node *parent;
	const struct property_entry *properties;
};

struct irq_affinity {
	unsigned int pre_vectors;
	unsigned int post_vectors;
	unsigned int nr_sets;
	unsigned int set_size[4];
	void (*calc_sets)(struct irq_affinity *, unsigned int);
	void *priv;
};

typedef void *acpi_handle;

struct irq_affinity_devres {
	unsigned int count;
	unsigned int irq[0];
};

struct platform_object {
	struct platform_device pdev;
	char name[0];
};

enum cache_type {
	CACHE_TYPE_NOCACHE = 0,
	CACHE_TYPE_INST = 1,
	CACHE_TYPE_DATA = 2,
	CACHE_TYPE_SEPARATE = 3,
	CACHE_TYPE_UNIFIED = 4,
};

struct cacheinfo {
	unsigned int id;
	enum cache_type type;
	unsigned int level;
	unsigned int coherency_line_size;
	unsigned int number_of_sets;
	unsigned int ways_of_associativity;
	unsigned int physical_line_partition;
	unsigned int size;
	cpumask_t shared_cpu_map;
	unsigned int attributes;
	void *fw_token;
	bool disable_sysfs;
	void *priv;
};

struct cpu_cacheinfo {
	struct cacheinfo *info_list;
	unsigned int num_levels;
	unsigned int num_leaves;
	bool cpu_map_populated;
	bool early_ci_levels;
};

struct cache_type_info {
	const char *size_prop;
	const char *line_size_props[2];
	const char *nr_sets_prop;
};

struct efi_system_resource_entry_v1 {
	efi_guid_t fw_class;
	u32 fw_type;
	u32 fw_version;
	u32 lowest_supported_fw_version;
	u32 capsule_flags;
	u32 last_attempt_version;
	u32 last_attempt_status;
};

struct efi_system_resource_table {
	u32 fw_resource_count;
	u32 fw_resource_count_max;
	u64 fw_resource_version;
	u8 entries[0];
};

struct esre_entry {
	union {
		struct efi_system_resource_entry_v1 *esre1;
	} esre;
	struct kobject kobj;
	struct list_head list;
};

struct esre_attribute {
	struct attribute attr;
	ssize_t (*show)(struct esre_entry *, char *);
	ssize_t (*store)(struct esre_entry *, const char *, size_t);
};

struct of_endpoint {
	unsigned int port;
	unsigned int id;
	const struct device_node *local_node;
};

struct supplier_bindings {
	struct device_node * (*parse_prop)(struct device_node *, const char *, int);
	bool optional;
	bool node_not_dev;
};

typedef int (*decompress_fn)(unsigned char *, long int, long int (*)(void *, long unsigned int), long int (*)(void *, long unsigned int), unsigned char *, long int *, void (*)(char *));

struct compress_format {
	unsigned char magic[2];
	const char *name;
	decompress_fn decompressor;
};

struct psci_operations {
	u32 (*get_version)();
	int (*cpu_suspend)(u32, long unsigned int);
	int (*cpu_off)(u32);
	int (*cpu_on)(long unsigned int, long unsigned int);
	int (*migrate)(long unsigned int);
	int (*affinity_info)(long unsigned int, long unsigned int);
	int (*migrate_info_type)();
};

struct cpu_operations {
	const char *name;
	int (*cpu_init)(unsigned int);
	int (*cpu_prepare)(unsigned int);
	int (*cpu_boot)(unsigned int);
	void (*cpu_postboot)();
	bool (*cpu_can_disable)(unsigned int);
	int (*cpu_disable)(unsigned int);
	void (*cpu_die)(unsigned int);
	int (*cpu_kill)(unsigned int);
};

struct alt_instr {
	s32 orig_offset;
	s32 alt_offset;
	u16 cpucap;
	u8 orig_len;
	u8 alt_len;
};

typedef void (*alternative_cb_t)(struct alt_instr *, __le32 *, __le32 *, int);

struct alt_region {
	struct alt_instr *begin;
	struct alt_instr *end;
};

enum scale_freq_source {
	SCALE_FREQ_SOURCE_CPUFREQ = 0,
	SCALE_FREQ_SOURCE_ARCH = 1,
	SCALE_FREQ_SOURCE_CPPC = 2,
};

struct scale_freq_data {
	enum scale_freq_source source;
	void (*set_freq_scale)();
};

enum aarch64_insn_register_type {
	AARCH64_INSN_REGTYPE_RT = 0,
	AARCH64_INSN_REGTYPE_RN = 1,
	AARCH64_INSN_REGTYPE_RT2 = 2,
	AARCH64_INSN_REGTYPE_RM = 3,
	AARCH64_INSN_REGTYPE_RD = 4,
	AARCH64_INSN_REGTYPE_RA = 5,
	AARCH64_INSN_REGTYPE_RS = 6,
};

typedef u32 probe_opcode_t;

typedef void probes_handler_t(u32, long int, struct pt_regs *);

struct arch_probe_insn {
	probe_opcode_t *insn;
	pstate_check_t *pstate_cc;
	probes_handler_t *handler;
	long unsigned int restore;
};

typedef u32 kprobe_opcode_t;

struct arch_specific_insn {
	struct arch_probe_insn api;
};

struct freelist_node {
	atomic_t refs;
	struct freelist_node *next;
};

struct freelist_head {
	struct freelist_node *head;
};

struct kprobe;

struct prev_kprobe {
	struct kprobe *kp;
	unsigned int status;
};

typedef int (*kprobe_pre_handler_t)(struct kprobe *, struct pt_regs *);

typedef void (*kprobe_post_handler_t)(struct kprobe *, struct pt_regs *, long unsigned int);

struct kprobe {
	struct hlist_node hlist;
	struct list_head list;
	long unsigned int nmissed;
	kprobe_opcode_t *addr;
	const char *symbol_name;
	unsigned int offset;
	kprobe_pre_handler_t pre_handler;
	kprobe_post_handler_t post_handler;
	kprobe_opcode_t opcode;
	struct arch_specific_insn ainsn;
	u32 flags;
};

struct kprobe_ctlblk {
	unsigned int kprobe_status;
	long unsigned int saved_irqflag;
	struct prev_kprobe prev_kprobe;
};

struct kretprobe_instance;

typedef int (*kretprobe_handler_t)(struct kretprobe_instance *, struct pt_regs *);

struct kretprobe_holder;

struct kretprobe_instance {
	union {
		struct freelist_node freelist;
		struct callback_head rcu;
	};
	struct llist_node llist;
	struct kretprobe_holder *rph;
	kprobe_opcode_t *ret_addr;
	void *fp;
	char data[0];
};

struct kretprobe;

struct kretprobe_holder {
	struct kretprobe *rp;
	refcount_t ref;
};

struct kretprobe {
	struct kprobe kp;
	kretprobe_handler_t handler;
	kretprobe_handler_t entry_handler;
	int maxactive;
	int nmissed;
	size_t data_size;
	struct freelist_head freelist;
	struct kretprobe_holder *rph;
};

struct kprobe_insn_cache {
	struct mutex mutex;
	void * (*alloc)();
	void (*free)(void *);
	const char *sym;
	struct list_head pages;
	size_t insn_size;
	int nr_garbage;
};

enum probe_insn {
	INSN_REJECTED = 0,
	INSN_GOOD_NO_SLOT = 1,
	INSN_GOOD = 2,
};

enum aarch64_insn_special_register {
	AARCH64_INSN_SPCLREG_SPSR_EL1 = 49664,
	AARCH64_INSN_SPCLREG_ELR_EL1 = 49665,
	AARCH64_INSN_SPCLREG_SP_EL0 = 49672,
	AARCH64_INSN_SPCLREG_SPSEL = 49680,
	AARCH64_INSN_SPCLREG_CURRENTEL = 49682,
	AARCH64_INSN_SPCLREG_DAIF = 55825,
	AARCH64_INSN_SPCLREG_NZCV = 55824,
	AARCH64_INSN_SPCLREG_FPCR = 55840,
	AARCH64_INSN_SPCLREG_DSPSR_EL0 = 55848,
	AARCH64_INSN_SPCLREG_DLR_EL0 = 55849,
	AARCH64_INSN_SPCLREG_SPSR_EL2 = 57856,
	AARCH64_INSN_SPCLREG_ELR_EL2 = 57857,
	AARCH64_INSN_SPCLREG_SP_EL1 = 57864,
	AARCH64_INSN_SPCLREG_SPSR_INQ = 57880,
	AARCH64_INSN_SPCLREG_SPSR_ABT = 57881,
	AARCH64_INSN_SPCLREG_SPSR_UND = 57882,
	AARCH64_INSN_SPCLREG_SPSR_FIQ = 57883,
	AARCH64_INSN_SPCLREG_SPSR_EL3 = 61952,
	AARCH64_INSN_SPCLREG_ELR_EL3 = 61953,
	AARCH64_INSN_SPCLREG_SP_EL2 = 61968,
};

enum vcpu_sysreg {
	__INVALID_SYSREG__ = 0,
	MPIDR_EL1 = 1,
	CLIDR_EL1 = 2,
	CSSELR_EL1 = 3,
	SCTLR_EL1 = 4,
	ACTLR_EL1 = 5,
	CPACR_EL1 = 6,
	ZCR_EL1 = 7,
	TTBR0_EL1 = 8,
	TTBR1_EL1 = 9,
	TCR_EL1 = 10,
	TCR2_EL1 = 11,
	ESR_EL1 = 12,
	AFSR0_EL1 = 13,
	AFSR1_EL1 = 14,
	FAR_EL1 = 15,
	MAIR_EL1 = 16,
	VBAR_EL1 = 17,
	CONTEXTIDR_EL1 = 18,
	TPIDR_EL0 = 19,
	TPIDRRO_EL0 = 20,
	TPIDR_EL1 = 21,
	AMAIR_EL1 = 22,
	CNTKCTL_EL1 = 23,
	PAR_EL1 = 24,
	MDSCR_EL1 = 25,
	MDCCINT_EL1 = 26,
	OSLSR_EL1 = 27,
	DISR_EL1 = 28,
	PMCR_EL0 = 29,
	PMSELR_EL0 = 30,
	PMEVCNTR0_EL0 = 31,
	PMEVCNTR30_EL0 = 61,
	PMCCNTR_EL0 = 62,
	PMEVTYPER0_EL0 = 63,
	PMEVTYPER30_EL0 = 93,
	PMCCFILTR_EL0 = 94,
	PMCNTENSET_EL0 = 95,
	PMINTENSET_EL1 = 96,
	PMOVSSET_EL0 = 97,
	PMUSERENR_EL0 = 98,
	APIAKEYLO_EL1 = 99,
	APIAKEYHI_EL1 = 100,
	APIBKEYLO_EL1 = 101,
	APIBKEYHI_EL1 = 102,
	APDAKEYLO_EL1 = 103,
	APDAKEYHI_EL1 = 104,
	APDBKEYLO_EL1 = 105,
	APDBKEYHI_EL1 = 106,
	APGAKEYLO_EL1 = 107,
	APGAKEYHI_EL1 = 108,
	ELR_EL1 = 109,
	SP_EL1 = 110,
	SPSR_EL1 = 111,
	CNTVOFF_EL2 = 112,
	CNTV_CVAL_EL0 = 113,
	CNTV_CTL_EL0 = 114,
	CNTP_CVAL_EL0 = 115,
	CNTP_CTL_EL0 = 116,
	RGSR_EL1 = 117,
	GCR_EL1 = 118,
	TFSR_EL1 = 119,
	TFSRE0_EL1 = 120,
	PIR_EL1 = 121,
	PIRE0_EL1 = 122,
	DACR32_EL2 = 123,
	IFSR32_EL2 = 124,
	FPEXC32_EL2 = 125,
	DBGVCR32_EL2 = 126,
	VPIDR_EL2 = 127,
	VMPIDR_EL2 = 128,
	SCTLR_EL2 = 129,
	ACTLR_EL2 = 130,
	HCR_EL2 = 131,
	MDCR_EL2 = 132,
	CPTR_EL2 = 133,
	HSTR_EL2 = 134,
	HACR_EL2 = 135,
	TTBR0_EL2 = 136,
	TTBR1_EL2 = 137,
	TCR_EL2 = 138,
	VTTBR_EL2 = 139,
	VTCR_EL2 = 140,
	SPSR_EL2 = 141,
	ELR_EL2 = 142,
	AFSR0_EL2 = 143,
	AFSR1_EL2 = 144,
	ESR_EL2 = 145,
	FAR_EL2 = 146,
	HPFAR_EL2 = 147,
	MAIR_EL2 = 148,
	AMAIR_EL2 = 149,
	VBAR_EL2 = 150,
	RVBAR_EL2 = 151,
	CONTEXTIDR_EL2 = 152,
	TPIDR_EL2 = 153,
	CNTHCTL_EL2 = 154,
	SP_EL2 = 155,
	CNTHP_CTL_EL2 = 156,
	CNTHP_CVAL_EL2 = 157,
	CNTHV_CTL_EL2 = 158,
	CNTHV_CVAL_EL2 = 159,
	NR_SYS_REGS = 160,
};

struct tasklet_struct {
	struct tasklet_struct *next;
	long unsigned int state;
	atomic_t count;
	bool use_callback;
	union {
		void (*func)(long unsigned int);
		void (*callback)(struct tasklet_struct *);
	};
	long unsigned int data;
};

enum {
	TASKLET_STATE_SCHED = 0,
	TASKLET_STATE_RUN = 1,
};

struct trace_event_raw_irq_handler_entry {
	struct trace_entry ent;
	int irq;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_irq_handler_exit {
	struct trace_entry ent;
	int irq;
	int ret;
	char __data[0];
};

struct trace_event_raw_softirq {
	struct trace_entry ent;
	unsigned int vec;
	char __data[0];
};

struct trace_event_raw_tasklet {
	struct trace_entry ent;
	void *tasklet;
	void *func;
	char __data[0];
};

struct trace_event_data_offsets_irq_handler_entry {
	u32 name;
};

struct trace_event_data_offsets_irq_handler_exit {};

struct trace_event_data_offsets_softirq {};

struct trace_event_data_offsets_tasklet {};

typedef void (*btf_trace_irq_handler_entry)(void *, int, struct irqaction *);

typedef void (*btf_trace_irq_handler_exit)(void *, int, struct irqaction *, int);

typedef void (*btf_trace_softirq_entry)(void *, unsigned int);

typedef void (*btf_trace_softirq_exit)(void *, unsigned int);

typedef void (*btf_trace_softirq_raise)(void *, unsigned int);

typedef void (*btf_trace_tasklet_entry)(void *, struct tasklet_struct *, void *);

typedef void (*btf_trace_tasklet_exit)(void *, struct tasklet_struct *, void *);

struct tasklet_head {
	struct tasklet_struct *head;
	struct tasklet_struct **tail;
};

enum kmsg_dump_reason {
	KMSG_DUMP_UNDEF = 0,
	KMSG_DUMP_PANIC = 1,
	KMSG_DUMP_OOPS = 2,
	KMSG_DUMP_EMERG = 3,
	KMSG_DUMP_SHUTDOWN = 4,
	KMSG_DUMP_MAX = 5,
};

enum reboot_type {
	BOOT_TRIPLE = 116,
	BOOT_KBD = 107,
	BOOT_BIOS = 98,
	BOOT_ACPI = 97,
	BOOT_EFI = 101,
	BOOT_CF9_FORCE = 112,
	BOOT_CF9_SAFE = 113,
};

struct sys_off_handler {
	struct notifier_block nb;
	int (*sys_off_cb)(struct sys_off_data *);
	void *cb_data;
	enum sys_off_mode mode;
	bool blocking;
	void *list;
};

struct optimistic_spin_node {
	struct optimistic_spin_node *next;
	struct optimistic_spin_node *prev;
	int locked;
	int cpu;
};

typedef unsigned int uint;

struct semaphore {
	raw_spinlock_t lock;
	unsigned int count;
	struct list_head wait_list;
};

struct dev_printk_info {
	char subsystem[16];
	char device[48];
};

enum cons_flags {
	CON_PRINTBUFFER = 1,
	CON_CONSDEV = 2,
	CON_ENABLED = 4,
	CON_BOOT = 8,
	CON_ANYTIME = 16,
	CON_BRL = 32,
	CON_EXTENDED = 64,
};

struct console {
	char name[16];
	void (*write)(struct console *, const char *, unsigned int);
	int (*read)(struct console *, char *, unsigned int);
	struct tty_driver * (*device)(struct console *, int *);
	void (*unblank)();
	int (*setup)(struct console *, char *);
	int (*exit)(struct console *);
	int (*match)(struct console *, char *, int, char *);
	short int flags;
	short int index;
	int cflag;
	uint ispeed;
	uint ospeed;
	u64 seq;
	long unsigned int dropped;
	void *data;
	struct hlist_node node;
};

enum con_flush_mode {
	CONSOLE_FLUSH_PENDING = 0,
	CONSOLE_REPLAY_ALL = 1,
};

struct trace_event_raw_console {
	struct trace_entry ent;
	u32 __data_loc_msg;
	char __data[0];
};

struct trace_event_data_offsets_console {
	u32 msg;
};

typedef void (*btf_trace_console)(void *, const char *, size_t);

struct printk_info {
	u64 seq;
	u64 ts_nsec;
	u16 text_len;
	u8 facility;
	u8 flags: 5;
	u8 level: 3;
	u32 caller_id;
	struct dev_printk_info dev_info;
};

struct printk_record {
	struct printk_info *info;
	char *text_buf;
	unsigned int text_buf_size;
};

struct console_cmdline {
	char name[16];
	int index;
	bool user_specified;
	char *options;
};

struct printk_buffers {
	char outbuf[0];
	char scratchbuf[0];
};

struct printk_message {
	struct printk_buffers *pbufs;
	unsigned int outbuf_len;
	u64 seq;
	long unsigned int dropped;
};

enum devkmsg_log_bits {
	__DEVKMSG_LOG_BIT_ON = 0,
	__DEVKMSG_LOG_BIT_OFF = 1,
	__DEVKMSG_LOG_BIT_LOCK = 2,
};

enum devkmsg_log_masks {
	DEVKMSG_LOG_MASK_ON = 1,
	DEVKMSG_LOG_MASK_OFF = 2,
	DEVKMSG_LOG_MASK_LOCK = 4,
};

enum con_msg_format_flags {
	MSG_FORMAT_DEFAULT = 0,
	MSG_FORMAT_SYSLOG = 1,
};

struct xa_limit {
	u32 max;
	u32 min;
};

struct pci_device_id {
	__u32 vendor;
	__u32 device;
	__u32 subvendor;
	__u32 subdevice;
	__u32 class;
	__u32 class_mask;
	kernel_ulong_t driver_data;
	__u32 override_only;
};

struct msi_map {
	int index;
	int virq;
};

enum msi_desc_filter {
	MSI_DESC_ALL = 0,
	MSI_DESC_NOTASSOCIATED = 1,
	MSI_DESC_ASSOCIATED = 2,
};

struct msi_domain_template {
	char name[48];
	struct irq_chip chip;
	struct msi_domain_ops ops;
	struct msi_domain_info info;
};

struct hotplug_slot;

struct pci_bus;

struct pci_slot {
	struct pci_bus *bus;
	struct list_head list;
	struct hotplug_slot *hotplug;
	unsigned char number;
	struct kobject kobj;
};

struct pci_dev;

struct pci_ops;

struct pci_bus {
	struct list_head node;
	struct pci_bus *parent;
	struct list_head children;
	struct list_head devices;
	struct pci_dev *self;
	struct list_head slots;
	struct resource *resource[4];
	struct list_head resources;
	struct resource busn_res;
	struct pci_ops *ops;
	void *sysdata;
	struct proc_dir_entry *procdir;
	unsigned char number;
	unsigned char primary;
	unsigned char max_bus_speed;
	unsigned char cur_bus_speed;
	char name[48];
	short unsigned int bridge_ctl;
	pci_bus_flags_t bus_flags;
	struct device *bridge;
	struct device dev;
	struct bin_attribute *legacy_io;
	struct bin_attribute *legacy_mem;
	unsigned int is_added: 1;
	unsigned int unsafe_warn: 1;
};

typedef int pci_power_t;

struct pci_vpd {
	struct mutex lock;
	unsigned int len;
	u8 cap;
};

struct pci_driver;

struct pci_dev {
	struct list_head bus_list;
	struct pci_bus *bus;
	struct pci_bus *subordinate;
	void *sysdata;
	struct proc_dir_entry *procent;
	struct pci_slot *slot;
	unsigned int devfn;
	short unsigned int vendor;
	short unsigned int device;
	short unsigned int subsystem_vendor;
	short unsigned int subsystem_device;
	unsigned int class;
	u8 revision;
	u8 hdr_type;
	u32 devcap;
	u8 pcie_cap;
	u8 msi_cap;
	u8 msix_cap;
	u8 pcie_mpss: 3;
	u8 rom_base_reg;
	u8 pin;
	u16 pcie_flags_reg;
	long unsigned int *dma_alias_mask;
	struct pci_driver *driver;
	u64 dma_mask;
	struct device_dma_parameters dma_parms;
	pci_power_t current_state;
	unsigned int imm_ready: 1;
	u8 pm_cap;
	unsigned int pme_support: 5;
	unsigned int pme_poll: 1;
	unsigned int d1_support: 1;
	unsigned int d2_support: 1;
	unsigned int no_d1d2: 1;
	unsigned int no_d3cold: 1;
	unsigned int bridge_d3: 1;
	unsigned int d3cold_allowed: 1;
	unsigned int mmio_always_on: 1;
	unsigned int wakeup_prepared: 1;
	unsigned int skip_bus_pm: 1;
	unsigned int ignore_hotplug: 1;
	unsigned int hotplug_user_indicators: 1;
	unsigned int clear_retrain_link: 1;
	unsigned int d3hot_delay;
	unsigned int d3cold_delay;
	unsigned int pasid_no_tlp: 1;
	unsigned int eetlp_prefix_path: 1;
	pci_channel_state_t error_state;
	struct device dev;
	int cfg_size;
	unsigned int irq;
	struct resource resource[11];
	struct resource driver_exclusive_resource;
	bool match_driver;
	unsigned int transparent: 1;
	unsigned int io_window: 1;
	unsigned int pref_window: 1;
	unsigned int pref_64_window: 1;
	unsigned int multifunction: 1;
	unsigned int is_busmaster: 1;
	unsigned int no_msi: 1;
	unsigned int no_64bit_msi: 1;
	unsigned int block_cfg_access: 1;
	unsigned int broken_parity_status: 1;
	unsigned int irq_reroute_variant: 2;
	unsigned int msi_enabled: 1;
	unsigned int msix_enabled: 1;
	unsigned int ari_enabled: 1;
	unsigned int ats_enabled: 1;
	unsigned int pasid_enabled: 1;
	unsigned int pri_enabled: 1;
	unsigned int is_managed: 1;
	unsigned int is_msi_managed: 1;
	unsigned int needs_freset: 1;
	unsigned int state_saved: 1;
	unsigned int is_physfn: 1;
	unsigned int is_virtfn: 1;
	unsigned int is_hotplug_bridge: 1;
	unsigned int shpc_managed: 1;
	unsigned int is_thunderbolt: 1;
	unsigned int untrusted: 1;
	unsigned int external_facing: 1;
	unsigned int broken_intx_masking: 1;
	unsigned int io_window_1k: 1;
	unsigned int irq_managed: 1;
	unsigned int non_compliant_bars: 1;
	unsigned int is_probed: 1;
	unsigned int link_active_reporting: 1;
	unsigned int no_vf_scan: 1;
	unsigned int no_command_memory: 1;
	unsigned int rom_bar_overlap: 1;
	pci_dev_flags_t dev_flags;
	atomic_t enable_cnt;
	u32 saved_config_space[16];
	struct hlist_head saved_cap_space;
	int rom_attr_enabled;
	struct bin_attribute *res_attr[11];
	struct bin_attribute *res_attr_wc[11];
	struct pci_vpd vpd;
	u16 acs_cap;
	phys_addr_t rom;
	size_t romlen;
	const char *driver_override;
	long unsigned int priv_flags;
	u8 reset_methods[7];
};

struct pci_dynids {
	spinlock_t lock;
	struct list_head list;
};

struct pci_error_handlers;

struct pci_driver {
	struct list_head node;
	const char *name;
	const struct pci_device_id *id_table;
	int (*probe)(struct pci_dev *, const struct pci_device_id *);
	void (*remove)(struct pci_dev *);
	int (*suspend)(struct pci_dev *, pm_message_t);
	int (*resume)(struct pci_dev *);
	void (*shutdown)(struct pci_dev *);
	int (*sriov_configure)(struct pci_dev *, int);
	int (*sriov_set_msix_vec_count)(struct pci_dev *, int);
	u32 (*sriov_get_vf_total_msix)(struct pci_dev *);
	const struct pci_error_handlers *err_handler;
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	struct device_driver driver;
	struct pci_dynids dynids;
	bool driver_managed_dma;
};

struct pci_ops {
	int (*add_bus)(struct pci_bus *);
	void (*remove_bus)(struct pci_bus *);
	void * (*map_bus)(struct pci_bus *, unsigned int, int);
	int (*read)(struct pci_bus *, unsigned int, int, int, u32 *);
	int (*write)(struct pci_bus *, unsigned int, int, int, u32);
};

struct pci_error_handlers {
	pci_ers_result_t (*error_detected)(struct pci_dev *, pci_channel_state_t);
	pci_ers_result_t (*mmio_enabled)(struct pci_dev *);
	pci_ers_result_t (*slot_reset)(struct pci_dev *);
	void (*reset_prepare)(struct pci_dev *);
	void (*reset_done)(struct pci_dev *);
	void (*resume)(struct pci_dev *);
	void (*cor_error_detected)(struct pci_dev *);
};

struct msi_ctrl {
	unsigned int domid;
	unsigned int first;
	unsigned int last;
	unsigned int nirqs;
};

struct hrtimer_sleeper {
	struct hrtimer timer;
	struct task_struct *task;
};

typedef struct {
	seqcount_t seqcount;
} seqcount_latch_t;

struct syscore_ops {
	struct list_head node;
	int (*suspend)();
	void (*resume)();
	void (*shutdown)();
};

struct clock_read_data {
	u64 epoch_ns;
	u64 epoch_cyc;
	u64 sched_clock_mask;
	u64 (*read_sched_clock)();
	u32 mult;
	u32 shift;
};

struct clock_data {
	seqcount_latch_t seq;
	struct clock_read_data read_data[2];
	ktime_t wrap_kt;
	long unsigned int rate;
	u64 (*actual_read_sched_clock)();
};

struct kprobe_blacklist_entry {
	struct list_head list;
	long unsigned int start_addr;
	long unsigned int end_addr;
};

struct kprobe_insn_page {
	struct list_head list;
	kprobe_opcode_t *insns;
	struct kprobe_insn_cache *cache;
	int nused;
	int ngarbage;
	char slot_used[0];
};

enum kprobe_slot_state {
	SLOT_CLEAN = 0,
	SLOT_DIRTY = 1,
	SLOT_USED = 2,
};

enum {
	TRACE_ARRAY_FL_GLOBAL = 1,
};

struct ftrace_func_command {
	struct list_head list;
	char *name;
	int (*func)(struct trace_array *, struct ftrace_hash *, char *, char *, char *, int);
};

struct ftrace_probe_ops {
	void (*func)(long unsigned int, long unsigned int, struct trace_array *, struct ftrace_probe_ops *, void *);
	int (*init)(struct ftrace_probe_ops *, struct trace_array *, long unsigned int, void *, void **);
	void (*free)(struct ftrace_probe_ops *, struct trace_array *, long unsigned int, void *);
	int (*print)(struct seq_file *, long unsigned int, struct ftrace_probe_ops *, void *);
};

typedef int (*ftrace_mapper_func)(void *);

enum {
	TRACE_FUNC_NO_OPTS = 0,
	TRACE_FUNC_OPT_STACK = 1,
	TRACE_FUNC_OPT_NO_REPEATS = 2,
	TRACE_FUNC_OPT_HIGHEST_BIT = 4,
};

struct eprobe_trace_entry_head {
	struct trace_entry ent;
};

struct ftrace_event_field {
	struct list_head link;
	const char *name;
	const char *type;
	int filter_type;
	int offset;
	int size;
	int is_signed;
	int len;
};

struct trace_eprobe {
	const char *event_system;
	const char *event_name;
	char *filter_str;
	struct trace_event_call *event;
	struct dyn_event devent;
	struct trace_probe tp;
};

struct eprobe_data {
	struct trace_event_file *file;
	struct trace_eprobe *ep;
};

struct btf_array {
	__u32 type;
	__u32 index_type;
	__u32 nelems;
};

struct btf_member {
	__u32 name_off;
	__u32 type;
	__u32 offset;
};

struct btf_param {
	__u32 name_off;
	__u32 type;
};

enum btf_func_linkage {
	BTF_FUNC_STATIC = 0,
	BTF_FUNC_GLOBAL = 1,
	BTF_FUNC_EXTERN = 2,
};

struct btf_var_secinfo {
	__u32 type;
	__u32 offset;
	__u32 size;
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS = 1,
};

enum bpf_core_relo_kind {
	BPF_CORE_FIELD_BYTE_OFFSET = 0,
	BPF_CORE_FIELD_BYTE_SIZE = 1,
	BPF_CORE_FIELD_EXISTS = 2,
	BPF_CORE_FIELD_SIGNED = 3,
	BPF_CORE_FIELD_LSHIFT_U64 = 4,
	BPF_CORE_FIELD_RSHIFT_U64 = 5,
	BPF_CORE_TYPE_ID_LOCAL = 6,
	BPF_CORE_TYPE_ID_TARGET = 7,
	BPF_CORE_TYPE_EXISTS = 8,
	BPF_CORE_TYPE_SIZE = 9,
	BPF_CORE_ENUMVAL_EXISTS = 10,
	BPF_CORE_ENUMVAL_VALUE = 11,
	BPF_CORE_TYPE_MATCHES = 12,
};

struct bpf_core_relo {
	__u32 insn_off;
	__u32 type_id;
	__u32 access_str_off;
	enum bpf_core_relo_kind kind;
};

struct btf_id_set {
	u32 cnt;
	u32 ids[0];
};

enum bpf_jit_poke_reason {
	BPF_POKE_REASON_TAIL_CALL = 0,
};

struct bpf_kfunc_desc {
	struct btf_func_model func_model;
	u32 func_id;
	s32 imm;
	u16 offset;
	long unsigned int addr;
};

struct bpf_kfunc_desc_tab {
	struct bpf_kfunc_desc descs[256];
	u32 nr_descs;
};

struct bpf_kfunc_btf {
	struct btf *btf;
	struct module *module;
	u16 offset;
};

struct bpf_kfunc_btf_tab {
	struct bpf_kfunc_btf descs[256];
	u32 nr_descs;
};

struct bpf_struct_ops {
	const struct bpf_verifier_ops *verifier_ops;
	int (*init)(struct btf *);
	int (*check_member)(const struct btf_type *, const struct btf_member *, const struct bpf_prog *);
	int (*init_member)(const struct btf_type *, const struct btf_member *, void *, const void *);
	int (*reg)(void *);
	void (*unreg)(void *);
	int (*update)(void *, void *);
	int (*validate)(void *);
	const struct btf_type *type;
	const struct btf_type *value_type;
	const char *name;
	struct btf_func_model func_models[64];
	u32 type_id;
	u32 value_id;
};

typedef u32 (*bpf_convert_ctx_access_t)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);

struct bpf_core_ctx {
	struct bpf_verifier_log *log;
	const struct btf *btf;
};

struct bpf_bprintf_data {
	u32 *bin_args;
	char *buf;
	bool get_bin_args;
	bool get_buf;
};

enum bpf_stack_slot_type {
	STACK_INVALID = 0,
	STACK_SPILL = 1,
	STACK_MISC = 2,
	STACK_ZERO = 3,
	STACK_DYNPTR = 4,
	STACK_ITER = 5,
};

struct bpf_verifier_stack_elem {
	struct bpf_verifier_state st;
	int insn_idx;
	int prev_insn_idx;
	struct bpf_verifier_stack_elem *next;
	u32 log_pos;
};

typedef void (*bpf_insn_print_t)(void *, const char *, ...);

typedef const char * (*bpf_insn_revmap_call_t)(void *, const struct bpf_insn *);

typedef const char * (*bpf_insn_print_imm_t)(void *, const struct bpf_insn *, __u64);

struct bpf_insn_cbs {
	bpf_insn_print_t cb_print;
	bpf_insn_revmap_call_t cb_call;
	bpf_insn_print_imm_t cb_imm;
	void *private_data;
};

struct bpf_call_arg_meta {
	struct bpf_map *map_ptr;
	bool raw_mode;
	bool pkt_access;
	u8 release_regno;
	int regno;
	int access_size;
	int mem_size;
	u64 msize_max_value;
	int ref_obj_id;
	int dynptr_id;
	int map_uid;
	int func_id;
	struct btf *btf;
	u32 btf_id;
	struct btf *ret_btf;
	u32 ret_btf_id;
	u32 subprogno;
	struct btf_field *kptr_field;
};

struct btf_and_id {
	struct btf *btf;
	u32 btf_id;
};

struct bpf_kfunc_call_arg_meta {
	struct btf *btf;
	u32 func_id;
	u32 kfunc_flags;
	const struct btf_type *func_proto;
	const char *func_name;
	u32 ref_obj_id;
	u8 release_regno;
	bool r0_rdonly;
	u32 ret_btf_id;
	u64 r0_size;
	u32 subprogno;
	struct {
		u64 value;
		bool found;
	} arg_constant;
	union {
		struct btf_and_id arg_obj_drop;
		struct btf_and_id arg_refcount_acquire;
	};
	struct {
		struct btf_field *field;
	} arg_list_head;
	struct {
		struct btf_field *field;
	} arg_rbtree_root;
	struct {
		enum bpf_dynptr_type type;
		u32 id;
	} initialized_dynptr;
	struct {
		u8 spi;
		u8 frameno;
	} iter;
	u64 mem_size;
};

enum reg_arg_type {
	SRC_OP = 0,
	DST_OP = 1,
	DST_OP_NO_MARK = 2,
};

enum bpf_access_src {
	ACCESS_DIRECT = 1,
	ACCESS_HELPER = 2,
};

struct task_struct__safe_rcu {
	const cpumask_t *cpus_ptr;
	struct css_set *cgroups;
	struct task_struct *real_parent;
	struct task_struct *group_leader;
};

struct cgroup__safe_rcu {
	struct kernfs_node *kn;
};

struct css_set__safe_rcu {
	struct cgroup *dfl_cgrp;
};

struct mm_struct__safe_rcu_or_null {
	struct file *exe_file;
};

struct sk_buff__safe_rcu_or_null {
	struct sock *sk;
};

struct request_sock__safe_rcu_or_null {
	struct sock *sk;
};

struct bpf_iter_meta__safe_trusted {
	struct seq_file *seq;
};

struct bpf_iter__task__safe_trusted {
	struct bpf_iter_meta *meta;
	struct task_struct *task;
};

struct linux_binprm__safe_trusted {
	struct file *file;
};

struct file__safe_trusted {
	struct inode *f_inode;
};

struct dentry__safe_trusted {
	struct inode *d_inode;
};

struct socket__safe_trusted {
	struct sock *sk;
};

struct bpf_reg_types {
	const enum bpf_reg_type types[10];
	u32 *btf_id;
};

enum {
	AT_PKT_END = -1,
	BEYOND_PKT_END = -2,
};

typedef int (*set_callee_state_fn)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *, int);

enum {
	KF_ARG_DYNPTR_ID = 0,
	KF_ARG_LIST_HEAD_ID = 1,
	KF_ARG_LIST_NODE_ID = 2,
	KF_ARG_RB_ROOT_ID = 3,
	KF_ARG_RB_NODE_ID = 4,
};

enum kfunc_ptr_arg_type {
	KF_ARG_PTR_TO_CTX = 0,
	KF_ARG_PTR_TO_ALLOC_BTF_ID = 1,
	KF_ARG_PTR_TO_REFCOUNTED_KPTR = 2,
	KF_ARG_PTR_TO_DYNPTR = 3,
	KF_ARG_PTR_TO_ITER = 4,
	KF_ARG_PTR_TO_LIST_HEAD = 5,
	KF_ARG_PTR_TO_LIST_NODE = 6,
	KF_ARG_PTR_TO_BTF_ID = 7,
	KF_ARG_PTR_TO_MEM = 8,
	KF_ARG_PTR_TO_MEM_SIZE = 9,
	KF_ARG_PTR_TO_CALLBACK = 10,
	KF_ARG_PTR_TO_RB_ROOT = 11,
	KF_ARG_PTR_TO_RB_NODE = 12,
};

enum special_kfunc_type {
	KF_bpf_obj_new_impl = 0,
	KF_bpf_obj_drop_impl = 1,
	KF_bpf_refcount_acquire_impl = 2,
	KF_bpf_list_push_front_impl = 3,
	KF_bpf_list_push_back_impl = 4,
	KF_bpf_list_pop_front = 5,
	KF_bpf_list_pop_back = 6,
	KF_bpf_cast_to_kern_ctx = 7,
	KF_bpf_rdonly_cast = 8,
	KF_bpf_rcu_read_lock = 9,
	KF_bpf_rcu_read_unlock = 10,
	KF_bpf_rbtree_remove = 11,
	KF_bpf_rbtree_add_impl = 12,
	KF_bpf_rbtree_first = 13,
	KF_bpf_dynptr_from_skb = 14,
	KF_bpf_dynptr_from_xdp = 15,
	KF_bpf_dynptr_slice = 16,
	KF_bpf_dynptr_slice_rdwr = 17,
};

enum {
	REASON_BOUNDS = -1,
	REASON_TYPE = -2,
	REASON_PATHS = -3,
	REASON_LIMIT = -4,
	REASON_STACK = -5,
};

struct bpf_sanitize_info {
	struct bpf_insn_aux_data aux;
	bool mask_to_left;
};

enum {
	DISCOVERED = 16,
	EXPLORED = 32,
	FALLTHROUGH = 1,
	BRANCH = 2,
};

enum {
	DONE_EXPLORING = 0,
	KEEP_EXPLORING = 1,
};

struct bpf_iter;

struct clk_multiplier {
	struct clk_hw hw;
	void *reg;
	u8 shift;
	u8 width;
	u8 flags;
	spinlock_t *lock;
};

struct clk_composite {
	struct clk_hw hw;
	struct clk_ops ops;
	struct clk_hw *mux_hw;
	struct clk_hw *rate_hw;
	struct clk_hw *gate_hw;
	const struct clk_ops *mux_ops;
	const struct clk_ops *rate_ops;
	const struct clk_ops *gate_ops;
};

struct component_ops {
	int (*bind)(struct device *, struct device *, void *);
	void (*unbind)(struct device *, struct device *, void *);
};

struct component_master_ops {
	int (*bind)(struct device *);
	void (*unbind)(struct device *);
};

struct component;

struct component_match_array {
	void *data;
	int (*compare)(struct device *, void *);
	int (*compare_typed)(struct device *, int, void *);
	void (*release)(struct device *, void *);
	struct component *component;
	bool duplicate;
};

struct aggregate_device;

struct component {
	struct list_head node;
	struct aggregate_device *adev;
	bool bound;
	const struct component_ops *ops;
	int subcomponent;
	struct device *dev;
};

struct component_match {
	size_t alloc;
	size_t num;
	struct component_match_array *compare;
};

struct aggregate_device {
	struct list_head node;
	bool bound;
	const struct component_master_ops *ops;
	struct device *parent;
	struct component_match *match;
};

typedef struct kobject *kobj_probe_t(dev_t, int *, void *);

struct probe {
	struct probe *next;
	dev_t dev;
	long unsigned int range;
	struct module *owner;
	kobj_probe_t *get;
	int (*lock)(dev_t, void *);
	void *data;
};

struct kobj_map {
	struct probe *probes[255];
	struct mutex *lock;
};

struct soc_device_attribute {
	const char *machine;
	const char *family;
	const char *revision;
	const char *serial_number;
	const char *soc_id;
	const void *data;
	const struct attribute_group *custom_attr_group;
};

struct soc_device {
	struct device dev;
	struct soc_device_attribute *attr;
	int soc_dev_num;
};

struct linux_efi_tpm_eventlog {
	u32 size;
	u32 final_events_preboot_size;
	u8 version;
	u8 log[0];
};

struct efi_tcg2_final_events_table {
	u64 version;
	u64 nr_events;
	u8 events[0];
};

struct tpm_digest {
	u16 alg_id;
	u8 digest[64];
};

enum tpm_duration {
	TPM_SHORT = 0,
	TPM_MEDIUM = 1,
	TPM_LONG = 2,
	TPM_LONG_LONG = 3,
	TPM_UNDEFINED = 4,
	TPM_NUM_DURATIONS = 4,
};

enum tcpa_event_types {
	PREBOOT = 0,
	POST_CODE = 1,
	UNUSED = 2,
	NO_ACTION = 3,
	SEPARATOR = 4,
	ACTION = 5,
	EVENT_TAG = 6,
	SCRTM_CONTENTS = 7,
	SCRTM_VERSION = 8,
	CPU_MICROCODE = 9,
	PLATFORM_CONFIG_FLAGS = 10,
	TABLE_OF_DEVICES = 11,
	COMPACT_HASH = 12,
	IPL = 13,
	IPL_PARTITION_DATA = 14,
	NONHOST_CODE = 15,
	NONHOST_CONFIG = 16,
	NONHOST_INFO = 17,
};

struct tcg_efi_specid_event_algs {
	u16 alg_id;
	u16 digest_size;
};

struct tcg_efi_specid_event_head {
	u8 signature[16];
	u32 platform_class;
	u8 spec_version_minor;
	u8 spec_version_major;
	u8 spec_errata;
	u8 uintnsize;
	u32 num_algs;
	struct tcg_efi_specid_event_algs digest_sizes[0];
};

struct tcg_pcr_event {
	u32 pcr_idx;
	u32 event_type;
	u8 digest[20];
	u32 event_size;
	u8 event[0];
};

struct tcg_event_field {
	u32 event_size;
	u8 event[0];
};

struct tcg_pcr_event2_head {
	u32 pcr_idx;
	u32 event_type;
	u32 count;
	struct tpm_digest digests[0];
};

enum efi_rts_ids {
	EFI_NONE = 0,
	EFI_GET_TIME = 1,
	EFI_SET_TIME = 2,
	EFI_GET_WAKEUP_TIME = 3,
	EFI_SET_WAKEUP_TIME = 4,
	EFI_GET_VARIABLE = 5,
	EFI_GET_NEXT_VARIABLE = 6,
	EFI_SET_VARIABLE = 7,
	EFI_QUERY_VARIABLE_INFO = 8,
	EFI_GET_NEXT_HIGH_MONO_COUNT = 9,
	EFI_RESET_SYSTEM = 10,
	EFI_UPDATE_CAPSULE = 11,
	EFI_QUERY_CAPSULE_CAPS = 12,
};

struct efi_runtime_work {
	void *arg1;
	void *arg2;
	void *arg3;
	void *arg4;
	void *arg5;
	efi_status_t status;
	struct work_struct work;
	enum efi_rts_ids efi_rts_id;
	struct completion efi_rts_comp;
};

struct of_timer_irq {
	int irq;
	int index;
	int percpu;
	const char *name;
	long unsigned int flags;
	irq_handler_t handler;
};

struct of_timer_base {
	void *base;
	const char *name;
	int index;
};

struct of_timer_clk {
	struct clk *clk;
	const char *name;
	int index;
	long unsigned int rate;
	long unsigned int period;
};

struct timer_of {
	unsigned int flags;
	struct device_node *np;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct clock_event_device clkevt;
	struct of_timer_base of_base;
	struct of_timer_irq of_irq;
	struct of_timer_clk of_clk;
	void *private_data;
	long: 64;
	long: 64;
};

struct of_bus {
	void (*count_cells)(const void *, int, int *, int *);
	u64 (*map)(__be32 *, const __be32 *, int, int, int);
	int (*translate)(__be32 *, u64, int);
};

struct of_intc_desc {
	struct list_head list;
	of_irq_init_cb_t irq_init_cb;
	struct device_node *dev;
	struct device_node *interrupt_parent;
};

struct fprop_local_single {
	long unsigned int events;
	unsigned int period;
	raw_spinlock_t lock;
};

struct maple_metadata {
	unsigned char end;
	unsigned char gap;
};

struct maple_pnode;

struct maple_range_64 {
	struct maple_pnode *parent;
	long unsigned int pivot[15];
	union {
		void *slot[16];
		struct {
			void *pad[15];
			struct maple_metadata meta;
		};
	};
};

struct maple_arange_64 {
	struct maple_pnode *parent;
	long unsigned int pivot[9];
	void *slot[10];
	long unsigned int gap[10];
	struct maple_metadata meta;
};

struct maple_topiary {
	struct maple_pnode *parent;
	struct maple_enode *next;
};

enum maple_type {
	maple_dense = 0,
	maple_leaf_64 = 1,
	maple_range_64 = 2,
	maple_arange_64 = 3,
};

struct maple_node {
	union {
		struct {
			struct maple_pnode *parent;
			void *slot[31];
		};
		struct {
			void *pad;
			struct callback_head rcu;
			struct maple_enode *piv_parent;
			unsigned char parent_slot;
			enum maple_type type;
			unsigned char slot_len;
			unsigned int ma_flags;
		};
		struct maple_range_64 mr64;
		struct maple_arange_64 ma64;
		struct maple_alloc alloc;
	};
};

struct ma_topiary {
	struct maple_enode *head;
	struct maple_enode *tail;
	struct maple_tree *mtree;
};

struct ma_wr_state {
	struct ma_state *mas;
	struct maple_node *node;
	long unsigned int r_min;
	long unsigned int r_max;
	enum maple_type type;
	unsigned char offset_end;
	unsigned char node_end;
	long unsigned int *pivots;
	long unsigned int end_piv;
	void **slots;
	void *entry;
	void *content;
};

struct trace_event_raw_ma_op {
	struct trace_entry ent;
	const char *fn;
	long unsigned int min;
	long unsigned int max;
	long unsigned int index;
	long unsigned int last;
	void *node;
	char __data[0];
};

struct trace_event_raw_ma_read {
	struct trace_entry ent;
	const char *fn;
	long unsigned int min;
	long unsigned int max;
	long unsigned int index;
	long unsigned int last;
	void *node;
	char __data[0];
};

struct trace_event_raw_ma_write {
	struct trace_entry ent;
	const char *fn;
	long unsigned int min;
	long unsigned int max;
	long unsigned int index;
	long unsigned int last;
	long unsigned int piv;
	void *val;
	void *node;
	char __data[0];
};

struct trace_event_data_offsets_ma_op {};

struct trace_event_data_offsets_ma_read {};

struct trace_event_data_offsets_ma_write {};

typedef void (*btf_trace_ma_op)(void *, const char *, struct ma_state *);

typedef void (*btf_trace_ma_read)(void *, const char *, struct ma_state *);

typedef void (*btf_trace_ma_write)(void *, const char *, struct ma_state *, long unsigned int, void *);

struct maple_big_node {
	struct maple_pnode *parent;
	long unsigned int pivot[33];
	union {
		struct maple_enode *slot[34];
		struct {
			long unsigned int padding[21];
			long unsigned int gap[21];
		};
	};
	unsigned char b_end;
	enum maple_type type;
};

struct maple_subtree_state {
	struct ma_state *orig_l;
	struct ma_state *orig_r;
	struct ma_state *l;
	struct ma_state *m;
	struct ma_state *r;
	struct ma_topiary *free;
	struct ma_topiary *destroy;
	struct maple_big_node *bn;
};

struct arm64_midr_revidr {
	u32 midr_rv;
	u32 revidr_mask;
};

struct arm64_cpu_capabilities {
	const char *desc;
	u16 capability;
	u16 type;
	bool (*matches)(const struct arm64_cpu_capabilities *, int);
	void (*cpu_enable)(const struct arm64_cpu_capabilities *);
	union {
		struct {
			struct midr_range midr_range;
			const struct arm64_midr_revidr * const fixed_revs;
		};
		const struct midr_range *midr_range_list;
		struct {
			u32 sys_reg;
			u8 field_pos;
			u8 field_width;
			u8 min_field_value;
			u8 hwcap_type;
			bool sign;
			long unsigned int hwcap;
		};
	};
	const struct arm64_cpu_capabilities *match_list;
};

enum mitigation_state {
	SPECTRE_UNAFFECTED = 0,
	SPECTRE_MITIGATED = 1,
	SPECTRE_VULNERABLE = 2,
};

enum arm64_hyp_spectre_vector {
	HYP_VECTOR_DIRECT = 0,
	HYP_VECTOR_SPECTRE_DIRECT = 1,
	HYP_VECTOR_INDIRECT = 2,
	HYP_VECTOR_SPECTRE_INDIRECT = 3,
};

typedef void (*bp_hardening_cb_t)();

struct bp_hardening_data {
	enum arm64_hyp_spectre_vector slot;
	bp_hardening_cb_t fn;
};

enum arm64_bp_harden_el1_vectors {
	EL1_VECTOR_BHB_LOOP = 0,
	EL1_VECTOR_BHB_FW = 1,
	EL1_VECTOR_BHB_CLEAR_INSN = 2,
	EL1_VECTOR_KPTI = 3,
};

enum spectre_v4_policy {
	SPECTRE_V4_POLICY_MITIGATION_DYNAMIC = 0,
	SPECTRE_V4_POLICY_MITIGATION_ENABLED = 1,
	SPECTRE_V4_POLICY_MITIGATION_DISABLED = 2,
};

struct spectre_v4_param {
	const char *str;
	enum spectre_v4_policy policy;
};

enum bhb_mitigation_bits {
	BHB_LOOP = 0,
	BHB_FW = 1,
	BHB_HW = 2,
	BHB_INSN = 3,
};

enum what {
	PROC_EVENT_NONE = 0,
	PROC_EVENT_FORK = 1,
	PROC_EVENT_EXEC = 2,
	PROC_EVENT_UID = 4,
	PROC_EVENT_GID = 64,
	PROC_EVENT_SID = 128,
	PROC_EVENT_PTRACE = 256,
	PROC_EVENT_COMM = 512,
	PROC_EVENT_COREDUMP = 1073741824,
	PROC_EVENT_EXIT = 2147483648,
};

struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
};

enum {
	SD_BALANCE_NEWIDLE = 1,
	SD_BALANCE_EXEC = 2,
	SD_BALANCE_FORK = 4,
	SD_BALANCE_WAKE = 8,
	SD_WAKE_AFFINE = 16,
	SD_ASYM_CPUCAPACITY = 32,
	SD_ASYM_CPUCAPACITY_FULL = 64,
	SD_SHARE_CPUCAPACITY = 128,
	SD_SHARE_PKG_RESOURCES = 256,
	SD_SERIALIZE = 512,
	SD_ASYM_PACKING = 1024,
	SD_PREFER_SIBLING = 2048,
	SD_OVERLAP = 4096,
	SD_NUMA = 8192,
};

struct sd_flag_debug {
	unsigned int meta_flags;
	char *name;
};

typedef const struct cpumask * (*sched_domain_mask_f)(int);

typedef int (*sched_domain_flags_f)();

struct sd_data {
	struct sched_domain **sd;
	struct sched_domain_shared **sds;
	struct sched_group **sg;
	struct sched_group_capacity **sgc;
};

struct sched_domain_topology_level {
	sched_domain_mask_f mask;
	sched_domain_flags_f sd_flags;
	int flags;
	int numa_level;
	struct sd_data data;
	char *name;
};

enum sched_tunable_scaling {
	SCHED_TUNABLESCALING_NONE = 0,
	SCHED_TUNABLESCALING_LOG = 1,
	SCHED_TUNABLESCALING_LINEAR = 2,
	SCHED_TUNABLESCALING_END = 3,
};

struct s_data {
	struct sched_domain **sd;
	struct root_domain *rd;
};

enum s_alloc {
	sa_rootdomain = 0,
	sa_sd = 1,
	sa_sd_storage = 2,
	sa_none = 3,
};

struct asym_cap_data {
	struct list_head link;
	long unsigned int capacity;
	long unsigned int cpus[0];
};

enum hk_flags {
	HK_FLAG_TIMER = 1,
	HK_FLAG_RCU = 2,
	HK_FLAG_MISC = 4,
	HK_FLAG_SCHED = 8,
	HK_FLAG_TICK = 16,
	HK_FLAG_DOMAIN = 32,
	HK_FLAG_WQ = 64,
	HK_FLAG_MANAGED_IRQ = 128,
	HK_FLAG_KTHREAD = 256,
};

struct housekeeping {
	struct cpumask cpumasks[9];
	long unsigned int flags;
};

struct filter_pred;

struct prog_entry {
	int target;
	int when_to_branch;
	struct filter_pred *pred;
};

struct regex;

typedef int (*regex_match_func)(char *, struct regex *, int);

struct regex {
	char pattern[256];
	int len;
	int field_len;
	regex_match_func match;
};

enum regex_type {
	MATCH_FULL = 0,
	MATCH_FRONT_ONLY = 1,
	MATCH_MIDDLE_ONLY = 2,
	MATCH_END_ONLY = 3,
	MATCH_GLOB = 4,
	MATCH_INDEX = 5,
};

enum filter_op_ids {
	OP_GLOB = 0,
	OP_NE = 1,
	OP_EQ = 2,
	OP_LE = 3,
	OP_LT = 4,
	OP_GE = 5,
	OP_GT = 6,
	OP_BAND = 7,
	OP_MAX = 8,
};

enum filter_pred_fn {
	FILTER_PRED_FN_NOP = 0,
	FILTER_PRED_FN_64 = 1,
	FILTER_PRED_FN_S64 = 2,
	FILTER_PRED_FN_U64 = 3,
	FILTER_PRED_FN_32 = 4,
	FILTER_PRED_FN_S32 = 5,
	FILTER_PRED_FN_U32 = 6,
	FILTER_PRED_FN_16 = 7,
	FILTER_PRED_FN_S16 = 8,
	FILTER_PRED_FN_U16 = 9,
	FILTER_PRED_FN_8 = 10,
	FILTER_PRED_FN_S8 = 11,
	FILTER_PRED_FN_U8 = 12,
	FILTER_PRED_FN_COMM = 13,
	FILTER_PRED_FN_STRING = 14,
	FILTER_PRED_FN_STRLOC = 15,
	FILTER_PRED_FN_STRRELLOC = 16,
	FILTER_PRED_FN_PCHAR_USER = 17,
	FILTER_PRED_FN_PCHAR = 18,
	FILTER_PRED_FN_CPU = 19,
	FILTER_PRED_FN_FUNCTION = 20,
	FILTER_PRED_FN_ = 21,
	FILTER_PRED_TEST_VISITED = 22,
};

struct filter_pred {
	enum filter_pred_fn fn_num;
	u64 val;
	u64 val2;
	struct regex regex;
	short unsigned int *ops;
	struct ftrace_event_field *field;
	int offset;
	int not;
	int op;
};

enum {
	FILT_ERR_NONE = 0,
	FILT_ERR_INVALID_OP = 1,
	FILT_ERR_TOO_MANY_OPEN = 2,
	FILT_ERR_TOO_MANY_CLOSE = 3,
	FILT_ERR_MISSING_QUOTE = 4,
	FILT_ERR_OPERAND_TOO_LONG = 5,
	FILT_ERR_EXPECT_STRING = 6,
	FILT_ERR_EXPECT_DIGIT = 7,
	FILT_ERR_ILLEGAL_FIELD_OP = 8,
	FILT_ERR_FIELD_NOT_FOUND = 9,
	FILT_ERR_ILLEGAL_INTVAL = 10,
	FILT_ERR_BAD_SUBSYS_FILTER = 11,
	FILT_ERR_TOO_MANY_PREDS = 12,
	FILT_ERR_INVALID_FILTER = 13,
	FILT_ERR_IP_FIELD_ONLY = 14,
	FILT_ERR_INVALID_VALUE = 15,
	FILT_ERR_NO_FUNCTION = 16,
	FILT_ERR_ERRNO = 17,
	FILT_ERR_NO_FILTER = 18,
};

struct filter_parse_error {
	int lasterr;
	int lasterr_pos;
};

typedef int (*parse_pred_fn)(const char *, void *, int, struct filter_parse_error *, struct filter_pred **);

enum {
	INVERT = 1,
	PROCESS_AND = 2,
	PROCESS_OR = 4,
};

struct ustring_buffer {
	char buffer[1024];
};

enum {
	TOO_MANY_CLOSE = -1,
	TOO_MANY_OPEN = -2,
	MISSING_QUOTE = -3,
};

struct filter_list {
	struct list_head list;
	struct event_filter *filter;
};

struct function_filter_data {
	struct ftrace_ops *ops;
	int first_filter;
	int first_notrace;
};

struct trace_probe_log {
	const char *subsystem;
	const char **argv;
	int argc;
	int index;
};

struct bpf_iter_seq_prog_info {
	u32 prog_id;
};

struct bpf_iter__bpf_prog {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_prog *prog;
	};
};

struct bpf_local_storage_data;

struct bpf_local_storage {
	struct bpf_local_storage_data *cache[16];
	struct bpf_local_storage_map *smap;
	struct hlist_head list;
	void *owner;
	struct callback_head rcu;
	raw_spinlock_t lock;
};

enum {
	BPF_LOCAL_STORAGE_GET_F_CREATE = 1,
	BPF_SK_STORAGE_GET_F_CREATE = 1,
};

struct bpf_local_storage_map_bucket;

struct bpf_local_storage_map {
	struct bpf_map map;
	struct bpf_local_storage_map_bucket *buckets;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
	struct bpf_mem_alloc selem_ma;
	struct bpf_mem_alloc storage_ma;
	bool bpf_ma;
	long: 64;
};

struct bpf_local_storage_map_bucket {
	struct hlist_head list;
	raw_spinlock_t lock;
};

struct bpf_local_storage_data {
	struct bpf_local_storage_map *smap;
	u8 data[0];
};

struct bpf_local_storage_elem {
	struct hlist_node map_node;
	struct hlist_node snode;
	struct bpf_local_storage *local_storage;
	struct callback_head rcu;
	long: 64;
	struct bpf_local_storage_data sdata;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct bpf_local_storage_cache {
	spinlock_t idx_lock;
	u64 idx_usage_counts[16];
};

typedef u64 (*btf_bpf_task_storage_get_recur)(struct bpf_map *, struct task_struct *, void *, u64, gfp_t);

typedef u64 (*btf_bpf_task_storage_get)(struct bpf_map *, struct task_struct *, void *, u64, gfp_t);

typedef u64 (*btf_bpf_task_storage_delete_recur)(struct bpf_map *, struct task_struct *);

typedef u64 (*btf_bpf_task_storage_delete)(struct bpf_map *, struct task_struct *);

struct btf_enum {
	__u32 name_off;
	__s32 val;
};

struct btf_enum64 {
	__u32 name_off;
	__u32 val_lo32;
	__u32 val_hi32;
};

struct bpf_core_cand {
	const struct btf *btf;
	__u32 id;
};

struct bpf_core_cand_list {
	struct bpf_core_cand *cands;
	int len;
};

struct bpf_core_accessor {
	__u32 type_id;
	__u32 idx;
	const char *name;
};

struct bpf_core_spec {
	const struct btf *btf;
	struct bpf_core_accessor spec[64];
	__u32 root_type_id;
	enum bpf_core_relo_kind relo_kind;
	int len;
	int raw_spec[64];
	int raw_len;
	__u32 bit_offset;
};

struct bpf_core_relo_res {
	__u64 orig_val;
	__u64 new_val;
	bool poison;
	bool validate;
	bool fail_memsz_adjust;
	__u32 orig_sz;
	__u32 orig_type_id;
	__u32 new_sz;
	__u32 new_type_id;
};

enum slab_state {
	DOWN = 0,
	PARTIAL = 1,
	PARTIAL_NODE = 2,
	UP = 3,
	FULL = 4,
};

struct kmalloc_info_struct {
	const char *name[3];
	unsigned int size;
};

struct trace_event_raw_kmem_cache_alloc {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	long unsigned int gfp_flags;
	int node;
	bool accounted;
	char __data[0];
};

struct trace_event_raw_kmalloc {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	long unsigned int gfp_flags;
	int node;
	char __data[0];
};

struct trace_event_raw_kfree {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	char __data[0];
};

struct trace_event_raw_kmem_cache_free {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_mm_page_free {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	char __data[0];
};

struct trace_event_raw_mm_page_free_batched {
	struct trace_entry ent;
	long unsigned int pfn;
	char __data[0];
};

struct trace_event_raw_mm_page_alloc {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	long unsigned int gfp_flags;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	int migratetype;
	int percpu_refill;
	char __data[0];
};

struct trace_event_raw_mm_page_pcpu_drain {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page_alloc_extfrag {
	struct trace_entry ent;
	long unsigned int pfn;
	int alloc_order;
	int fallback_order;
	int alloc_migratetype;
	int fallback_migratetype;
	int change_ownership;
	char __data[0];
};

struct trace_event_raw_rss_stat {
	struct trace_entry ent;
	unsigned int mm_id;
	unsigned int curr;
	int member;
	long int size;
	char __data[0];
};

struct trace_event_data_offsets_kmem_cache_alloc {};

struct trace_event_data_offsets_kmalloc {};

struct trace_event_data_offsets_kfree {};

struct trace_event_data_offsets_kmem_cache_free {
	u32 name;
};

struct trace_event_data_offsets_mm_page_free {};

struct trace_event_data_offsets_mm_page_free_batched {};

struct trace_event_data_offsets_mm_page_alloc {};

struct trace_event_data_offsets_mm_page {};

struct trace_event_data_offsets_mm_page_pcpu_drain {};

struct trace_event_data_offsets_mm_page_alloc_extfrag {};

struct trace_event_data_offsets_rss_stat {};

typedef void (*btf_trace_kmem_cache_alloc)(void *, long unsigned int, const void *, struct kmem_cache *, gfp_t, int);

typedef void (*btf_trace_kmalloc)(void *, long unsigned int, const void *, size_t, size_t, gfp_t, int);

typedef void (*btf_trace_kfree)(void *, long unsigned int, const void *);

typedef void (*btf_trace_kmem_cache_free)(void *, long unsigned int, const void *, const struct kmem_cache *);

typedef void (*btf_trace_mm_page_free)(void *, struct page *, unsigned int);

typedef void (*btf_trace_mm_page_free_batched)(void *, struct page *);

typedef void (*btf_trace_mm_page_alloc)(void *, struct page *, unsigned int, gfp_t, int);

typedef void (*btf_trace_mm_page_alloc_zone_locked)(void *, struct page *, unsigned int, int, int);

typedef void (*btf_trace_mm_page_pcpu_drain)(void *, struct page *, unsigned int, int);

typedef void (*btf_trace_mm_page_alloc_extfrag)(void *, struct page *, int, int, int, int);

typedef void (*btf_trace_rss_stat)(void *, struct mm_struct *, int);

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH = 0,
	TLB_REMOTE_SHOOTDOWN = 1,
	TLB_LOCAL_SHOOTDOWN = 2,
	TLB_LOCAL_MM_SHOOTDOWN = 3,
	TLB_REMOTE_SEND_IPI = 4,
	NR_TLB_FLUSH_REASONS = 5,
};

struct trace_event_raw_tlb_flush {
	struct trace_entry ent;
	int reason;
	long unsigned int pages;
	char __data[0];
};

struct trace_event_data_offsets_tlb_flush {};

typedef void (*btf_trace_tlb_flush)(void *, int, long unsigned int);

struct trace_event_raw_mm_migrate_pages {
	struct trace_entry ent;
	long unsigned int succeeded;
	long unsigned int failed;
	long unsigned int thp_succeeded;
	long unsigned int thp_failed;
	long unsigned int thp_split;
	enum migrate_mode mode;
	int reason;
	char __data[0];
};

struct trace_event_raw_mm_migrate_pages_start {
	struct trace_entry ent;
	enum migrate_mode mode;
	int reason;
	char __data[0];
};

struct trace_event_raw_migration_pte {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int pte;
	int order;
	char __data[0];
};

struct trace_event_data_offsets_mm_migrate_pages {};

struct trace_event_data_offsets_mm_migrate_pages_start {};

struct trace_event_data_offsets_migration_pte {};

typedef void (*btf_trace_mm_migrate_pages)(void *, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, enum migrate_mode, int);

typedef void (*btf_trace_mm_migrate_pages_start)(void *, enum migrate_mode, int);

typedef void (*btf_trace_set_migration_pte)(void *, long unsigned int, long unsigned int, int);

typedef void (*btf_trace_remove_migration_pte)(void *, long unsigned int, long unsigned int, int);

struct folio_referenced_arg {
	int mapcount;
	int referenced;
	long unsigned int vm_flags;
	struct mem_cgroup *memcg;
};

struct stat {
	long unsigned int st_dev;
	long unsigned int st_ino;
	unsigned int st_mode;
	unsigned int st_nlink;
	unsigned int st_uid;
	unsigned int st_gid;
	long unsigned int st_rdev;
	long unsigned int __pad1;
	long int st_size;
	int st_blksize;
	int __pad2;
	long int st_blocks;
	long int st_atime;
	long unsigned int st_atime_nsec;
	long int st_mtime;
	long unsigned int st_mtime_nsec;
	long int st_ctime;
	long unsigned int st_ctime_nsec;
	unsigned int __unused4;
	unsigned int __unused5;
};

struct statx_timestamp {
	__s64 tv_sec;
	__u32 tv_nsec;
	__s32 __reserved;
};

struct statx {
	__u32 stx_mask;
	__u32 stx_blksize;
	__u64 stx_attributes;
	__u32 stx_nlink;
	__u32 stx_uid;
	__u32 stx_gid;
	__u16 stx_mode;
	__u16 __spare0[1];
	__u64 stx_ino;
	__u64 stx_size;
	__u64 stx_blocks;
	__u64 stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime;
	struct statx_timestamp stx_ctime;
	struct statx_timestamp stx_mtime;
	__u32 stx_rdev_major;
	__u32 stx_rdev_minor;
	__u32 stx_dev_major;
	__u32 stx_dev_minor;
	__u64 stx_mnt_id;
	__u32 stx_dio_mem_align;
	__u32 stx_dio_offset_align;
	__u64 __spare3[12];
};

struct fiemap_extent;

struct fiemap_extent_info {
	unsigned int fi_flags;
	unsigned int fi_extents_mapped;
	unsigned int fi_extents_max;
	struct fiemap_extent *fi_extents_start;
};

struct fiemap_extent {
	__u64 fe_logical;
	__u64 fe_physical;
	__u64 fe_length;
	__u64 fe_reserved64[2];
	__u32 fe_flags;
	__u32 fe_reserved[3];
};

struct simple_xattrs {
	struct rb_root rb_root;
	rwlock_t lock;
};

struct simple_xattr {
	struct rb_node rb_node;
	char *name;
	size_t size;
	char value[0];
};

struct xattr_name {
	char name[256];
};

struct xattr_ctx {
	union {
		const void *cvalue;
		void *value;
	};
	void *kvalue;
	size_t size;
	struct xattr_name *kname;
	unsigned int flags;
};

typedef int __kernel_daddr_t;

struct ustat {
	__kernel_daddr_t f_tfree;
	long unsigned int f_tinode;
	char f_fname[6];
	char f_fpack[6];
};

struct statfs {
	__kernel_long_t f_type;
	__kernel_long_t f_bsize;
	__kernel_long_t f_blocks;
	__kernel_long_t f_bfree;
	__kernel_long_t f_bavail;
	__kernel_long_t f_files;
	__kernel_long_t f_ffree;
	__kernel_fsid_t f_fsid;
	__kernel_long_t f_namelen;
	__kernel_long_t f_frsize;
	__kernel_long_t f_flags;
	__kernel_long_t f_spare[4];
};

struct statfs64 {
	__kernel_long_t f_type;
	__kernel_long_t f_bsize;
	__u64 f_blocks;
	__u64 f_bfree;
	__u64 f_bavail;
	__u64 f_files;
	__u64 f_ffree;
	__kernel_fsid_t f_fsid;
	__kernel_long_t f_namelen;
	__kernel_long_t f_frsize;
	__kernel_long_t f_flags;
	__kernel_long_t f_spare[4];
};

struct u32_fract {
	__u32 numerator;
	__u32 denominator;
};

struct clk_fractional_divider {
	struct clk_hw hw;
	void *reg;
	u8 mshift;
	u8 mwidth;
	u8 nshift;
	u8 nwidth;
	u8 flags;
	void (*approximation)(struct clk_hw *, long unsigned int, long unsigned int *, long unsigned int *, long unsigned int *);
	spinlock_t *lock;
};

struct class_dev_iter {
	struct klist_iter ki;
	const struct device_type *type;
	struct subsys_private *sp;
};

struct class_attribute {
	struct attribute attr;
	ssize_t (*show)(const struct class *, const struct class_attribute *, char *);
	ssize_t (*store)(const struct class *, const struct class_attribute *, const char *, size_t);
};

struct class_attribute_string {
	struct class_attribute attr;
	char *str;
};

struct class_interface {
	struct list_head node;
	const struct class *class;
	int (*add_dev)(struct device *);
	void (*remove_dev)(struct device *);
};

struct class_compat {
	struct kobject *kobj;
};

struct minmax_sample {
	u32 t;
	u32 v;
};

struct minmax {
	struct minmax_sample s[3];
};

typedef struct {
	u16 version;
	u16 length;
	u32 runtime_services_supported;
} efi_rt_properties_table_t;

struct linux_efi_memreserve {
	int size;
	atomic_t count;
	phys_addr_t next;
	struct {
		phys_addr_t base;
		phys_addr_t size;
	} entry[0];
};

struct linux_efi_initrd {
	long unsigned int base;
	long unsigned int size;
};

typedef enum {
	EfiPciIoWidthUint8 = 0,
	EfiPciIoWidthUint16 = 1,
	EfiPciIoWidthUint32 = 2,
	EfiPciIoWidthUint64 = 3,
	EfiPciIoWidthFifoUint8 = 4,
	EfiPciIoWidthFifoUint16 = 5,
	EfiPciIoWidthFifoUint32 = 6,
	EfiPciIoWidthFifoUint64 = 7,
	EfiPciIoWidthFillUint8 = 8,
	EfiPciIoWidthFillUint16 = 9,
	EfiPciIoWidthFillUint32 = 10,
	EfiPciIoWidthFillUint64 = 11,
	EfiPciIoWidthMaximum = 12,
} EFI_PCI_IO_PROTOCOL_WIDTH;

typedef struct {
	u32 read;
	u32 write;
} efi_pci_io_protocol_access_32_t;

typedef struct {
	void *read;
	void *write;
} efi_pci_io_protocol_access_t;

union efi_pci_io_protocol;

typedef union efi_pci_io_protocol efi_pci_io_protocol_t;

typedef efi_status_t (*efi_pci_io_protocol_cfg_t)(efi_pci_io_protocol_t *, EFI_PCI_IO_PROTOCOL_WIDTH, u32, long unsigned int, void *);

typedef struct {
	efi_pci_io_protocol_cfg_t read;
	efi_pci_io_protocol_cfg_t write;
} efi_pci_io_protocol_config_access_t;

union efi_pci_io_protocol {
	struct {
		void *poll_mem;
		void *poll_io;
		efi_pci_io_protocol_access_t mem;
		efi_pci_io_protocol_access_t io;
		efi_pci_io_protocol_config_access_t pci;
		void *copy_mem;
		void *map;
		void *unmap;
		void *allocate_buffer;
		void *free_buffer;
		void *flush;
		efi_status_t (*get_location)(efi_pci_io_protocol_t *, long unsigned int *, long unsigned int *, long unsigned int *, long unsigned int *);
		void *attributes;
		void *get_bar_attributes;
		void *set_bar_attributes;
		uint64_t romsize;
		void *romimage;
	};
	struct {
		u32 poll_mem;
		u32 poll_io;
		efi_pci_io_protocol_access_32_t mem;
		efi_pci_io_protocol_access_32_t io;
		efi_pci_io_protocol_access_32_t pci;
		u32 copy_mem;
		u32 map;
		u32 unmap;
		u32 allocate_buffer;
		u32 free_buffer;
		u32 flush;
		u32 get_location;
		u32 attributes;
		u32 get_bar_attributes;
		u32 set_bar_attributes;
		u64 romsize;
		u32 romimage;
	} mixed_mode;
};

enum {
	Root_NFS = 255,
	Root_CIFS = 254,
	Root_Generic = 253,
	Root_RAM0 = 1048576,
};

struct fault_info {
	int (*fn)(long unsigned int, long unsigned int, struct pt_regs *);
	int sig;
	int code;
	const char *name;
};

struct sigqueue {
	struct list_head list;
	int flags;
	kernel_siginfo_t info;
	struct ucounts *ucounts;
};

struct ptrace_peeksiginfo_args {
	__u64 off;
	__u32 flags;
	__s32 nr;
};

struct ptrace_syscall_info {
	__u8 op;
	__u8 pad[3];
	__u32 arch;
	__u64 instruction_pointer;
	__u64 stack_pointer;
	union {
		struct {
			__u64 nr;
			__u64 args[6];
		} entry;
		struct {
			__s64 rval;
			__u8 is_error;
		} exit;
		struct {
			__u64 nr;
			__u64 args[6];
			__u32 ret_data;
		} seccomp;
	};
};

struct ipc_ids {
	int in_use;
	short unsigned int seq;
	struct rw_semaphore rwsem;
	struct idr ipcs_idr;
	int max_idx;
	int last_idx;
	struct rhashtable key_ht;
};

struct ipc_namespace {
	struct ipc_ids ids[3];
	int sem_ctls[4];
	int used_sems;
	unsigned int msg_ctlmax;
	unsigned int msg_ctlmnb;
	unsigned int msg_ctlmni;
	struct percpu_counter percpu_msg_bytes;
	struct percpu_counter percpu_msg_hdrs;
	size_t shm_ctlmax;
	size_t shm_ctlall;
	long unsigned int shm_tot;
	int shm_ctlmni;
	int shm_rmid_forced;
	struct notifier_block ipcns_nb;
	struct vfsmount *mq_mnt;
	unsigned int mq_queues_count;
	unsigned int mq_queues_max;
	unsigned int mq_msg_max;
	unsigned int mq_msgsize_max;
	unsigned int mq_msg_default;
	unsigned int mq_msgsize_default;
	struct ctl_table_set mq_set;
	struct ctl_table_header *mq_sysctls;
	struct ctl_table_set ipc_set;
	struct ctl_table_header *ipc_sysctls;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct llist_node mnt_llist;
	struct ns_common ns;
};

struct ww_acquire_ctx;

struct ww_mutex {
	struct mutex base;
	struct ww_acquire_ctx *ctx;
};

struct ww_acquire_ctx {
	struct task_struct *task;
	long unsigned int stamp;
	unsigned int acquired;
	short unsigned int wounded;
	short unsigned int is_wait_die;
};

struct trace_event_raw_contention_begin {
	struct trace_entry ent;
	void *lock_addr;
	unsigned int flags;
	char __data[0];
};

struct trace_event_raw_contention_end {
	struct trace_entry ent;
	void *lock_addr;
	int ret;
	char __data[0];
};

struct trace_event_data_offsets_contention_begin {};

struct trace_event_data_offsets_contention_end {};

typedef void (*btf_trace_contention_begin)(void *, void *, unsigned int);

typedef void (*btf_trace_contention_end)(void *, void *, int);

struct mutex_waiter {
	struct list_head list;
	struct task_struct *task;
	struct ww_acquire_ctx *ww_ctx;
};

enum {
	GP_IDLE = 0,
	GP_ENTER = 1,
	GP_PASSED = 2,
	GP_EXIT = 3,
	GP_REPLAY = 4,
};

struct dma_map_ops {
	unsigned int flags;
	void * (*alloc)(struct device *, size_t, dma_addr_t *, gfp_t, long unsigned int);
	void (*free)(struct device *, size_t, void *, dma_addr_t, long unsigned int);
	struct page * (*alloc_pages)(struct device *, size_t, dma_addr_t *, enum dma_data_direction, gfp_t);
	void (*free_pages)(struct device *, size_t, struct page *, dma_addr_t, enum dma_data_direction);
	struct sg_table * (*alloc_noncontiguous)(struct device *, size_t, enum dma_data_direction, gfp_t, long unsigned int);
	void (*free_noncontiguous)(struct device *, size_t, struct sg_table *, enum dma_data_direction);
	int (*mmap)(struct device *, struct vm_area_struct *, void *, dma_addr_t, size_t, long unsigned int);
	int (*get_sgtable)(struct device *, struct sg_table *, void *, dma_addr_t, size_t, long unsigned int);
	dma_addr_t (*map_page)(struct device *, struct page *, long unsigned int, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_page)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	int (*map_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	void (*unmap_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	dma_addr_t (*map_resource)(struct device *, phys_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_resource)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*sync_single_for_cpu)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_single_for_device)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_sg_for_cpu)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*sync_sg_for_device)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*cache_sync)(struct device *, void *, size_t, enum dma_data_direction);
	int (*dma_supported)(struct device *, u64);
	u64 (*get_required_mask)(struct device *);
	size_t (*max_mapping_size)(struct device *);
	size_t (*opt_mapping_size)();
	long unsigned int (*get_merge_boundary)(struct device *);
};

struct dma_sgt_handle {
	struct sg_table sgt;
	struct page **pages;
};

struct dma_devres {
	size_t size;
	void *vaddr;
	dma_addr_t dma_handle;
	long unsigned int attrs;
};

typedef __kernel_long_t __kernel_suseconds_t;

typedef __kernel_suseconds_t suseconds_t;

typedef __kernel_clock_t clock_t;

typedef __u64 timeu64_t;

struct __kernel_itimerspec {
	struct __kernel_timespec it_interval;
	struct __kernel_timespec it_value;
};

struct itimerspec64 {
	struct timespec64 it_interval;
	struct timespec64 it_value;
};

struct old_itimerspec32 {
	struct old_timespec32 it_interval;
	struct old_timespec32 it_value;
};

struct __kernel_timex_timeval {
	__kernel_time64_t tv_sec;
	long long int tv_usec;
};

struct __kernel_timex {
	unsigned int modes;
	long long int offset;
	long long int freq;
	long long int maxerror;
	long long int esterror;
	int status;
	long long int constant;
	long long int precision;
	long long int tolerance;
	struct __kernel_timex_timeval time;
	long long int tick;
	long long int ppsfreq;
	long long int jitter;
	int shift;
	long long int stabil;
	long long int jitcnt;
	long long int calcnt;
	long long int errcnt;
	long long int stbcnt;
	int tai;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct trace_bprintk_fmt {
	struct list_head list;
	const char *fmt;
};

enum {
	BPF_F_INDEX_MASK = 4294967295ULL,
	BPF_F_CURRENT_CPU = 4294967295ULL,
	BPF_F_CTXLEN_MASK = 4503595332403200ULL,
};

enum {
	BPF_F_GET_BRANCH_RECORDS_SIZE = 1,
};

struct bpf_perf_event_value {
	__u64 counter;
	__u64 enabled;
	__u64 running;
};

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

struct btf_ptr {
	void *ptr;
	__u32 type_id;
	__u32 flags;
};

enum {
	BTF_F_COMPACT = 1,
	BTF_F_NONAME = 2,
	BTF_F_PTR_RAW = 4,
	BTF_F_ZERO = 8,
};

struct bpf_event_entry {
	struct perf_event *event;
	struct file *perf_file;
	struct file *map_file;
	struct callback_head rcu;
};

typedef long unsigned int (*bpf_ctx_copy_t)(void *, const void *, long unsigned int, long unsigned int);

struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
};

struct perf_event_query_bpf {
	__u32 ids_len;
	__u32 prog_cnt;
	__u32 ids[0];
};

struct trace_event_raw_bpf_trace_printk {
	struct trace_entry ent;
	u32 __data_loc_bpf_string;
	char __data[0];
};

struct trace_event_data_offsets_bpf_trace_printk {
	u32 bpf_string;
};

typedef void (*btf_trace_bpf_trace_printk)(void *, const char *);

struct bpf_trace_module {
	struct module *module;
	struct list_head list;
};

typedef u64 (*btf_bpf_probe_read_user)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_read_user_str)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_read_kernel)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_read_kernel_str)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_read_compat)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_read_compat_str)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_write_user)(void *, const void *, u32);

typedef u64 (*btf_bpf_trace_printk)(char *, u32, u64, u64, u64);

typedef u64 (*btf_bpf_trace_vprintk)(char *, u32, const void *, u32);

typedef u64 (*btf_bpf_seq_printf)(struct seq_file *, char *, u32, const void *, u32);

typedef u64 (*btf_bpf_seq_write)(struct seq_file *, const void *, u32);

typedef u64 (*btf_bpf_seq_printf_btf)(struct seq_file *, struct btf_ptr *, u32, u64);

typedef u64 (*btf_bpf_perf_event_read)(struct bpf_map *, u64);

typedef u64 (*btf_bpf_perf_event_read_value)(struct bpf_map *, u64, struct bpf_perf_event_value *, u32);

struct bpf_trace_sample_data {
	struct perf_sample_data sds[3];
};

typedef u64 (*btf_bpf_perf_event_output)(struct pt_regs *, struct bpf_map *, u64, void *, u64);

struct bpf_nested_pt_regs {
	struct pt_regs regs[3];
};

typedef u64 (*btf_bpf_get_current_task)();

typedef u64 (*btf_bpf_get_current_task_btf)();

typedef u64 (*btf_bpf_task_pt_regs)(struct task_struct *);

typedef u64 (*btf_bpf_current_task_under_cgroup)(struct bpf_map *, u32);

struct send_signal_irq_work {
	struct irq_work irq_work;
	struct task_struct *task;
	u32 sig;
	enum pid_type type;
};

typedef u64 (*btf_bpf_send_signal)(u32);

typedef u64 (*btf_bpf_send_signal_thread)(u32);

typedef u64 (*btf_bpf_d_path)(struct path *, char *, u32);

typedef u64 (*btf_bpf_snprintf_btf)(char *, u32, struct btf_ptr *, u32, u64);

typedef u64 (*btf_bpf_get_func_ip_tracing)(void *);

typedef u64 (*btf_bpf_get_func_ip_kprobe)(struct pt_regs *);

typedef u64 (*btf_bpf_get_func_ip_kprobe_multi)(struct pt_regs *);

typedef u64 (*btf_bpf_get_attach_cookie_kprobe_multi)(struct pt_regs *);

typedef u64 (*btf_bpf_get_attach_cookie_trace)(void *);

typedef u64 (*btf_bpf_get_attach_cookie_pe)(struct bpf_perf_event_data_kern *);

typedef u64 (*btf_bpf_get_attach_cookie_tracing)(void *);

typedef u64 (*btf_bpf_get_branch_snapshot)(void *, u32, u64);

typedef u64 (*btf_get_func_arg)(void *, u32, u64 *);

typedef u64 (*btf_get_func_ret)(void *, u64 *);

typedef u64 (*btf_get_func_arg_cnt)(void *);

typedef u64 (*btf_bpf_perf_event_output_tp)(void *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_get_stackid_tp)(void *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_get_stack_tp)(void *, void *, u32, u64);

typedef u64 (*btf_bpf_perf_prog_read_value)(struct bpf_perf_event_data_kern *, struct bpf_perf_event_value *, u32);

typedef u64 (*btf_bpf_read_branch_records)(struct bpf_perf_event_data_kern *, void *, u32, u64);

struct bpf_raw_tp_regs {
	struct pt_regs regs[3];
};

typedef u64 (*btf_bpf_perf_event_output_raw_tp)(struct bpf_raw_tracepoint_args *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_get_stackid_raw_tp)(struct bpf_raw_tracepoint_args *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_get_stack_raw_tp)(struct bpf_raw_tracepoint_args *, void *, u32, u64);

struct bpf_bloom_filter {
	struct bpf_map map;
	u32 bitset_mask;
	u32 hash_seed;
	u32 nr_hash_funcs;
	long unsigned int bitset[0];
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
};

struct obj_cgroup;

struct bpf_mem_cache {
	struct llist_head free_llist;
	local_t active;
	struct llist_head free_llist_extra;
	struct irq_work refill_work;
	struct obj_cgroup *objcg;
	int unit_size;
	int free_cnt;
	int low_watermark;
	int high_watermark;
	int batch;
	int percpu_size;
	struct callback_head rcu;
	struct llist_head free_by_rcu;
	struct llist_head waiting_for_gp;
	atomic_t call_rcu_in_progress;
};

struct bpf_mem_caches {
	struct bpf_mem_cache cache[11];
};

typedef __le32 uprobe_opcode_t;

struct arch_uprobe {
	union {
		u8 insn[4];
		u8 ixol[4];
	};
	struct arch_probe_insn api;
	bool simulate;
};

struct uprobe {
	struct rb_node rb_node;
	refcount_t ref;
	struct rw_semaphore register_rwsem;
	struct rw_semaphore consumer_rwsem;
	struct list_head pending_list;
	struct uprobe_consumer *consumers;
	struct inode *inode;
	loff_t offset;
	loff_t ref_ctr_offset;
	long unsigned int flags;
	struct arch_uprobe arch;
};

enum rp_check {
	RP_CHECK_CALL = 0,
	RP_CHECK_CHAIN_CALL = 1,
	RP_CHECK_RET = 2,
};

struct vm_special_mapping {
	const char *name;
	struct page **pages;
	vm_fault_t (*fault)(const struct vm_special_mapping *, struct vm_area_struct *, struct vm_fault *);
	int (*mremap)(const struct vm_special_mapping *, struct vm_area_struct *);
};

struct xol_area {
	wait_queue_head_t wq;
	atomic_t slot_count;
	long unsigned int *bitmap;
	struct vm_special_mapping xol_mapping;
	struct page *pages[2];
	long unsigned int vaddr;
};

struct delayed_uprobe {
	struct list_head list;
	struct uprobe *uprobe;
	struct mm_struct *mm;
};

struct __uprobe_key {
	struct inode *inode;
	loff_t offset;
};

struct map_info {
	struct map_info *next;
	struct mm_struct *mm;
	long unsigned int vaddr;
};

struct vm_unmapped_area_info {
	long unsigned int flags;
	long unsigned int length;
	long unsigned int low_limit;
	long unsigned int high_limit;
	long unsigned int align_mask;
	long unsigned int align_offset;
};

enum {
	HUGETLB_SHMFS_INODE = 1,
	HUGETLB_ANONHUGE_INODE = 2,
};

struct trace_event_raw_vm_unmapped_area {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int total_vm;
	long unsigned int flags;
	long unsigned int length;
	long unsigned int low_limit;
	long unsigned int high_limit;
	long unsigned int align_mask;
	long unsigned int align_offset;
	char __data[0];
};

struct trace_event_raw_vma_mas_szero {
	struct trace_entry ent;
	struct maple_tree *mt;
	long unsigned int start;
	long unsigned int end;
	char __data[0];
};

struct trace_event_raw_vma_store {
	struct trace_entry ent;
	struct maple_tree *mt;
	struct vm_area_struct *vma;
	long unsigned int vm_start;
	long unsigned int vm_end;
	char __data[0];
};

struct trace_event_raw_exit_mmap {
	struct trace_entry ent;
	struct mm_struct *mm;
	struct maple_tree *mt;
	char __data[0];
};

struct trace_event_data_offsets_vm_unmapped_area {};

struct trace_event_data_offsets_vma_mas_szero {};

struct trace_event_data_offsets_vma_store {};

struct trace_event_data_offsets_exit_mmap {};

typedef void (*btf_trace_vm_unmapped_area)(void *, long unsigned int, struct vm_unmapped_area_info *);

typedef void (*btf_trace_vma_mas_szero)(void *, struct maple_tree *, long unsigned int, long unsigned int);

typedef void (*btf_trace_vma_store)(void *, struct maple_tree *, struct vm_area_struct *);

typedef void (*btf_trace_exit_mmap)(void *, struct mm_struct *);

struct vma_prepare {
	struct vm_area_struct *vma;
	struct vm_area_struct *adj_next;
	struct file *file;
	struct address_space *mapping;
	struct anon_vma *anon_vma;
	struct vm_area_struct *insert;
	struct vm_area_struct *remove;
	struct vm_area_struct *remove2;
};

struct static_key_true {
	struct static_key key;
};

struct page_frag_cache {
	void *va;
	__u16 offset;
	__u16 size;
	unsigned int pagecnt_bias;
	bool pfmemalloc;
};

typedef void compound_page_dtor(struct page *);

enum oom_constraint {
	CONSTRAINT_NONE = 0,
	CONSTRAINT_CPUSET = 1,
	CONSTRAINT_MEMORY_POLICY = 2,
	CONSTRAINT_MEMCG = 3,
};

struct oom_control {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct mem_cgroup *memcg;
	const gfp_t gfp_mask;
	const int order;
	long unsigned int totalpages;
	struct task_struct *chosen;
	long int chosen_points;
	enum oom_constraint constraint;
};

enum compact_priority {
	COMPACT_PRIO_SYNC_FULL = 0,
	MIN_COMPACT_PRIORITY = 0,
	COMPACT_PRIO_SYNC_LIGHT = 1,
	MIN_COMPACT_COSTLY_PRIORITY = 1,
	DEF_COMPACT_PRIORITY = 1,
	COMPACT_PRIO_ASYNC = 2,
	INIT_COMPACT_PRIORITY = 2,
};

struct alloc_context {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct zoneref *preferred_zoneref;
	int migratetype;
	enum zone_type highest_zoneidx;
	bool spread_dirty_pages;
};

typedef int fpi_t;

struct capture_control;

struct file_clone_range {
	__s64 src_fd;
	__u64 src_offset;
	__u64 src_length;
	__u64 dest_offset;
};

struct fsxattr {
	__u32 fsx_xflags;
	__u32 fsx_extsize;
	__u32 fsx_nextents;
	__u32 fsx_projid;
	__u32 fsx_cowextsize;
	unsigned char fsx_pad[8];
};

struct space_resv {
	__s16 l_type;
	__s16 l_whence;
	__s64 l_start;
	__s64 l_len;
	__s32 l_sysid;
	__u32 l_pid;
	__s32 l_pad[4];
};

struct fiemap {
	__u64 fm_start;
	__u64 fm_length;
	__u32 fm_flags;
	__u32 fm_mapped_extents;
	__u32 fm_extent_count;
	__u32 fm_reserved;
	struct fiemap_extent fm_extents[0];
};

struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};

struct mount_kattr {
	unsigned int attr_set;
	unsigned int attr_clr;
	unsigned int propagation;
	unsigned int lookup_flags;
	bool recurse;
	struct user_namespace *mnt_userns;
	struct mnt_idmap *mnt_idmap;
};

enum umount_tree_flags {
	UMOUNT_SYNC = 1,
	UMOUNT_PROPAGATE = 2,
	UMOUNT_CONNECTED = 4,
};

enum mnt_tree_flags_t {
	MNT_TREE_MOVE = 1,
	MNT_TREE_BENEATH = 2,
};

struct ramfs_mount_opts {
	umode_t mode;
};

struct ramfs_fs_info {
	struct ramfs_mount_opts mount_opts;
};

enum ramfs_param {
	Opt_mode___2 = 0,
};

typedef void (*swap_r_func_t)(void *, void *, int, const void *);

typedef int (*cmp_r_func_t)(const void *, const void *, const void *);

struct wrapper {
	cmp_func_t cmp;
	swap_func_t swap;
};

struct rnd_state {
	__u32 s1;
	__u32 s2;
	__u32 s3;
	__u32 s4;
};

struct region {
	unsigned int start;
	unsigned int off;
	unsigned int group_len;
	unsigned int end;
	unsigned int nbits;
};

enum {
	REG_OP_ISFREE = 0,
	REG_OP_ALLOC = 1,
	REG_OP_RELEASE = 2,
};

struct partition_affinity {
	cpumask_t mask;
	void *partition_id;
};

struct partition_desc {
	int nr_parts;
	struct partition_affinity *parts;
	struct irq_domain *domain;
	struct irq_desc *chained_desc;
	long unsigned int *bitmap;
	struct irq_domain_ops ops;
};

typedef void (*of_init_fn_1)(struct device_node *);

struct clk_fixed_factor {
	struct clk_hw hw;
	unsigned int mult;
	unsigned int div;
};

enum input_clock_type {
	INPUT_CLK_REAL = 0,
	INPUT_CLK_MONO = 1,
	INPUT_CLK_BOOT = 2,
	INPUT_CLK_MAX = 3,
};

struct internal_container {
	struct klist_node node;
	struct attribute_container *cont;
	struct device classdev;
};

typedef void (*irq_write_msi_msg_t)(struct msi_desc *, struct msi_msg *);

struct platform_msi_priv_data {
	struct device *dev;
	void *host_data;
	msi_alloc_info_t arg;
	irq_write_msi_msg_t write_msg;
	int devid;
};

struct serial_icounter_struct {
	int cts;
	int dsr;
	int rng;
	int dcd;
	int rx;
	int tx;
	int frame;
	int overrun;
	int parity;
	int brk;
	int buf_overrun;
	int reserved[9];
};

struct serial_struct {
	int type;
	int line;
	unsigned int port;
	int irq;
	int flags;
	int xmit_fifo_size;
	int custom_divisor;
	int baud_base;
	short unsigned int close_delay;
	char io_type;
	char reserved_char[1];
	int hub6;
	short unsigned int closing_wait;
	short unsigned int closing_wait2;
	unsigned char *iomem_base;
	short unsigned int iomem_reg_shift;
	unsigned int port_high;
	long unsigned int iomap_base;
};

struct fdt_errtabent {
	const char *str;
};

enum {
	LOGIC_PIO_INDIRECT = 0,
	LOGIC_PIO_CPU_MMIO = 1,
};

struct logic_pio_host_ops;

struct logic_pio_hwaddr {
	struct list_head list;
	struct fwnode_handle *fwnode;
	resource_size_t hw_start;
	resource_size_t io_start;
	resource_size_t size;
	long unsigned int flags;
	void *hostdata;
	const struct logic_pio_host_ops *ops;
};

struct logic_pio_host_ops {
	u32 (*in)(void *, long unsigned int, size_t);
	void (*out)(void *, long unsigned int, u32, size_t);
	u32 (*ins)(void *, long unsigned int, void *, size_t, unsigned int);
	void (*outs)(void *, long unsigned int, const void *, size_t, unsigned int);
};

struct tcpa_event {
	u32 pcr_index;
	u32 event_type;
	u8 pcr_value[20];
	u32 event_size;
	u8 event_data[0];
};

typedef u32 efi_tcg2_event_log_format;

struct efi_tcg2_event {
	u32 event_size;
	struct {
		u32 header_size;
		u16 header_version;
		u32 pcr_index;
		u32 event_type;
	} __attribute__((packed)) event_header;
} __attribute__((packed));

typedef struct efi_tcg2_event efi_tcg2_event_t;

union efi_tcg2_protocol;

typedef union efi_tcg2_protocol efi_tcg2_protocol_t;

union efi_tcg2_protocol {
	struct {
		void *get_capability;
		efi_status_t (*get_event_log)(efi_tcg2_protocol_t *, efi_tcg2_event_log_format, efi_physical_addr_t *, efi_physical_addr_t *, efi_bool_t *);
		efi_status_t (*hash_log_extend_event)(efi_tcg2_protocol_t *, u64, efi_physical_addr_t, u64, const efi_tcg2_event_t *);
		void *submit_command;
		void *get_active_pcr_banks;
		void *set_active_pcr_banks;
		void *get_result_of_set_active_pcr_banks;
	};
	struct {
		u32 get_capability;
		u32 get_event_log;
		u32 hash_log_extend_event;
		u32 submit_command;
		u32 get_active_pcr_banks;
		u32 set_active_pcr_banks;
		u32 get_result_of_set_active_pcr_banks;
	} mixed_mode;
};

struct nmi_ctx {
	u64 hcr;
	unsigned int cnt;
};

struct mpidr_hash {
	u64 mask;
	u32 shift_aff[4];
	u32 bits;
};

struct cpuinfo_32bit {
	u32 reg_id_dfr0;
	u32 reg_id_dfr1;
	u32 reg_id_isar0;
	u32 reg_id_isar1;
	u32 reg_id_isar2;
	u32 reg_id_isar3;
	u32 reg_id_isar4;
	u32 reg_id_isar5;
	u32 reg_id_isar6;
	u32 reg_id_mmfr0;
	u32 reg_id_mmfr1;
	u32 reg_id_mmfr2;
	u32 reg_id_mmfr3;
	u32 reg_id_mmfr4;
	u32 reg_id_mmfr5;
	u32 reg_id_pfr0;
	u32 reg_id_pfr1;
	u32 reg_id_pfr2;
	u32 reg_mvfr0;
	u32 reg_mvfr1;
	u32 reg_mvfr2;
};

struct cpuinfo_arm64 {
	struct cpu cpu;
	struct kobject kobj;
	u64 reg_ctr;
	u64 reg_cntfrq;
	u64 reg_dczid;
	u64 reg_midr;
	u64 reg_revidr;
	u64 reg_gmid;
	u64 reg_smidr;
	u64 reg_id_aa64dfr0;
	u64 reg_id_aa64dfr1;
	u64 reg_id_aa64isar0;
	u64 reg_id_aa64isar1;
	u64 reg_id_aa64isar2;
	u64 reg_id_aa64mmfr0;
	u64 reg_id_aa64mmfr1;
	u64 reg_id_aa64mmfr2;
	u64 reg_id_aa64mmfr3;
	u64 reg_id_aa64pfr0;
	u64 reg_id_aa64pfr1;
	u64 reg_id_aa64zfr0;
	u64 reg_id_aa64smfr0;
	struct cpuinfo_32bit aarch32;
	u64 reg_zcr;
	u64 reg_smcr;
};

typedef int (*pte_fn_t)(pte_t *, long unsigned int, void *);

struct set_perm_data {
	const efi_memory_desc_t *md;
	bool has_bti;
};

enum {
	NDD_UNARMED = 1,
	NDD_LOCKED = 2,
	NDD_SECURITY_OVERWRITE = 3,
	NDD_WORK_PENDING = 4,
	NDD_LABELING = 6,
	NDD_INCOHERENT = 7,
	NDD_REGISTER_SYNC = 8,
	ND_IOCTL_MAX_BUFLEN = 4194304,
	ND_CMD_MAX_ELEM = 5,
	ND_CMD_MAX_ENVELOPE = 256,
	ND_MAX_MAPPINGS = 32,
	ND_REGION_PAGEMAP = 0,
	ND_REGION_PERSIST_CACHE = 1,
	ND_REGION_PERSIST_MEMCTRL = 2,
	ND_REGION_ASYNC = 3,
	ND_REGION_CXL = 4,
	DPA_RESOURCE_ADJUSTED = 1,
};

struct taint_flag {
	char c_true;
	char c_false;
	bool module;
};

enum error_detector {
	ERROR_DETECTOR_KFENCE = 0,
	ERROR_DETECTOR_KASAN = 1,
	ERROR_DETECTOR_WARN = 2,
};

struct warn_args {
	const char *fmt;
	va_list args;
};

struct die_args {
	struct pt_regs *regs;
	const char *str;
	long int err;
	int trapnr;
	int signr;
};

struct srcu_notifier_head {
	struct mutex mutex;
	struct srcu_usage srcuu;
	struct srcu_struct srcu;
	struct notifier_block *head;
};

struct trace_event_raw_notifier_info {
	struct trace_entry ent;
	void *cb;
	char __data[0];
};

struct trace_event_data_offsets_notifier_info {};

typedef void (*btf_trace_notifier_register)(void *, void *);

typedef void (*btf_trace_notifier_unregister)(void *, void *);

typedef void (*btf_trace_notifier_run)(void *, void *);

struct semaphore_waiter {
	struct list_head list;
	struct task_struct *task;
	bool up;
};

struct mcs_spinlock {
	struct mcs_spinlock *next;
	int locked;
	int count;
};

struct qnode {
	struct mcs_spinlock mcs;
};

struct latch_tree_root {
	seqcount_latch_t seq;
	struct rb_root tree[2];
};

enum kernel_read_file_id {
	READING_UNKNOWN = 0,
	READING_FIRMWARE = 1,
	READING_MODULE = 2,
	READING_KEXEC_IMAGE = 3,
	READING_KEXEC_INITRAMFS = 4,
	READING_POLICY = 5,
	READING_X509_CERTIFICATE = 6,
	READING_MAX_ID = 7,
};

enum kernel_load_data_id {
	LOADING_UNKNOWN = 0,
	LOADING_FIRMWARE = 1,
	LOADING_MODULE = 2,
	LOADING_KEXEC_IMAGE = 3,
	LOADING_KEXEC_INITRAMFS = 4,
	LOADING_POLICY = 5,
	LOADING_X509_CERTIFICATE = 6,
	LOADING_MAX_ID = 7,
};

enum mod_license {
	NOT_GPL_ONLY = 0,
	GPL_ONLY = 1,
};

struct find_symbol_arg {
	const char *name;
	bool gplok;
	bool warn;
	struct module *owner;
	const s32 *crc;
	const struct kernel_symbol *sym;
	enum mod_license license;
};

enum fail_dup_mod_reason {
	FAIL_DUP_MOD_BECOMING = 0,
	FAIL_DUP_MOD_LOAD = 1,
};

struct mod_tree_root {
	struct latch_tree_root root;
	long unsigned int addr_min;
	long unsigned int addr_max;
};

struct trace_event_raw_module_load {
	struct trace_entry ent;
	unsigned int taints;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_module_free {
	struct trace_entry ent;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_module_request {
	struct trace_entry ent;
	long unsigned int ip;
	bool wait;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_data_offsets_module_load {
	u32 name;
};

struct trace_event_data_offsets_module_free {
	u32 name;
};

struct trace_event_data_offsets_module_request {
	u32 name;
};

typedef void (*btf_trace_module_load)(void *, struct module *);

typedef void (*btf_trace_module_free)(void *, struct module *);

typedef void (*btf_trace_module_request)(void *, char *, bool, long unsigned int);

struct symsearch {
	const struct kernel_symbol *start;
	const struct kernel_symbol *stop;
	const s32 *crcs;
	enum mod_license license;
};

struct mod_initfree {
	struct llist_node node;
	void *init_text;
	void *init_data;
	void *init_rodata;
};

enum trace_iter_flags {
	TRACE_FILE_LAT_FMT = 1,
	TRACE_FILE_ANNOTATE = 2,
	TRACE_FILE_TIME_IN_NS = 4,
};

struct ctx_switch_entry {
	struct trace_entry ent;
	unsigned int prev_pid;
	unsigned int next_pid;
	unsigned int next_cpu;
	unsigned char prev_prio;
	unsigned char prev_state;
	unsigned char next_prio;
	unsigned char next_state;
};

struct stack_entry {
	struct trace_entry ent;
	int size;
	long unsigned int caller[8];
};

struct userstack_entry {
	struct trace_entry ent;
	unsigned int tgid;
	long unsigned int caller[8];
};

struct bprint_entry {
	struct trace_entry ent;
	long unsigned int ip;
	const char *fmt;
	u32 buf[0];
};

struct print_entry {
	struct trace_entry ent;
	long unsigned int ip;
	char buf[0];
};

struct raw_data_entry {
	struct trace_entry ent;
	unsigned int id;
	char buf[0];
};

struct bputs_entry {
	struct trace_entry ent;
	long unsigned int ip;
	const char *str;
};

struct hwlat_entry {
	struct trace_entry ent;
	u64 duration;
	u64 outer_duration;
	u64 nmi_total_ts;
	struct timespec64 timestamp;
	unsigned int nmi_count;
	unsigned int seqnum;
	unsigned int count;
};

struct func_repeats_entry {
	struct trace_entry ent;
	long unsigned int ip;
	long unsigned int parent_ip;
	u16 count;
	u16 top_delta_ts;
	u32 bottom_delta_ts;
};

struct osnoise_entry {
	struct trace_entry ent;
	u64 noise;
	u64 runtime;
	u64 max_sample;
	unsigned int hw_count;
	unsigned int nmi_count;
	unsigned int irq_count;
	unsigned int softirq_count;
	unsigned int thread_count;
};

struct timerlat_entry {
	struct trace_entry ent;
	unsigned int seqnum;
	int context;
	u64 timer_latency;
};

enum trace_iterator_flags {
	TRACE_ITER_PRINT_PARENT = 1,
	TRACE_ITER_SYM_OFFSET = 2,
	TRACE_ITER_SYM_ADDR = 4,
	TRACE_ITER_VERBOSE = 8,
	TRACE_ITER_RAW = 16,
	TRACE_ITER_HEX = 32,
	TRACE_ITER_BIN = 64,
	TRACE_ITER_BLOCK = 128,
	TRACE_ITER_FIELDS = 256,
	TRACE_ITER_PRINTK = 512,
	TRACE_ITER_ANNOTATE = 1024,
	TRACE_ITER_USERSTACKTRACE = 2048,
	TRACE_ITER_SYM_USEROBJ = 4096,
	TRACE_ITER_PRINTK_MSGONLY = 8192,
	TRACE_ITER_CONTEXT_INFO = 16384,
	TRACE_ITER_LATENCY_FMT = 32768,
	TRACE_ITER_RECORD_CMD = 65536,
	TRACE_ITER_RECORD_TGID = 131072,
	TRACE_ITER_OVERWRITE = 262144,
	TRACE_ITER_STOP_ON_FREE = 524288,
	TRACE_ITER_IRQ_INFO = 1048576,
	TRACE_ITER_MARKERS = 2097152,
	TRACE_ITER_EVENT_FORK = 4194304,
	TRACE_ITER_PAUSE_ON_TRACE = 8388608,
	TRACE_ITER_HASH_PTR = 16777216,
	TRACE_ITER_FUNCTION = 33554432,
	TRACE_ITER_FUNC_FORK = 67108864,
	TRACE_ITER_DISPLAY_GRAPH = 134217728,
	TRACE_ITER_STACKTRACE = 268435456,
};

struct trace_mark {
	long long unsigned int val;
	char sym;
};

enum {
	TRACE_PIDS = 1,
	TRACE_NO_PIDS = 2,
};

struct trace_parser {
	bool cont;
	char *buffer;
	unsigned int idx;
	unsigned int size;
};

struct module_string {
	struct list_head next;
	struct module *module;
	char *str;
};

enum {
	FORMAT_HEADER = 1,
	FORMAT_FIELD_SEPERATOR = 2,
	FORMAT_PRINTFMT = 3,
};

struct boot_triggers {
	const char *event;
	char *trigger;
};

struct event_probe_data {
	struct trace_event_file *file;
	long unsigned int count;
	int ref;
	bool enable;
};

struct bpf_spin_lock {
	__u32 val;
};

struct bpf_timer {
	long: 64;
	long: 64;
};

struct bpf_dynptr {
	long: 64;
	long: 64;
};

struct bpf_list_head {
	long: 64;
	long: 64;
};

struct bpf_list_node {
	long: 64;
	long: 64;
};

struct bpf_rb_root {
	long: 64;
	long: 64;
};

struct bpf_rb_node {
	long: 64;
	long: 64;
	long: 64;
};

struct bpf_refcount {
	int: 32;
};

struct bpf_pidns_info {
	__u32 pid;
	__u32 tgid;
};

enum {
	BPF_F_TIMER_ABS = 1,
};

typedef u64 (*btf_bpf_map_lookup_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_update_elem)(struct bpf_map *, void *, void *, u64);

typedef u64 (*btf_bpf_map_delete_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_push_elem)(struct bpf_map *, void *, u64);

typedef u64 (*btf_bpf_map_pop_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_peek_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_lookup_percpu_elem)(struct bpf_map *, void *, u32);

typedef u64 (*btf_bpf_get_smp_processor_id)();

typedef u64 (*btf_bpf_get_numa_node_id)();

typedef u64 (*btf_bpf_ktime_get_ns)();

typedef u64 (*btf_bpf_ktime_get_boot_ns)();

typedef u64 (*btf_bpf_ktime_get_coarse_ns)();

typedef u64 (*btf_bpf_ktime_get_tai_ns)();

typedef u64 (*btf_bpf_get_current_pid_tgid)();

typedef u64 (*btf_bpf_get_current_uid_gid)();

typedef u64 (*btf_bpf_get_current_comm)(char *, u32);

typedef u64 (*btf_bpf_spin_lock)(struct bpf_spin_lock *);

typedef u64 (*btf_bpf_spin_unlock)(struct bpf_spin_lock *);

typedef u64 (*btf_bpf_jiffies64)();

typedef u64 (*btf_bpf_strtol)(const char *, size_t, u64, long int *);

typedef u64 (*btf_bpf_strtoul)(const char *, size_t, u64, long unsigned int *);

typedef u64 (*btf_bpf_strncmp)(const char *, u32, const char *);

typedef u64 (*btf_bpf_get_ns_current_pid_tgid)(u64, u64, struct bpf_pidns_info *, u32);

typedef u64 (*btf_bpf_event_output_data)(void *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_copy_from_user)(void *, u32, const void *);

typedef u64 (*btf_bpf_copy_from_user_task)(void *, u32, const void *, struct task_struct *, u64);

typedef u64 (*btf_bpf_per_cpu_ptr)(const void *, u32);

typedef u64 (*btf_bpf_this_cpu_ptr)(const void *);

struct bpf_bprintf_buffers {
	char bin_args[512];
	char buf[1024];
};

typedef u64 (*btf_bpf_snprintf)(char *, u32, char *, const void *, u32);

struct bpf_hrtimer {
	struct hrtimer timer;
	struct bpf_map *map;
	struct bpf_prog *prog;
	void *callback_fn;
	void *value;
};

struct bpf_timer_kern {
	struct bpf_hrtimer *timer;
	struct bpf_spin_lock lock;
};

typedef u64 (*btf_bpf_timer_init)(struct bpf_timer_kern *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_timer_set_callback)(struct bpf_timer_kern *, void *, struct bpf_prog_aux *);

typedef u64 (*btf_bpf_timer_start)(struct bpf_timer_kern *, u64, u64);

typedef u64 (*btf_bpf_timer_cancel)(struct bpf_timer_kern *);

typedef u64 (*btf_bpf_kptr_xchg)(void *, void *);

typedef u64 (*btf_bpf_dynptr_from_mem)(void *, u32, u64, struct bpf_dynptr_kern *);

typedef u64 (*btf_bpf_dynptr_read)(void *, u32, const struct bpf_dynptr_kern *, u32, u64);

typedef u64 (*btf_bpf_dynptr_write)(const struct bpf_dynptr_kern *, u32, void *, u32, u64);

typedef u64 (*btf_bpf_dynptr_data)(const struct bpf_dynptr_kern *, u32, u32);

enum {
	BTF_VAR_STATIC = 0,
	BTF_VAR_GLOBAL_ALLOCATED = 1,
	BTF_VAR_GLOBAL_EXTERN = 2,
};

struct btf_var {
	__u32 linkage;
};

struct btf_decl_tag {
	__s32 component_idx;
};

struct bpf_btf_info {
	__u64 btf;
	__u32 btf_size;
	__u32 id;
	__u64 name;
	__u32 name_len;
	__u32 kernel_btf;
};

struct btf_struct_metas {
	u32 cnt;
	struct btf_struct_meta types[0];
};

enum {
	BTF_FIELDS_MAX = 10,
};

struct inet_ehash_bucket;

struct inet_bind_hashbucket;

struct inet_listen_hashbucket;

struct inet_hashinfo {
	struct inet_ehash_bucket *ehash;
	spinlock_t *ehash_locks;
	unsigned int ehash_mask;
	unsigned int ehash_locks_mask;
	struct kmem_cache *bind_bucket_cachep;
	struct inet_bind_hashbucket *bhash;
	struct kmem_cache *bind2_bucket_cachep;
	struct inet_bind_hashbucket *bhash2;
	unsigned int bhash_size;
	unsigned int lhash2_mask;
	struct inet_listen_hashbucket *lhash2;
	bool pernet;
};

struct ip_ra_chain {
	struct ip_ra_chain *next;
	struct sock *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};

struct inet_peer_base {
	struct rb_root rb_root;
	seqlock_t lock;
	int total;
};

struct tcp_fastopen_context {
	siphash_key_t key[2];
	int num;
	struct callback_head rcu;
};

struct lwtunnel_state {
	__u16 type;
	__u16 flags;
	__u16 headroom;
	atomic_t refcnt;
	int (*orig_output)(struct net *, struct sock *, struct sk_buff *);
	int (*orig_input)(struct sk_buff *);
	struct callback_head rcu;
	__u8 data[0];
};

struct sock_reuseport {
	struct callback_head rcu;
	u16 max_socks;
	u16 num_socks;
	u16 num_closed_socks;
	u16 incoming_cpu;
	unsigned int synq_overflow_ts;
	unsigned int reuseport_id;
	unsigned int bind_inany: 1;
	unsigned int has_conns: 1;
	struct bpf_prog *prog;
	struct sock *socks[0];
};

struct sk_psock_progs {
	struct bpf_prog *msg_parser;
	struct bpf_prog *stream_parser;
	struct bpf_prog *stream_verdict;
	struct bpf_prog *skb_verdict;
};

struct sk_psock_work_state {
	u32 len;
	u32 off;
};

struct sk_msg;

struct sk_psock {
	struct sock *sk;
	struct sock *sk_redir;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 eval;
	bool redir_ingress;
	struct sk_msg *cork;
	struct sk_psock_progs progs;
	struct sk_buff_head ingress_skb;
	struct list_head ingress_msg;
	spinlock_t ingress_lock;
	long unsigned int state;
	struct list_head link;
	spinlock_t link_lock;
	refcount_t refcnt;
	void (*saved_unhash)(struct sock *);
	void (*saved_destroy)(struct sock *);
	void (*saved_close)(struct sock *, long int);
	void (*saved_write_space)(struct sock *);
	void (*saved_data_ready)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	struct proto *sk_proto;
	struct mutex work_mutex;
	struct sk_psock_work_state work_state;
	struct delayed_work work;
	struct rcu_work rwork;
};

enum {
	__ND_OPT_PREFIX_INFO_END = 0,
	ND_OPT_SOURCE_LL_ADDR = 1,
	ND_OPT_TARGET_LL_ADDR = 2,
	ND_OPT_PREFIX_INFO = 3,
	ND_OPT_REDIRECT_HDR = 4,
	ND_OPT_MTU = 5,
	ND_OPT_NONCE = 14,
	__ND_OPT_ARRAY_MAX = 15,
	ND_OPT_ROUTE_INFO = 24,
	ND_OPT_RDNSS = 25,
	ND_OPT_DNSSL = 31,
	ND_OPT_6CO = 34,
	ND_OPT_CAPTIVE_PORTAL = 37,
	ND_OPT_PREF64 = 38,
	__ND_OPT_MAX = 39,
};

struct inet_ehash_bucket {
	struct hlist_nulls_head chain;
};

struct inet_bind_hashbucket {
	spinlock_t lock;
	struct hlist_head chain;
};

struct inet_listen_hashbucket {
	spinlock_t lock;
	struct hlist_nulls_head nulls_head;
};

struct ack_sample {
	u32 pkts_acked;
	s32 rtt_us;
	u32 in_flight;
};

struct rate_sample {
	u64 prior_mstamp;
	u32 prior_delivered;
	u32 prior_delivered_ce;
	s32 delivered;
	s32 delivered_ce;
	long int interval_us;
	u32 snd_interval_us;
	u32 rcv_interval_us;
	long int rtt_us;
	int losses;
	u32 acked_sacked;
	u32 prior_in_flight;
	u32 last_end_seq;
	bool is_app_limited;
	bool is_retrans;
	bool is_ack_delayed;
};

struct sk_msg_sg {
	u32 start;
	u32 curr;
	u32 end;
	u32 size;
	u32 copybreak;
	long unsigned int copy[1];
	struct scatterlist data[19];
};

struct sk_msg {
	struct sk_msg_sg sg;
	void *data;
	void *data_end;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 flags;
	struct sk_buff *skb;
	struct sock *sk_redir;
	struct sock *sk;
	struct list_head list;
};

enum btf_kfunc_hook {
	BTF_KFUNC_HOOK_COMMON = 0,
	BTF_KFUNC_HOOK_XDP = 1,
	BTF_KFUNC_HOOK_TC = 2,
	BTF_KFUNC_HOOK_STRUCT_OPS = 3,
	BTF_KFUNC_HOOK_TRACING = 4,
	BTF_KFUNC_HOOK_SYSCALL = 5,
	BTF_KFUNC_HOOK_FMODRET = 6,
	BTF_KFUNC_HOOK_CGROUP_SKB = 7,
	BTF_KFUNC_HOOK_SCHED_ACT = 8,
	BTF_KFUNC_HOOK_SK_SKB = 9,
	BTF_KFUNC_HOOK_SOCKET_FILTER = 10,
	BTF_KFUNC_HOOK_LWT = 11,
	BTF_KFUNC_HOOK_NETFILTER = 12,
	BTF_KFUNC_HOOK_MAX = 13,
};

enum {
	BTF_KFUNC_SET_MAX_CNT = 256,
	BTF_DTOR_KFUNC_MAX_CNT = 256,
};

struct btf_kfunc_set_tab {
	struct btf_id_set8 *sets[13];
};

struct btf_id_dtor_kfunc_tab {
	u32 cnt;
	struct btf_id_dtor_kfunc dtors[0];
};

enum verifier_phase {
	CHECK_META = 0,
	CHECK_TYPE = 1,
};

struct resolve_vertex {
	const struct btf_type *t;
	u32 type_id;
	u16 next_member;
};

enum visit_state {
	NOT_VISITED = 0,
	VISITED = 1,
	RESOLVED = 2,
};

enum resolve_mode {
	RESOLVE_TBD = 0,
	RESOLVE_PTR = 1,
	RESOLVE_STRUCT_OR_ARRAY = 2,
};

struct btf_sec_info {
	u32 off;
	u32 len;
};

struct btf_verifier_env {
	struct btf *btf;
	u8 *visit_states;
	struct resolve_vertex stack[32];
	struct bpf_verifier_log log;
	u32 log_type_id;
	u32 top_stack;
	enum verifier_phase phase;
	enum resolve_mode resolve_mode;
};

struct btf_show {
	u64 flags;
	void *target;
	void (*showfn)(struct btf_show *, const char *, va_list);
	const struct btf *btf;
	struct {
		u8 depth;
		u8 depth_to_show;
		u8 depth_check;
		u8 array_member: 1;
		u8 array_terminated: 1;
		u16 array_encoding;
		u32 type_id;
		int status;
		const struct btf_type *type;
		const struct btf_member *member;
		char name[80];
	} state;
	struct {
		u32 size;
		void *head;
		void *data;
		u8 safe[32];
	} obj;
};

struct btf_kind_operations {
	s32 (*check_meta)(struct btf_verifier_env *, const struct btf_type *, u32);
	int (*resolve)(struct btf_verifier_env *, const struct resolve_vertex *);
	int (*check_member)(struct btf_verifier_env *, const struct btf_type *, const struct btf_member *, const struct btf_type *);
	int (*check_kflag_member)(struct btf_verifier_env *, const struct btf_type *, const struct btf_member *, const struct btf_type *);
	void (*log_details)(struct btf_verifier_env *, const struct btf_type *);
	void (*show)(const struct btf *, const struct btf_type *, u32, void *, u8, struct btf_show *);
};

enum {
	BTF_FIELD_IGNORE = 0,
	BTF_FIELD_FOUND = 1,
};

struct btf_field_info {
	enum btf_field_type type;
	u32 off;
	union {
		struct {
			u32 type_id;
		} kptr;
		struct {
			const char *node_name;
			u32 value_btf_id;
		} graph_root;
	};
};

struct bpf_ctx_convert {
	bpf_user_pt_regs_t BPF_PROG_TYPE_KPROBE_prog;
	struct pt_regs BPF_PROG_TYPE_KPROBE_kern;
	__u64 BPF_PROG_TYPE_TRACEPOINT_prog;
	u64 BPF_PROG_TYPE_TRACEPOINT_kern;
	struct bpf_perf_event_data BPF_PROG_TYPE_PERF_EVENT_prog;
	struct bpf_perf_event_data_kern BPF_PROG_TYPE_PERF_EVENT_kern;
	struct bpf_raw_tracepoint_args BPF_PROG_TYPE_RAW_TRACEPOINT_prog;
	u64 BPF_PROG_TYPE_RAW_TRACEPOINT_kern;
	struct bpf_raw_tracepoint_args BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE_prog;
	u64 BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE_kern;
	void *BPF_PROG_TYPE_TRACING_prog;
	void *BPF_PROG_TYPE_TRACING_kern;
	void *BPF_PROG_TYPE_STRUCT_OPS_prog;
	void *BPF_PROG_TYPE_STRUCT_OPS_kern;
	void *BPF_PROG_TYPE_EXT_prog;
	void *BPF_PROG_TYPE_EXT_kern;
	void *BPF_PROG_TYPE_SYSCALL_prog;
	void *BPF_PROG_TYPE_SYSCALL_kern;
};

enum {
	__ctx_convertBPF_PROG_TYPE_KPROBE = 0,
	__ctx_convertBPF_PROG_TYPE_TRACEPOINT = 1,
	__ctx_convertBPF_PROG_TYPE_PERF_EVENT = 2,
	__ctx_convertBPF_PROG_TYPE_RAW_TRACEPOINT = 3,
	__ctx_convertBPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 4,
	__ctx_convertBPF_PROG_TYPE_TRACING = 5,
	__ctx_convertBPF_PROG_TYPE_STRUCT_OPS = 6,
	__ctx_convertBPF_PROG_TYPE_EXT = 7,
	__ctx_convertBPF_PROG_TYPE_SYSCALL = 8,
	__ctx_convert_unused = 9,
};

enum bpf_struct_walk_result {
	WALK_SCALAR = 0,
	WALK_PTR = 1,
	WALK_STRUCT = 2,
};

struct btf_show_snprintf {
	struct btf_show show;
	int len_left;
	int len;
};

enum {
	BTF_MODULE_F_LIVE = 1,
};

struct btf_module {
	struct list_head list;
	struct module *module;
	struct btf *btf;
	struct bin_attribute *sysfs_attr;
	int flags;
};

typedef u64 (*btf_bpf_btf_find_by_name_kind)(char *, int, u32, int);

struct bpf_cand_cache {
	const char *name;
	u32 name_len;
	u16 kind;
	u16 cnt;
	struct {
		const struct btf *btf;
		u32 id;
	} cands[0];
};

typedef struct {
	u64 val;
} pfn_t;

typedef unsigned int zap_flags_t;

typedef unsigned int pgtbl_mod_mask;

struct zap_details {
	struct folio *single_folio;
	bool even_cows;
	zap_flags_t zap_flags;
};

struct char_device_struct {
	struct char_device_struct *next;
	unsigned int major;
	unsigned int baseminor;
	int minorct;
	char name[64];
	struct cdev *cdev;
};

typedef struct {
	long unsigned int fds_bits[16];
} __kernel_fd_set;

typedef __kernel_fd_set fd_set;

struct old_timeval32 {
	old_time32_t tv_sec;
	s32 tv_usec;
};

struct poll_table_entry {
	struct file *filp;
	__poll_t key;
	wait_queue_entry_t wait;
	wait_queue_head_t *wait_address;
};

struct poll_table_page;

struct poll_wqueues {
	poll_table pt;
	struct poll_table_page *table;
	struct task_struct *polling_task;
	int triggered;
	int error;
	int inline_index;
	struct poll_table_entry inline_entries[9];
};

struct poll_table_page {
	struct poll_table_page *next;
	struct poll_table_entry *entry;
	struct poll_table_entry entries[0];
};

enum poll_time_type {
	PT_TIMEVAL = 0,
	PT_OLD_TIMEVAL = 1,
	PT_TIMESPEC = 2,
	PT_OLD_TIMESPEC = 3,
};

typedef struct {
	long unsigned int *in;
	long unsigned int *out;
	long unsigned int *ex;
	long unsigned int *res_in;
	long unsigned int *res_out;
	long unsigned int *res_ex;
} fd_set_bits;

struct sigset_argpack {
	sigset_t *p;
	size_t size;
};

struct poll_list {
	struct poll_list *next;
	int len;
	struct pollfd entries[0];
};

enum fsconfig_command {
	FSCONFIG_SET_FLAG = 0,
	FSCONFIG_SET_STRING = 1,
	FSCONFIG_SET_BINARY = 2,
	FSCONFIG_SET_PATH = 3,
	FSCONFIG_SET_PATH_EMPTY = 4,
	FSCONFIG_SET_FD = 5,
	FSCONFIG_CMD_CREATE = 6,
	FSCONFIG_CMD_RECONFIGURE = 7,
};

typedef int (*of_init_fn_2)(struct device_node *, struct device_node *);

enum gic_type {
	GIC_V2 = 0,
	GIC_V3 = 1,
};

struct gic_kvm_info {
	enum gic_type type;
	struct resource vcpu;
	unsigned int maint_irq;
	bool no_maint_irq_mask;
	struct resource vctrl;
	bool has_v4;
	bool has_v4_1;
	bool no_hw_deactivation;
};

struct gic_quirk {
	const char *desc;
	const char *compatible;
	const char *property;
	bool (*init)(void *);
	u32 iidr;
	u32 mask;
};

union gic_base {
	void *common_base;
	void **percpu_base;
};

struct gic_chip_data {
	union gic_base dist_base;
	union gic_base cpu_base;
	void *raw_dist_base;
	void *raw_cpu_base;
	u32 percpu_offset;
	struct irq_domain *domain;
	unsigned int gic_irqs;
};

struct clk_lookup {
	struct list_head node;
	const char *dev_id;
	const char *con_id;
	struct clk *clk;
	struct clk_hw *clk_hw;
};

struct clk_lookup_alloc {
	struct clk_lookup cl;
	char dev_id[20];
	char con_id[16];
};

struct devres_node {
	struct list_head entry;
	dr_release_t release;
	const char *name;
	size_t size;
};

struct devres {
	struct devres_node node;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	u8 data[0];
};

struct devres_group {
	struct devres_node node[2];
	void *id;
	int color;
};

struct action_devres {
	void *data;
	void (*action)(void *);
};

struct pages_devres {
	long unsigned int addr;
	unsigned int order;
};

struct trace_event_raw_thermal_pressure_update {
	struct trace_entry ent;
	long unsigned int thermal_pressure;
	int cpu;
	char __data[0];
};

struct trace_event_data_offsets_thermal_pressure_update {};

typedef void (*btf_trace_thermal_pressure_update)(void *, int, long unsigned int);

struct alias_prop {
	struct list_head link;
	const char *alias;
	struct device_node *np;
	int id;
	char stem[0];
};

enum perf_hw_id {
	PERF_COUNT_HW_CPU_CYCLES = 0,
	PERF_COUNT_HW_INSTRUCTIONS = 1,
	PERF_COUNT_HW_CACHE_REFERENCES = 2,
	PERF_COUNT_HW_CACHE_MISSES = 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4,
	PERF_COUNT_HW_BRANCH_MISSES = 5,
	PERF_COUNT_HW_BUS_CYCLES = 6,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 8,
	PERF_COUNT_HW_REF_CPU_CYCLES = 9,
	PERF_COUNT_HW_MAX = 10,
};

enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D = 0,
	PERF_COUNT_HW_CACHE_L1I = 1,
	PERF_COUNT_HW_CACHE_LL = 2,
	PERF_COUNT_HW_CACHE_DTLB = 3,
	PERF_COUNT_HW_CACHE_ITLB = 4,
	PERF_COUNT_HW_CACHE_BPU = 5,
	PERF_COUNT_HW_CACHE_NODE = 6,
	PERF_COUNT_HW_CACHE_MAX = 7,
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ = 0,
	PERF_COUNT_HW_CACHE_OP_WRITE = 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH = 2,
	PERF_COUNT_HW_CACHE_OP_MAX = 3,
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS = 1,
	PERF_COUNT_HW_CACHE_RESULT_MAX = 2,
};

enum armpmu_attr_groups {
	ARMPMU_ATTR_GROUP_COMMON = 0,
	ARMPMU_ATTR_GROUP_EVENTS = 1,
	ARMPMU_ATTR_GROUP_FORMATS = 2,
	ARMPMU_ATTR_GROUP_CAPS = 3,
	ARMPMU_NR_ATTR_GROUPS = 4,
};

enum kvm_arch_timers {
	TIMER_PTIMER = 0,
	TIMER_VTIMER = 1,
	NR_KVM_EL0_TIMERS = 2,
	TIMER_HVTIMER = 2,
	TIMER_HPTIMER = 3,
	NR_KVM_TIMERS = 4,
};

enum kvm_bus {
	KVM_MMIO_BUS = 0,
	KVM_PIO_BUS = 1,
	KVM_VIRTIO_CCW_NOTIFY_BUS = 2,
	KVM_FAST_MMIO_BUS = 3,
	KVM_NR_BUSES = 4,
};

struct armv8pmu_probe_info {
	struct arm_pmu *pmu;
	bool present;
};

typedef struct {
	u32 red_mask;
	u32 green_mask;
	u32 blue_mask;
	u32 reserved_mask;
} efi_pixel_bitmask_t;

typedef struct {
	u32 version;
	u32 horizontal_resolution;
	u32 vertical_resolution;
	int pixel_format;
	efi_pixel_bitmask_t pixel_information;
	u32 pixels_per_scan_line;
} efi_graphics_output_mode_info_t;

union efi_graphics_output_protocol_mode {
	struct {
		u32 max_mode;
		u32 mode;
		efi_graphics_output_mode_info_t *info;
		long unsigned int size_of_info;
		efi_physical_addr_t frame_buffer_base;
		long unsigned int frame_buffer_size;
	};
	struct {
		u32 max_mode;
		u32 mode;
		u32 info;
		u32 size_of_info;
		u64 frame_buffer_base;
		u32 frame_buffer_size;
	} mixed_mode;
};

typedef union efi_graphics_output_protocol_mode efi_graphics_output_protocol_mode_t;

union efi_graphics_output_protocol;

typedef union efi_graphics_output_protocol efi_graphics_output_protocol_t;

union efi_graphics_output_protocol {
	struct {
		efi_status_t (*query_mode)(efi_graphics_output_protocol_t *, u32, long unsigned int *, efi_graphics_output_mode_info_t **);
		efi_status_t (*set_mode)(efi_graphics_output_protocol_t *, u32);
		void *blt;
		efi_graphics_output_protocol_mode_t *mode;
	};
	struct {
		u32 query_mode;
		u32 set_mode;
		u32 blt;
		u32 mode;
	} mixed_mode;
};

enum efi_cmdline_option {
	EFI_CMDLINE_NONE = 0,
	EFI_CMDLINE_MODE_NUM = 1,
	EFI_CMDLINE_RES = 2,
	EFI_CMDLINE_AUTO = 3,
	EFI_CMDLINE_LIST = 4,
};

struct linux_efi_random_seed {
	u32 size;
	u8 bits[0];
};

union efi_rng_protocol;

typedef union efi_rng_protocol efi_rng_protocol_t;

union efi_rng_protocol {
	struct {
		efi_status_t (*get_info)(efi_rng_protocol_t *, long unsigned int *, efi_guid_t *);
		efi_status_t (*get_rng)(efi_rng_protocol_t *, efi_guid_t *, long unsigned int, u8 *);
	};
	struct {
		u32 get_info;
		u32 get_rng;
	} mixed_mode;
};

typedef struct {
	efi_guid_t guid;
	u32 table;
} efi_config_table_32_t;

typedef union {
	struct {
		efi_guid_t guid;
		void *table;
	};
	efi_config_table_32_t mixed_mode;
} efi_config_table_t;

struct efi_vendor_dev_path {
	struct efi_generic_dev_path header;
	efi_guid_t vendorguid;
	u8 vendordata[0];
};

union efi_memory_attribute_protocol;

typedef union efi_memory_attribute_protocol efi_memory_attribute_protocol_t;

union efi_memory_attribute_protocol {
	struct {
		efi_status_t (*get_memory_attributes)(efi_memory_attribute_protocol_t *, efi_physical_addr_t, u64, u64 *);
		efi_status_t (*set_memory_attributes)(efi_memory_attribute_protocol_t *, efi_physical_addr_t, u64, u64);
		efi_status_t (*clear_memory_attributes)(efi_memory_attribute_protocol_t *, efi_physical_addr_t, u64, u64);
	};
	struct {
		u32 get_memory_attributes;
		u32 set_memory_attributes;
		u32 clear_memory_attributes;
	} mixed_mode;
};

struct efi_tcg2_tagged_event {
	u32 tagged_event_id;
	u32 tagged_event_data_size;
};

typedef struct efi_tcg2_tagged_event efi_tcg2_tagged_event_t;

typedef struct {
	u32 attributes;
	u16 file_path_list_length;
	u8 variable_data[0];
} __attribute__((packed)) efi_load_option_t;

typedef struct {
	u32 attributes;
	u16 file_path_list_length;
	const efi_char16_t *description;
	const efi_device_path_protocol_t *file_path_list;
	u32 optional_data_size;
	const void *optional_data;
} efi_load_option_unpacked_t;

enum efistub_event {
	EFISTUB_EVT_INITRD = 0,
	EFISTUB_EVT_LOAD_OPTIONS = 1,
	EFISTUB_EVT_COUNT = 2,
};

struct efi_measured_event {
	efi_tcg2_event_t event_data;
	efi_tcg2_tagged_event_t tagged_event;
	u8 tagged_event_data[0];
} __attribute__((packed));

struct cpu_fp_state {
	struct user_fpsimd_state *st;
	void *sve_state;
	void *sme_state;
	u64 *svcr;
	unsigned int sve_vl;
	unsigned int sme_vl;
	enum fp_type *fp_type;
	enum fp_type to_save;
};

struct vl_config {
	int __default_vl;
};

struct return_address_data {
	unsigned int level;
	void *addr;
};

struct secondary_data {
	struct task_struct *task;
	long int status;
};

enum ipi_msg_type {
	IPI_RESCHEDULE = 0,
	IPI_CALL_FUNC = 1,
	IPI_CPU_STOP = 2,
	IPI_CPU_CRASH_STOP = 3,
	IPI_TIMER = 4,
	IPI_IRQ_WORK = 5,
	IPI_WAKEUP = 6,
	NR_IPI = 7,
};

struct page_change_data {
	pgprot_t set_mask;
	pgprot_t clear_mask;
};

struct io_uring_sqe;

struct io_uring_cmd {
	struct file *file;
	const struct io_uring_sqe *sqe;
	union {
		void (*task_work_cb)(struct io_uring_cmd *, unsigned int);
		void *cookie;
	};
	u32 cmd_op;
	u32 flags;
	u8 pdu[32];
};

struct io_uring_sqe {
	__u8 opcode;
	__u8 flags;
	__u16 ioprio;
	__s32 fd;
	union {
		__u64 off;
		__u64 addr2;
		struct {
			__u32 cmd_op;
			__u32 __pad1;
		};
	};
	union {
		__u64 addr;
		__u64 splice_off_in;
	};
	__u32 len;
	union {
		__kernel_rwf_t rw_flags;
		__u32 fsync_flags;
		__u16 poll_events;
		__u32 poll32_events;
		__u32 sync_range_flags;
		__u32 msg_flags;
		__u32 timeout_flags;
		__u32 accept_flags;
		__u32 cancel_flags;
		__u32 open_flags;
		__u32 statx_flags;
		__u32 fadvise_advice;
		__u32 splice_flags;
		__u32 rename_flags;
		__u32 unlink_flags;
		__u32 hardlink_flags;
		__u32 xattr_flags;
		__u32 msg_ring_flags;
		__u32 uring_cmd_flags;
	};
	__u64 user_data;
	union {
		__u16 buf_index;
		__u16 buf_group;
	};
	__u16 personality;
	union {
		__s32 splice_fd_in;
		__u32 file_index;
		struct {
			__u16 addr_len;
			__u16 __pad3[1];
		};
	};
	union {
		struct {
			__u64 addr3;
			__u64 __pad2[1];
		};
		__u8 cmd[0];
	};
};

struct waitid_info {
	pid_t pid;
	uid_t uid;
	int status;
	int cause;
};

struct wait_opts {
	enum pid_type wo_type;
	int wo_flags;
	struct pid *wo_pid;
	struct waitid_info *wo_info;
	int wo_stat;
	struct rusage *wo_rusage;
	wait_queue_entry_t child_wait;
	int notask_error;
};

struct async_domain {
	struct list_head pending;
	unsigned int registered: 1;
};

struct async_entry {
	struct list_head domain_list;
	struct list_head global_list;
	struct work_struct work;
	async_cookie_t cookie;
	async_func_t func;
	void *data;
	struct async_domain *domain;
};

enum uclamp_id {
	UCLAMP_MIN = 0,
	UCLAMP_MAX = 1,
	UCLAMP_CNT = 2,
};

enum cpu_idle_type {
	CPU_IDLE = 0,
	CPU_NOT_IDLE = 1,
	CPU_NEWLY_IDLE = 2,
	CPU_MAX_IDLE_TYPES = 3,
};

struct cpuidle_state_usage {
	long long unsigned int disable;
	long long unsigned int usage;
	u64 time_ns;
	long long unsigned int above;
	long long unsigned int below;
	long long unsigned int rejected;
};

struct cpuidle_device;

struct cpuidle_driver;

struct cpuidle_state {
	char name[16];
	char desc[32];
	s64 exit_latency_ns;
	s64 target_residency_ns;
	unsigned int flags;
	unsigned int exit_latency;
	int power_usage;
	unsigned int target_residency;
	int (*enter)(struct cpuidle_device *, struct cpuidle_driver *, int);
	int (*enter_dead)(struct cpuidle_device *, int);
	int (*enter_s2idle)(struct cpuidle_device *, struct cpuidle_driver *, int);
};

struct cpuidle_state_kobj;

struct cpuidle_driver_kobj;

struct cpuidle_device_kobj;

struct cpuidle_device {
	unsigned int registered: 1;
	unsigned int enabled: 1;
	unsigned int poll_time_limit: 1;
	unsigned int cpu;
	ktime_t next_hrtimer;
	int last_state_idx;
	u64 last_residency_ns;
	u64 poll_limit_ns;
	u64 forced_idle_latency_limit_ns;
	struct cpuidle_state_usage states_usage[10];
	struct cpuidle_state_kobj *kobjs[10];
	struct cpuidle_driver_kobj *kobj_driver;
	struct cpuidle_device_kobj *kobj_dev;
	struct list_head device_list;
};

struct cpuidle_driver {
	const char *name;
	struct module *owner;
	unsigned int bctimer: 1;
	struct cpuidle_state states[10];
	int state_count;
	int safe_state_index;
	struct cpumask *cpumask;
	const char *governor;
};

struct cfs_bandwidth {};

struct energy_env {
	long unsigned int task_busy_time;
	long unsigned int pd_busy_time;
	long unsigned int cpu_cap;
	long unsigned int pd_cap;
};

enum fbq_type {
	regular = 0,
	remote = 1,
	all = 2,
};

enum group_type {
	group_has_spare = 0,
	group_fully_busy = 1,
	group_misfit_task = 2,
	group_asym_packing = 3,
	group_imbalanced = 4,
	group_overloaded = 5,
};

enum migration_type {
	migrate_load = 0,
	migrate_util = 1,
	migrate_task = 2,
	migrate_misfit = 3,
};

struct lb_env {
	struct sched_domain *sd;
	struct rq *src_rq;
	int src_cpu;
	int dst_cpu;
	struct rq *dst_rq;
	struct cpumask *dst_grpmask;
	int new_dst_cpu;
	enum cpu_idle_type idle;
	long int imbalance;
	struct cpumask *cpus;
	unsigned int flags;
	unsigned int loop;
	unsigned int loop_break;
	unsigned int loop_max;
	enum fbq_type fbq_type;
	enum migration_type migration_type;
	struct list_head tasks;
};

struct sg_lb_stats {
	long unsigned int avg_load;
	long unsigned int group_load;
	long unsigned int group_capacity;
	long unsigned int group_util;
	long unsigned int group_runnable;
	unsigned int sum_nr_running;
	unsigned int sum_h_nr_running;
	unsigned int idle_cpus;
	unsigned int group_weight;
	enum group_type group_type;
	unsigned int group_asym_packing;
	long unsigned int group_misfit_task_load;
};

struct sd_lb_stats {
	struct sched_group *busiest;
	struct sched_group *local;
	long unsigned int total_load;
	long unsigned int total_capacity;
	long unsigned int avg_load;
	unsigned int prefer_sibling;
	struct sg_lb_stats busiest_stat;
	struct sg_lb_stats local_stat;
};

struct task_group;

enum pci_p2pdma_map_type {
	PCI_P2PDMA_MAP_UNKNOWN = 0,
	PCI_P2PDMA_MAP_NOT_SUPPORTED = 1,
	PCI_P2PDMA_MAP_BUS_ADDR = 2,
	PCI_P2PDMA_MAP_THRU_HOST_BRIDGE = 3,
};

struct pci_p2pdma_map_state {
	struct dev_pagemap *pgmap;
	int map;
	u64 bus_off;
};

struct latch_tree_ops {
	bool (*less)(struct latch_tree_node *, struct latch_tree_node *);
	int (*comp)(void *, struct latch_tree_node *);
};

struct ktime_timestamps {
	u64 mono;
	u64 boot;
	u64 real;
};

struct system_time_snapshot {
	u64 cycles;
	ktime_t real;
	ktime_t raw;
	enum clocksource_ids cs_id;
	unsigned int clock_was_set_seq;
	u8 cs_was_changed_seq;
};

struct system_device_crosststamp {
	ktime_t device;
	ktime_t sys_realtime;
	ktime_t sys_monoraw;
};

struct system_counterval_t {
	u64 cycles;
	struct clocksource *cs;
};

struct tk_read_base {
	struct clocksource *clock;
	u64 mask;
	u64 cycle_last;
	u32 mult;
	u32 shift;
	u64 xtime_nsec;
	ktime_t base;
	u64 base_real;
};

struct timekeeper {
	struct tk_read_base tkr_mono;
	struct tk_read_base tkr_raw;
	u64 xtime_sec;
	long unsigned int ktime_sec;
	struct timespec64 wall_to_monotonic;
	ktime_t offs_real;
	ktime_t offs_boot;
	ktime_t offs_tai;
	s32 tai_offset;
	unsigned int clock_was_set_seq;
	u8 cs_was_changed_seq;
	ktime_t next_leap_ktime;
	u64 raw_sec;
	struct timespec64 monotonic_to_boot;
	u64 cycle_interval;
	u64 xtime_interval;
	s64 xtime_remainder;
	u64 raw_interval;
	u64 ntp_tick;
	s64 ntp_error;
	u32 ntp_error_shift;
	u32 ntp_err_mult;
	u32 skip_second_overflow;
};

struct audit_ntp_data {};

enum timekeeping_adv_mode {
	TK_ADV_TICK = 0,
	TK_ADV_FREQ = 1,
};

struct tk_fast {
	seqcount_latch_t seq;
	struct tk_read_base base[2];
};

struct tp_module {
	struct list_head list;
	struct module *mod;
};

enum tp_func_state {
	TP_FUNC_0 = 0,
	TP_FUNC_1 = 1,
	TP_FUNC_2 = 2,
	TP_FUNC_N = 3,
};

enum tp_transition_sync {
	TP_TRANSITION_SYNC_1_0_1 = 0,
	TP_TRANSITION_SYNC_N_2_1 = 1,
	_NR_TP_TRANSITION_SYNC = 2,
};

struct tp_transition_snapshot {
	long unsigned int rcu;
	long unsigned int srcu;
	bool ongoing;
};

struct tp_probes {
	struct callback_head rcu;
	struct tracepoint_func probes[0];
};

enum {
	TRACE_NOP_OPT_ACCEPT = 1,
	TRACE_NOP_OPT_REFUSE = 2,
};

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP = 1,
	XDP_PASS = 2,
	XDP_TX = 3,
	XDP_REDIRECT = 4,
};

struct bpf_empty_prog_array {
	struct bpf_prog_array hdr;
	struct bpf_prog *null_prog;
};

enum xdp_mem_type {
	MEM_TYPE_PAGE_SHARED = 0,
	MEM_TYPE_PAGE_ORDER0 = 1,
	MEM_TYPE_PAGE_POOL = 2,
	MEM_TYPE_XSK_BUFF_POOL = 3,
	MEM_TYPE_MAX = 4,
};

struct xdp_cpumap_stats {
	unsigned int redirect;
	unsigned int pass;
	unsigned int drop;
};

struct bpf_prog_pack {
	struct list_head list;
	void *ptr;
	long unsigned int bitmap[0];
};

struct bpf_prog_dummy {
	struct bpf_prog prog;
};

typedef u64 (*btf_bpf_user_rnd_u32)();

typedef u64 (*btf_bpf_get_raw_cpu_id)();

struct _bpf_dtab_netdev {
	struct net_device *dev;
};

struct xdp_mem_allocator {
	struct xdp_mem_info mem;
	union {
		void *allocator;
		struct page_pool *page_pool;
	};
	struct rhash_head node;
	struct callback_head rcu;
};

struct trace_event_raw_xdp_exception {
	struct trace_entry ent;
	int prog_id;
	u32 act;
	int ifindex;
	char __data[0];
};

struct trace_event_raw_xdp_bulk_tx {
	struct trace_entry ent;
	int ifindex;
	u32 act;
	int drops;
	int sent;
	int err;
	char __data[0];
};

struct trace_event_raw_xdp_redirect_template {
	struct trace_entry ent;
	int prog_id;
	u32 act;
	int ifindex;
	int err;
	int to_ifindex;
	u32 map_id;
	int map_index;
	char __data[0];
};

struct trace_event_raw_xdp_cpumap_kthread {
	struct trace_entry ent;
	int map_id;
	u32 act;
	int cpu;
	unsigned int drops;
	unsigned int processed;
	int sched;
	unsigned int xdp_pass;
	unsigned int xdp_drop;
	unsigned int xdp_redirect;
	char __data[0];
};

struct trace_event_raw_xdp_cpumap_enqueue {
	struct trace_entry ent;
	int map_id;
	u32 act;
	int cpu;
	unsigned int drops;
	unsigned int processed;
	int to_cpu;
	char __data[0];
};

struct trace_event_raw_xdp_devmap_xmit {
	struct trace_entry ent;
	int from_ifindex;
	u32 act;
	int to_ifindex;
	int drops;
	int sent;
	int err;
	char __data[0];
};

struct trace_event_raw_mem_disconnect {
	struct trace_entry ent;
	const struct xdp_mem_allocator *xa;
	u32 mem_id;
	u32 mem_type;
	const void *allocator;
	char __data[0];
};

struct trace_event_raw_mem_connect {
	struct trace_entry ent;
	const struct xdp_mem_allocator *xa;
	u32 mem_id;
	u32 mem_type;
	const void *allocator;
	const struct xdp_rxq_info *rxq;
	int ifindex;
	char __data[0];
};

struct trace_event_raw_mem_return_failed {
	struct trace_entry ent;
	const struct page *page;
	u32 mem_id;
	u32 mem_type;
	char __data[0];
};

struct trace_event_data_offsets_xdp_exception {};

struct trace_event_data_offsets_xdp_bulk_tx {};

struct trace_event_data_offsets_xdp_redirect_template {};

struct trace_event_data_offsets_xdp_cpumap_kthread {};

struct trace_event_data_offsets_xdp_cpumap_enqueue {};

struct trace_event_data_offsets_xdp_devmap_xmit {};

struct trace_event_data_offsets_mem_disconnect {};

struct trace_event_data_offsets_mem_connect {};

struct trace_event_data_offsets_mem_return_failed {};

typedef void (*btf_trace_xdp_exception)(void *, const struct net_device *, const struct bpf_prog *, u32);

typedef void (*btf_trace_xdp_bulk_tx)(void *, const struct net_device *, int, int, int);

typedef void (*btf_trace_xdp_redirect)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_err)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_map)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_map_err)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_cpumap_kthread)(void *, int, unsigned int, unsigned int, int, struct xdp_cpumap_stats *);

typedef void (*btf_trace_xdp_cpumap_enqueue)(void *, int, unsigned int, unsigned int, int);

typedef void (*btf_trace_xdp_devmap_xmit)(void *, const struct net_device *, const struct net_device *, int, int, int);

typedef void (*btf_trace_mem_disconnect)(void *, const struct xdp_mem_allocator *);

typedef void (*btf_trace_mem_connect)(void *, const struct xdp_mem_allocator *, const struct xdp_rxq_info *);

typedef void (*btf_trace_mem_return_failed)(void *, const struct xdp_mem_info *, const struct page *);

enum bpf_stack_build_id_status {
	BPF_STACK_BUILD_ID_EMPTY = 0,
	BPF_STACK_BUILD_ID_VALID = 1,
	BPF_STACK_BUILD_ID_IP = 2,
};

struct bpf_stack_build_id {
	__s32 status;
	unsigned char build_id[20];
	union {
		__u64 offset;
		__u64 ip;
	};
};

enum {
	BPF_F_SKIP_FIELD_MASK = 255,
	BPF_F_USER_STACK = 256,
	BPF_F_FAST_STACK_CMP = 512,
	BPF_F_REUSE_STACKID = 1024,
	BPF_F_USER_BUILD_ID = 2048,
};

enum perf_callchain_context {
	PERF_CONTEXT_HV = 18446744073709551584ULL,
	PERF_CONTEXT_KERNEL = 18446744073709551488ULL,
	PERF_CONTEXT_USER = 18446744073709551104ULL,
	PERF_CONTEXT_GUEST = 18446744073709549568ULL,
	PERF_CONTEXT_GUEST_KERNEL = 18446744073709549440ULL,
	PERF_CONTEXT_GUEST_USER = 18446744073709549056ULL,
	PERF_CONTEXT_MAX = 18446744073709547521ULL,
};

struct stack_map_bucket {
	struct pcpu_freelist_node fnode;
	u32 hash;
	u32 nr;
	u64 data[0];
};

struct bpf_stack_map {
	struct bpf_map map;
	void *elems;
	struct pcpu_freelist freelist;
	u32 n_buckets;
	struct stack_map_bucket *buckets[0];
	long: 64;
	long: 64;
	long: 64;
};

typedef u64 (*btf_bpf_get_stackid)(struct pt_regs *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_get_stackid_pe)(struct bpf_perf_event_data_kern *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_get_stack)(struct pt_regs *, void *, u32, u64);

typedef u64 (*btf_bpf_get_task_stack)(struct task_struct *, void *, u32, u64);

typedef u64 (*btf_bpf_get_stack_pe)(struct bpf_perf_event_data_kern *, void *, u32, u64);

struct pcpu_group_info {
	int nr_units;
	long unsigned int base_offset;
	unsigned int *cpu_map;
};

struct pcpu_alloc_info {
	size_t static_size;
	size_t reserved_size;
	size_t dyn_size;
	size_t unit_size;
	size_t atom_size;
	size_t alloc_size;
	size_t __ai_size;
	int nr_groups;
	struct pcpu_group_info groups[0];
};

typedef int pcpu_fc_cpu_to_node_fn_t(int);

typedef int pcpu_fc_cpu_distance_fn_t(unsigned int, unsigned int);

struct trace_event_raw_percpu_alloc_percpu {
	struct trace_entry ent;
	long unsigned int call_site;
	bool reserved;
	bool is_atomic;
	size_t size;
	size_t align;
	void *base_addr;
	int off;
	void *ptr;
	size_t bytes_alloc;
	long unsigned int gfp_flags;
	char __data[0];
};

struct trace_event_raw_percpu_free_percpu {
	struct trace_entry ent;
	void *base_addr;
	int off;
	void *ptr;
	char __data[0];
};

struct trace_event_raw_percpu_alloc_percpu_fail {
	struct trace_entry ent;
	bool reserved;
	bool is_atomic;
	size_t size;
	size_t align;
	char __data[0];
};

struct trace_event_raw_percpu_create_chunk {
	struct trace_entry ent;
	void *base_addr;
	char __data[0];
};

struct trace_event_raw_percpu_destroy_chunk {
	struct trace_entry ent;
	void *base_addr;
	char __data[0];
};

struct trace_event_data_offsets_percpu_alloc_percpu {};

struct trace_event_data_offsets_percpu_free_percpu {};

struct trace_event_data_offsets_percpu_alloc_percpu_fail {};

struct trace_event_data_offsets_percpu_create_chunk {};

struct trace_event_data_offsets_percpu_destroy_chunk {};

typedef void (*btf_trace_percpu_alloc_percpu)(void *, long unsigned int, bool, bool, size_t, size_t, void *, int, void *, size_t, gfp_t);

typedef void (*btf_trace_percpu_free_percpu)(void *, void *, int, void *);

typedef void (*btf_trace_percpu_alloc_percpu_fail)(void *, bool, bool, size_t, size_t);

typedef void (*btf_trace_percpu_create_chunk)(void *, void *);

typedef void (*btf_trace_percpu_destroy_chunk)(void *, void *);

struct pcpu_block_md {
	int scan_hint;
	int scan_hint_start;
	int contig_hint;
	int contig_hint_start;
	int left_free;
	int right_free;
	int first_free;
	int nr_bits;
};

struct pcpu_chunk {
	struct list_head list;
	int free_bytes;
	struct pcpu_block_md chunk_md;
	void *base_addr;
	long unsigned int *alloc_map;
	long unsigned int *bound_map;
	struct pcpu_block_md *md_blocks;
	void *data;
	bool immutable;
	bool isolated;
	int start_offset;
	int end_offset;
	int nr_pages;
	int nr_populated;
	int nr_empty_pop_pages;
	long unsigned int populated[0];
};

typedef u32 depot_stack_handle_t;

enum stat_item {
	ALLOC_FASTPATH = 0,
	ALLOC_SLOWPATH = 1,
	FREE_FASTPATH = 2,
	FREE_SLOWPATH = 3,
	FREE_FROZEN = 4,
	FREE_ADD_PARTIAL = 5,
	FREE_REMOVE_PARTIAL = 6,
	ALLOC_FROM_PARTIAL = 7,
	ALLOC_SLAB = 8,
	ALLOC_REFILL = 9,
	ALLOC_NODE_MISMATCH = 10,
	FREE_SLAB = 11,
	CPUSLAB_FLUSH = 12,
	DEACTIVATE_FULL = 13,
	DEACTIVATE_EMPTY = 14,
	DEACTIVATE_TO_HEAD = 15,
	DEACTIVATE_TO_TAIL = 16,
	DEACTIVATE_REMOTE_FREES = 17,
	DEACTIVATE_BYPASS = 18,
	ORDER_FALLBACK = 19,
	CMPXCHG_DOUBLE_CPU_FAIL = 20,
	CMPXCHG_DOUBLE_FAIL = 21,
	CPU_PARTIAL_ALLOC = 22,
	CPU_PARTIAL_FREE = 23,
	CPU_PARTIAL_NODE = 24,
	CPU_PARTIAL_DRAIN = 25,
	NR_SLUB_STAT_ITEMS = 26,
};

struct memory_notify {
	long unsigned int start_pfn;
	long unsigned int nr_pages;
	int status_change_nid_normal;
	int status_change_nid;
};

struct partial_context {
	struct slab **slab;
	gfp_t flags;
	unsigned int orig_size;
};

enum track_item {
	TRACK_ALLOC = 0,
	TRACK_FREE = 1,
};

struct slub_flush_work {
	struct work_struct work;
	struct kmem_cache *s;
	bool skip;
};

struct detached_freelist {
	struct slab *slab;
	void *tail;
	void *freelist;
	int cnt;
	struct kmem_cache *s;
};

enum slab_modes {
	M_NONE = 0,
	M_PARTIAL = 1,
	M_FREE = 2,
	M_FULL_NOLIST = 3,
};

struct saved {
	struct path link;
	struct delayed_call done;
	const char *name;
	unsigned int seq;
};

struct nameidata {
	struct path path;
	struct qstr last;
	struct path root;
	struct inode *inode;
	unsigned int flags;
	unsigned int state;
	unsigned int seq;
	unsigned int next_seq;
	unsigned int m_seq;
	unsigned int r_seq;
	int last_type;
	unsigned int depth;
	int total_link_count;
	struct saved *stack;
	struct saved internal[2];
	struct filename *name;
	struct nameidata *saved;
	unsigned int root_seq;
	int dfd;
	vfsuid_t dir_vfsuid;
	umode_t dir_mode;
};

struct renamedata {
	struct mnt_idmap *old_mnt_idmap;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct mnt_idmap *new_mnt_idmap;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct inode **delegated_inode;
	unsigned int flags;
};

enum {
	LAST_NORM = 0,
	LAST_ROOT = 1,
	LAST_DOT = 2,
	LAST_DOTDOT = 3,
};

enum {
	WALK_TRAILING = 1,
	WALK_MORE = 2,
	WALK_NOFOLLOW = 4,
};

struct prepend_buffer {
	char *buf;
	int len;
};

struct tracefs_dir_ops {
	int (*mkdir)(const char *);
	int (*rmdir)(const char *);
};

struct tracefs_mount_opts {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	unsigned int opts;
};

struct tracefs_fs_info {
	struct tracefs_mount_opts mount_opts;
};

struct once_work {
	struct work_struct work;
	struct static_key_true *key;
	struct module *module;
};

struct node_groups {
	unsigned int id;
	union {
		unsigned int ngroups;
		unsigned int ncpus;
	};
};

struct mbi_range {
	u32 spi_start;
	u32 nr_spis;
	long unsigned int *bm;
};

struct clk_notifier {
	struct clk *clk;
	struct srcu_notifier_head notifier_head;
	struct list_head node;
};

struct clk_notifier_data {
	struct clk *clk;
	long unsigned int old_rate;
	long unsigned int new_rate;
};

struct clk_parent_map;

struct clk_core {
	const char *name;
	const struct clk_ops *ops;
	struct clk_hw *hw;
	struct module *owner;
	struct device *dev;
	struct device_node *of_node;
	struct clk_core *parent;
	struct clk_parent_map *parents;
	u8 num_parents;
	u8 new_parent_index;
	long unsigned int rate;
	long unsigned int req_rate;
	long unsigned int new_rate;
	struct clk_core *new_parent;
	struct clk_core *new_child;
	long unsigned int flags;
	bool orphan;
	bool rpm_enabled;
	unsigned int enable_count;
	unsigned int prepare_count;
	unsigned int protect_count;
	long unsigned int min_rate;
	long unsigned int max_rate;
	long unsigned int accuracy;
	int phase;
	struct clk_duty duty;
	struct hlist_head children;
	struct hlist_node child_node;
	struct hlist_head clks;
	unsigned int notifier_count;
	struct dentry *dentry;
	struct hlist_node debug_node;
	struct kref ref;
};

struct clk_onecell_data {
	struct clk **clks;
	unsigned int clk_num;
};

struct clk_hw_onecell_data {
	unsigned int num;
	struct clk_hw *hws[0];
};

struct clk_parent_map {
	const struct clk_hw *hw;
	struct clk_core *core;
	const char *fw_name;
	const char *name;
	int index;
};

struct trace_event_raw_clk {
	struct trace_entry ent;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_clk_rate {
	struct trace_entry ent;
	u32 __data_loc_name;
	long unsigned int rate;
	char __data[0];
};

struct trace_event_raw_clk_rate_range {
	struct trace_entry ent;
	u32 __data_loc_name;
	long unsigned int min;
	long unsigned int max;
	char __data[0];
};

struct trace_event_raw_clk_parent {
	struct trace_entry ent;
	u32 __data_loc_name;
	u32 __data_loc_pname;
	char __data[0];
};

struct trace_event_raw_clk_phase {
	struct trace_entry ent;
	u32 __data_loc_name;
	int phase;
	char __data[0];
};

struct trace_event_raw_clk_duty_cycle {
	struct trace_entry ent;
	u32 __data_loc_name;
	unsigned int num;
	unsigned int den;
	char __data[0];
};

struct trace_event_raw_clk_rate_request {
	struct trace_entry ent;
	u32 __data_loc_name;
	u32 __data_loc_pname;
	long unsigned int min;
	long unsigned int max;
	long unsigned int prate;
	char __data[0];
};

struct trace_event_data_offsets_clk {
	u32 name;
};

struct trace_event_data_offsets_clk_rate {
	u32 name;
};

struct trace_event_data_offsets_clk_rate_range {
	u32 name;
};

struct trace_event_data_offsets_clk_parent {
	u32 name;
	u32 pname;
};

struct trace_event_data_offsets_clk_phase {
	u32 name;
};

struct trace_event_data_offsets_clk_duty_cycle {
	u32 name;
};

struct trace_event_data_offsets_clk_rate_request {
	u32 name;
	u32 pname;
};

typedef void (*btf_trace_clk_enable)(void *, struct clk_core *);

typedef void (*btf_trace_clk_enable_complete)(void *, struct clk_core *);

typedef void (*btf_trace_clk_disable)(void *, struct clk_core *);

typedef void (*btf_trace_clk_disable_complete)(void *, struct clk_core *);

typedef void (*btf_trace_clk_prepare)(void *, struct clk_core *);

typedef void (*btf_trace_clk_prepare_complete)(void *, struct clk_core *);

typedef void (*btf_trace_clk_unprepare)(void *, struct clk_core *);

typedef void (*btf_trace_clk_unprepare_complete)(void *, struct clk_core *);

typedef void (*btf_trace_clk_set_rate)(void *, struct clk_core *, long unsigned int);

typedef void (*btf_trace_clk_set_rate_complete)(void *, struct clk_core *, long unsigned int);

typedef void (*btf_trace_clk_set_min_rate)(void *, struct clk_core *, long unsigned int);

typedef void (*btf_trace_clk_set_max_rate)(void *, struct clk_core *, long unsigned int);

typedef void (*btf_trace_clk_set_rate_range)(void *, struct clk_core *, long unsigned int, long unsigned int);

typedef void (*btf_trace_clk_set_parent)(void *, struct clk_core *, struct clk_core *);

typedef void (*btf_trace_clk_set_parent_complete)(void *, struct clk_core *, struct clk_core *);

typedef void (*btf_trace_clk_set_phase)(void *, struct clk_core *, int);

typedef void (*btf_trace_clk_set_phase_complete)(void *, struct clk_core *, int);

typedef void (*btf_trace_clk_set_duty_cycle)(void *, struct clk_core *, struct clk_duty *);

typedef void (*btf_trace_clk_set_duty_cycle_complete)(void *, struct clk_core *, struct clk_duty *);

typedef void (*btf_trace_clk_rate_request_start)(void *, struct clk_rate_request *);

typedef void (*btf_trace_clk_rate_request_done)(void *, struct clk_rate_request *);

struct clk_notifier_devres {
	struct clk *clk;
	struct notifier_block *nb;
};

struct of_clk_provider {
	struct list_head link;
	struct device_node *node;
	struct clk * (*get)(struct of_phandle_args *, void *);
	struct clk_hw * (*get_hw)(struct of_phandle_args *, void *);
	void *data;
};

struct clock_provider {
	void (*clk_init_cb)(struct device_node *);
	struct device_node *np;
	struct list_head node;
};

struct software_node_ref_args {
	const struct software_node *node;
	unsigned int nargs;
	u64 args[8];
};

struct swnode {
	struct kobject kobj;
	struct fwnode_handle fwnode;
	const struct software_node *node;
	int id;
	struct ida child_ids;
	struct list_head entry;
	struct list_head children;
	struct swnode *parent;
	unsigned int allocated: 1;
	unsigned int managed: 1;
};

typedef struct {
	efi_guid_t guid;
	long unsigned int *ptr;
	const char name[16];
} efi_config_table_type_t;

struct arm_smccc_quirk {
	int id;
	union {
		long unsigned int a6;
	} state;
};

struct psci_0_1_function_ids {
	u32 cpu_suspend;
	u32 cpu_on;
	u32 cpu_off;
	u32 migrate;
};

typedef int suspend_state_t;

struct platform_suspend_ops {
	int (*valid)(suspend_state_t);
	int (*begin)(suspend_state_t);
	int (*prepare)();
	int (*prepare_late)();
	int (*enter)(suspend_state_t);
	void (*wake)();
	void (*finish)();
	bool (*suspend_again)();
	void (*end)();
	void (*recover)();
};

typedef long unsigned int psci_fn(long unsigned int, long unsigned int, long unsigned int, long unsigned int);

typedef int (*psci_initcall_t)(const struct device_node *);

struct of_bus___2;

struct of_pci_range_parser {
	struct device_node *node;
	struct of_bus___2 *bus;
	const __be32 *range;
	const __be32 *end;
	int na;
	int ns;
	int pna;
	bool dma;
};

struct of_bus___2 {
	const char *name;
	const char *addresses;
	int (*match)(struct device_node *);
	void (*count_cells)(struct device_node *, int *, int *);
	u64 (*map)(__be32 *, const __be32 *, int, int, int);
	int (*translate)(__be32 *, u64, int);
	bool has_flags;
	unsigned int (*get_flags)(const __be32 *);
};

struct of_pci_range {
	union {
		u64 pci_addr;
		u64 bus_addr;
	};
	u64 cpu_addr;
	u64 size;
	u32 flags;
};

struct uevent_sock {
	struct list_head list;
	struct sock *sk;
};

struct ftr_set_desc {
	char name[20];
	struct arm64_ftr_override *override;
	struct {
		char name[10];
		u8 shift;
		u8 width;
		bool (*filter)(u64);
	} fields[0];
};

struct aarch64_insn_patch {
	void **text_addrs;
	u32 *new_insns;
	int insn_cnt;
	atomic_t cpu_count;
};

enum hw_breakpoint_ops {
	HW_BREAKPOINT_INSTALL = 0,
	HW_BREAKPOINT_UNINSTALL = 1,
	HW_BREAKPOINT_RESTORE = 2,
};

struct multiprocess_signals {
	sigset_t signal;
	struct hlist_node node;
};

enum {
	TRACE_SIGNAL_DELIVERED = 0,
	TRACE_SIGNAL_IGNORED = 1,
	TRACE_SIGNAL_ALREADY_PENDING = 2,
	TRACE_SIGNAL_OVERFLOW_FAIL = 3,
	TRACE_SIGNAL_LOSE_INFO = 4,
};

struct trace_event_raw_signal_generate {
	struct trace_entry ent;
	int sig;
	int errno;
	int code;
	char comm[16];
	pid_t pid;
	int group;
	int result;
	char __data[0];
};

struct trace_event_raw_signal_deliver {
	struct trace_entry ent;
	int sig;
	int errno;
	int code;
	long unsigned int sa_handler;
	long unsigned int sa_flags;
	char __data[0];
};

struct trace_event_data_offsets_signal_generate {};

struct trace_event_data_offsets_signal_deliver {};

typedef void (*btf_trace_signal_generate)(void *, int, struct kernel_siginfo *, struct task_struct *, int, int);

typedef void (*btf_trace_signal_deliver)(void *, int, struct kernel_siginfo *, struct k_sigaction *);

enum sig_handler {
	HANDLER_CURRENT = 0,
	HANDLER_SIG_DFL = 1,
	HANDLER_EXIT = 2,
};

struct irqchip_fwid {
	struct fwnode_handle fwnode;
	unsigned int type;
	char *name;
	phys_addr_t *pa;
};

enum cc_attr {
	CC_ATTR_MEM_ENCRYPT = 0,
	CC_ATTR_HOST_MEM_ENCRYPT = 1,
	CC_ATTR_GUEST_MEM_ENCRYPT = 2,
	CC_ATTR_GUEST_STATE_ENCRYPT = 3,
	CC_ATTR_GUEST_UNROLL_STRING_IO = 4,
	CC_ATTR_GUEST_SEV_SNP = 5,
	CC_ATTR_HOTPLUG_DISABLED = 6,
};

struct io_tlb_area {
	long unsigned int used;
	unsigned int index;
	spinlock_t lock;
};

struct io_tlb_slot {
	phys_addr_t orig_addr;
	size_t alloc_size;
	unsigned int list;
};

struct trace_event_raw_swiotlb_bounced {
	struct trace_entry ent;
	u32 __data_loc_dev_name;
	u64 dma_mask;
	dma_addr_t dev_addr;
	size_t size;
	bool force;
	char __data[0];
};

struct trace_event_data_offsets_swiotlb_bounced {
	u32 dev_name;
};

typedef void (*btf_trace_swiotlb_bounced)(void *, struct device *, dma_addr_t, size_t);

enum audit_ntp_type {
	AUDIT_NTP_OFFSET = 0,
	AUDIT_NTP_FREQ = 1,
	AUDIT_NTP_STATUS = 2,
	AUDIT_NTP_TAI = 3,
	AUDIT_NTP_TICK = 4,
	AUDIT_NTP_ADJUST = 5,
	AUDIT_NTP_NVALS = 6,
};

typedef s64 int64_t;

struct ce_unbind {
	struct clock_event_device *ce;
	int res;
};

struct ftrace_func_entry {
	struct hlist_node hlist;
	long unsigned int ip;
	long unsigned int direct;
};

enum ftrace_bug_type {
	FTRACE_BUG_UNKNOWN = 0,
	FTRACE_BUG_INIT = 1,
	FTRACE_BUG_NOP = 2,
	FTRACE_BUG_CALL = 3,
	FTRACE_BUG_UPDATE = 4,
};

enum {
	FTRACE_FL_ENABLED = 2147483648,
	FTRACE_FL_REGS = 1073741824,
	FTRACE_FL_REGS_EN = 536870912,
	FTRACE_FL_TRAMP = 268435456,
	FTRACE_FL_TRAMP_EN = 134217728,
	FTRACE_FL_IPMODIFY = 67108864,
	FTRACE_FL_DISABLED = 33554432,
	FTRACE_FL_DIRECT = 16777216,
	FTRACE_FL_DIRECT_EN = 8388608,
	FTRACE_FL_CALL_OPS = 4194304,
	FTRACE_FL_CALL_OPS_EN = 2097152,
	FTRACE_FL_TOUCHED = 1048576,
	FTRACE_FL_MODIFIED = 524288,
};

enum {
	FTRACE_UPDATE_IGNORE = 0,
	FTRACE_UPDATE_MAKE_CALL = 1,
	FTRACE_UPDATE_MODIFY_CALL = 2,
	FTRACE_UPDATE_MAKE_NOP = 3,
};

enum {
	FTRACE_ITER_FILTER = 1,
	FTRACE_ITER_NOTRACE = 2,
	FTRACE_ITER_PRINTALL = 4,
	FTRACE_ITER_DO_PROBES = 8,
	FTRACE_ITER_PROBE = 16,
	FTRACE_ITER_MOD = 32,
	FTRACE_ITER_ENABLED = 64,
	FTRACE_ITER_TOUCHED = 128,
};

struct ftrace_mod_load {
	struct list_head list;
	char *func;
	char *module;
	int enable;
};

enum {
	FTRACE_HASH_FL_MOD = 1,
};

enum {
	FTRACE_MODIFY_ENABLE_FL = 1,
	FTRACE_MODIFY_MAY_SLEEP_FL = 2,
};

struct ftrace_func_probe {
	struct ftrace_probe_ops *probe_ops;
	struct ftrace_ops ops;
	struct trace_array *tr;
	struct list_head list;
	void *data;
	int ref;
};

struct ftrace_page {
	struct ftrace_page *next;
	struct dyn_ftrace *records;
	int index;
	int order;
};

struct ftrace_rec_iter {
	struct ftrace_page *pg;
	int index;
};

struct ftrace_iterator {
	loff_t pos;
	loff_t func_pos;
	loff_t mod_pos;
	struct ftrace_page *pg;
	struct dyn_ftrace *func;
	struct ftrace_func_probe *probe;
	struct ftrace_func_entry *probe_entry;
	struct trace_parser parser;
	struct ftrace_hash *hash;
	struct ftrace_ops *ops;
	struct trace_array *tr;
	struct list_head *mod_list;
	int pidx;
	int idx;
	unsigned int flags;
};

struct ftrace_glob {
	char *search;
	unsigned int len;
	int type;
};

struct ftrace_func_map {
	struct ftrace_func_entry entry;
	void *data;
};

struct ftrace_func_mapper {
	struct ftrace_hash hash;
};

enum graph_filter_type {
	GRAPH_FILTER_NOTRACE = 0,
	GRAPH_FILTER_FUNCTION = 1,
};

struct ftrace_graph_data {
	struct ftrace_hash *hash;
	struct ftrace_func_entry *entry;
	int idx;
	enum graph_filter_type type;
	struct ftrace_hash *new_hash;
	const struct seq_operations *seq_ops;
	struct trace_parser parser;
};

struct ftrace_mod_func {
	struct list_head list;
	char *name;
	long unsigned int ip;
	unsigned int size;
};

struct ftrace_mod_map {
	struct callback_head rcu;
	struct list_head list;
	struct module *mod;
	long unsigned int start_addr;
	long unsigned int end_addr;
	struct list_head funcs;
	unsigned int num_funcs;
};

struct ftrace_init_func {
	struct list_head list;
	long unsigned int ip;
};

struct kallsyms_data {
	long unsigned int *addrs;
	const char **syms;
	size_t cnt;
	size_t found;
};

struct bpf_iter_seq_map_info {
	u32 map_id;
};

struct bpf_iter__bpf_map {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_map *map;
	};
};

struct trace_event_raw_oom_score_adj_update {
	struct trace_entry ent;
	pid_t pid;
	char comm[16];
	short int oom_score_adj;
	char __data[0];
};

struct trace_event_raw_reclaim_retry_zone {
	struct trace_entry ent;
	int node;
	int zone_idx;
	int order;
	long unsigned int reclaimable;
	long unsigned int available;
	long unsigned int min_wmark;
	int no_progress_loops;
	bool wmark_check;
	char __data[0];
};

struct trace_event_raw_mark_victim {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_raw_wake_reaper {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_raw_start_task_reaping {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_raw_finish_task_reaping {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_raw_skip_task_reaping {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_data_offsets_oom_score_adj_update {};

struct trace_event_data_offsets_reclaim_retry_zone {};

struct trace_event_data_offsets_mark_victim {};

struct trace_event_data_offsets_wake_reaper {};

struct trace_event_data_offsets_start_task_reaping {};

struct trace_event_data_offsets_finish_task_reaping {};

struct trace_event_data_offsets_skip_task_reaping {};

typedef void (*btf_trace_oom_score_adj_update)(void *, struct task_struct *);

typedef void (*btf_trace_reclaim_retry_zone)(void *, struct zoneref *, int, long unsigned int, long unsigned int, long unsigned int, int, bool);

typedef void (*btf_trace_mark_victim)(void *, int);

typedef void (*btf_trace_wake_reaper)(void *, int);

typedef void (*btf_trace_start_task_reaping)(void *, int);

typedef void (*btf_trace_finish_task_reaping)(void *, int);

typedef void (*btf_trace_skip_task_reaping)(void *, int);

struct trace_event_raw_mmap_lock {
	struct trace_entry ent;
	struct mm_struct *mm;
	u32 __data_loc_memcg_path;
	bool write;
	char __data[0];
};

struct trace_event_raw_mmap_lock_acquire_returned {
	struct trace_entry ent;
	struct mm_struct *mm;
	u32 __data_loc_memcg_path;
	bool write;
	bool success;
	char __data[0];
};

struct trace_event_data_offsets_mmap_lock {
	u32 memcg_path;
};

struct trace_event_data_offsets_mmap_lock_acquire_returned {
	u32 memcg_path;
};

typedef void (*btf_trace_mmap_lock_start_locking)(void *, struct mm_struct *, const char *, bool);

typedef void (*btf_trace_mmap_lock_released)(void *, struct mm_struct *, const char *, bool);

typedef void (*btf_trace_mmap_lock_acquire_returned)(void *, struct mm_struct *, const char *, bool, bool);

struct ei_entry {
	struct list_head list;
	long unsigned int start_addr;
	long unsigned int end_addr;
	int etype;
	void *priv;
};

struct simple_pm_bus {
	struct clk_bulk_data *clks;
	int num_clks;
};

enum {
	POWER_SUPPLY_TECHNOLOGY_UNKNOWN = 0,
	POWER_SUPPLY_TECHNOLOGY_NiMH = 1,
	POWER_SUPPLY_TECHNOLOGY_LION = 2,
	POWER_SUPPLY_TECHNOLOGY_LIPO = 3,
	POWER_SUPPLY_TECHNOLOGY_LiFe = 4,
	POWER_SUPPLY_TECHNOLOGY_NiCd = 5,
	POWER_SUPPLY_TECHNOLOGY_LiMn = 6,
};

enum {
	POWER_SUPPLY_SCOPE_UNKNOWN = 0,
	POWER_SUPPLY_SCOPE_SYSTEM = 1,
	POWER_SUPPLY_SCOPE_DEVICE = 2,
};

enum power_supply_property {
	POWER_SUPPLY_PROP_STATUS = 0,
	POWER_SUPPLY_PROP_CHARGE_TYPE = 1,
	POWER_SUPPLY_PROP_HEALTH = 2,
	POWER_SUPPLY_PROP_PRESENT = 3,
	POWER_SUPPLY_PROP_ONLINE = 4,
	POWER_SUPPLY_PROP_AUTHENTIC = 5,
	POWER_SUPPLY_PROP_TECHNOLOGY = 6,
	POWER_SUPPLY_PROP_CYCLE_COUNT = 7,
	POWER_SUPPLY_PROP_VOLTAGE_MAX = 8,
	POWER_SUPPLY_PROP_VOLTAGE_MIN = 9,
	POWER_SUPPLY_PROP_VOLTAGE_MAX_DESIGN = 10,
	POWER_SUPPLY_PROP_VOLTAGE_MIN_DESIGN = 11,
	POWER_SUPPLY_PROP_VOLTAGE_NOW = 12,
	POWER_SUPPLY_PROP_VOLTAGE_AVG = 13,
	POWER_SUPPLY_PROP_VOLTAGE_OCV = 14,
	POWER_SUPPLY_PROP_VOLTAGE_BOOT = 15,
	POWER_SUPPLY_PROP_CURRENT_MAX = 16,
	POWER_SUPPLY_PROP_CURRENT_NOW = 17,
	POWER_SUPPLY_PROP_CURRENT_AVG = 18,
	POWER_SUPPLY_PROP_CURRENT_BOOT = 19,
	POWER_SUPPLY_PROP_POWER_NOW = 20,
	POWER_SUPPLY_PROP_POWER_AVG = 21,
	POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN = 22,
	POWER_SUPPLY_PROP_CHARGE_EMPTY_DESIGN = 23,
	POWER_SUPPLY_PROP_CHARGE_FULL = 24,
	POWER_SUPPLY_PROP_CHARGE_EMPTY = 25,
	POWER_SUPPLY_PROP_CHARGE_NOW = 26,
	POWER_SUPPLY_PROP_CHARGE_AVG = 27,
	POWER_SUPPLY_PROP_CHARGE_COUNTER = 28,
	POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT = 29,
	POWER_SUPPLY_PROP_CONSTANT_CHARGE_CURRENT_MAX = 30,
	POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE = 31,
	POWER_SUPPLY_PROP_CONSTANT_CHARGE_VOLTAGE_MAX = 32,
	POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT = 33,
	POWER_SUPPLY_PROP_CHARGE_CONTROL_LIMIT_MAX = 34,
	POWER_SUPPLY_PROP_CHARGE_CONTROL_START_THRESHOLD = 35,
	POWER_SUPPLY_PROP_CHARGE_CONTROL_END_THRESHOLD = 36,
	POWER_SUPPLY_PROP_CHARGE_BEHAVIOUR = 37,
	POWER_SUPPLY_PROP_INPUT_CURRENT_LIMIT = 38,
	POWER_SUPPLY_PROP_INPUT_VOLTAGE_LIMIT = 39,
	POWER_SUPPLY_PROP_INPUT_POWER_LIMIT = 40,
	POWER_SUPPLY_PROP_ENERGY_FULL_DESIGN = 41,
	POWER_SUPPLY_PROP_ENERGY_EMPTY_DESIGN = 42,
	POWER_SUPPLY_PROP_ENERGY_FULL = 43,
	POWER_SUPPLY_PROP_ENERGY_EMPTY = 44,
	POWER_SUPPLY_PROP_ENERGY_NOW = 45,
	POWER_SUPPLY_PROP_ENERGY_AVG = 46,
	POWER_SUPPLY_PROP_CAPACITY = 47,
	POWER_SUPPLY_PROP_CAPACITY_ALERT_MIN = 48,
	POWER_SUPPLY_PROP_CAPACITY_ALERT_MAX = 49,
	POWER_SUPPLY_PROP_CAPACITY_ERROR_MARGIN = 50,
	POWER_SUPPLY_PROP_CAPACITY_LEVEL = 51,
	POWER_SUPPLY_PROP_TEMP = 52,
	POWER_SUPPLY_PROP_TEMP_MAX = 53,
	POWER_SUPPLY_PROP_TEMP_MIN = 54,
	POWER_SUPPLY_PROP_TEMP_ALERT_MIN = 55,
	POWER_SUPPLY_PROP_TEMP_ALERT_MAX = 56,
	POWER_SUPPLY_PROP_TEMP_AMBIENT = 57,
	POWER_SUPPLY_PROP_TEMP_AMBIENT_ALERT_MIN = 58,
	POWER_SUPPLY_PROP_TEMP_AMBIENT_ALERT_MAX = 59,
	POWER_SUPPLY_PROP_TIME_TO_EMPTY_NOW = 60,
	POWER_SUPPLY_PROP_TIME_TO_EMPTY_AVG = 61,
	POWER_SUPPLY_PROP_TIME_TO_FULL_NOW = 62,
	POWER_SUPPLY_PROP_TIME_TO_FULL_AVG = 63,
	POWER_SUPPLY_PROP_TYPE = 64,
	POWER_SUPPLY_PROP_USB_TYPE = 65,
	POWER_SUPPLY_PROP_SCOPE = 66,
	POWER_SUPPLY_PROP_PRECHARGE_CURRENT = 67,
	POWER_SUPPLY_PROP_CHARGE_TERM_CURRENT = 68,
	POWER_SUPPLY_PROP_CALIBRATE = 69,
	POWER_SUPPLY_PROP_MANUFACTURE_YEAR = 70,
	POWER_SUPPLY_PROP_MANUFACTURE_MONTH = 71,
	POWER_SUPPLY_PROP_MANUFACTURE_DAY = 72,
	POWER_SUPPLY_PROP_MODEL_NAME = 73,
	POWER_SUPPLY_PROP_MANUFACTURER = 74,
	POWER_SUPPLY_PROP_SERIAL_NUMBER = 75,
};

enum power_supply_type {
	POWER_SUPPLY_TYPE_UNKNOWN = 0,
	POWER_SUPPLY_TYPE_BATTERY = 1,
	POWER_SUPPLY_TYPE_UPS = 2,
	POWER_SUPPLY_TYPE_MAINS = 3,
	POWER_SUPPLY_TYPE_USB = 4,
	POWER_SUPPLY_TYPE_USB_DCP = 5,
	POWER_SUPPLY_TYPE_USB_CDP = 6,
	POWER_SUPPLY_TYPE_USB_ACA = 7,
	POWER_SUPPLY_TYPE_USB_TYPE_C = 8,
	POWER_SUPPLY_TYPE_USB_PD = 9,
	POWER_SUPPLY_TYPE_USB_PD_DRP = 10,
	POWER_SUPPLY_TYPE_APPLE_BRICK_ID = 11,
	POWER_SUPPLY_TYPE_WIRELESS = 12,
};

enum power_supply_usb_type {
	POWER_SUPPLY_USB_TYPE_UNKNOWN = 0,
	POWER_SUPPLY_USB_TYPE_SDP = 1,
	POWER_SUPPLY_USB_TYPE_DCP = 2,
	POWER_SUPPLY_USB_TYPE_CDP = 3,
	POWER_SUPPLY_USB_TYPE_ACA = 4,
	POWER_SUPPLY_USB_TYPE_C = 5,
	POWER_SUPPLY_USB_TYPE_PD = 6,
	POWER_SUPPLY_USB_TYPE_PD_DRP = 7,
	POWER_SUPPLY_USB_TYPE_PD_PPS = 8,
	POWER_SUPPLY_USB_TYPE_APPLE_BRICK_ID = 9,
};

enum power_supply_notifier_events {
	PSY_EVENT_PROP_CHANGED = 0,
};

union power_supply_propval {
	int intval;
	const char *strval;
};

struct power_supply_config {
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	void *drv_data;
	const struct attribute_group **attr_grp;
	char **supplied_to;
	size_t num_supplicants;
};

struct power_supply;

struct power_supply_desc {
	const char *name;
	enum power_supply_type type;
	const enum power_supply_usb_type *usb_types;
	size_t num_usb_types;
	const enum power_supply_property *properties;
	size_t num_properties;
	int (*get_property)(struct power_supply *, enum power_supply_property, union power_supply_propval *);
	int (*set_property)(struct power_supply *, enum power_supply_property, const union power_supply_propval *);
	int (*property_is_writeable)(struct power_supply *, enum power_supply_property);
	void (*external_power_changed)(struct power_supply *);
	void (*set_charged)(struct power_supply *);
	bool no_thermal;
	int use_for_apm;
};

struct power_supply_battery_info;

struct power_supply {
	const struct power_supply_desc *desc;
	char **supplied_to;
	size_t num_supplicants;
	char **supplied_from;
	size_t num_supplies;
	struct device_node *of_node;
	void *drv_data;
	struct device dev;
	struct work_struct changed_work;
	struct delayed_work deferred_register_work;
	spinlock_t changed_lock;
	bool changed;
	bool initialized;
	bool removing;
	atomic_t use_cnt;
	struct power_supply_battery_info *battery_info;
};

struct power_supply_maintenance_charge_table;

struct power_supply_battery_ocv_table;

struct power_supply_resistance_temp_table;

struct power_supply_vbat_ri_table;

struct power_supply_battery_info {
	unsigned int technology;
	int energy_full_design_uwh;
	int charge_full_design_uah;
	int voltage_min_design_uv;
	int voltage_max_design_uv;
	int tricklecharge_current_ua;
	int precharge_current_ua;
	int precharge_voltage_max_uv;
	int charge_term_current_ua;
	int charge_restart_voltage_uv;
	int overvoltage_limit_uv;
	int constant_charge_current_max_ua;
	int constant_charge_voltage_max_uv;
	struct power_supply_maintenance_charge_table *maintenance_charge;
	int maintenance_charge_size;
	int alert_low_temp_charge_current_ua;
	int alert_low_temp_charge_voltage_uv;
	int alert_high_temp_charge_current_ua;
	int alert_high_temp_charge_voltage_uv;
	int factory_internal_resistance_uohm;
	int factory_internal_resistance_charging_uohm;
	int ocv_temp[20];
	int temp_ambient_alert_min;
	int temp_ambient_alert_max;
	int temp_alert_min;
	int temp_alert_max;
	int temp_min;
	int temp_max;
	struct power_supply_battery_ocv_table *ocv_table[20];
	int ocv_table_size[20];
	struct power_supply_resistance_temp_table *resist_table;
	int resist_table_size;
	struct power_supply_vbat_ri_table *vbat2ri_discharging;
	int vbat2ri_discharging_size;
	struct power_supply_vbat_ri_table *vbat2ri_charging;
	int vbat2ri_charging_size;
	int bti_resistance_ohm;
	int bti_resistance_tolerance;
};

struct power_supply_battery_ocv_table {
	int ocv;
	int capacity;
};

struct power_supply_resistance_temp_table {
	int temp;
	int resistance;
};

struct power_supply_vbat_ri_table {
	int vbat_uv;
	int ri_uohm;
};

struct power_supply_maintenance_charge_table {
	int charge_current_max_ua;
	int charge_voltage_max_uv;
	int charge_safety_timer_minutes;
};

struct psy_am_i_supplied_data {
	struct power_supply *psy;
	unsigned int count;
};

struct psy_get_supplier_prop_data {
	struct power_supply *psy;
	enum power_supply_property psp;
	union power_supply_propval *val;
};

struct rmem_assigned_device {
	struct device *dev;
	struct reserved_mem *rmem;
	struct list_head list;
};

struct klist_waiter {
	struct list_head list;
	struct klist_node *node;
	struct task_struct *process;
	int woken;
};

struct timens_offset {
	s64 sec;
	u64 nsec;
};

struct arch_vdso_data {};

struct vdso_timestamp {
	u64 sec;
	u64 nsec;
};

struct vdso_data {
	u32 seq;
	s32 clock_mode;
	u64 cycle_last;
	u64 mask;
	u32 mult;
	u32 shift;
	union {
		struct vdso_timestamp basetime[12];
		struct timens_offset offset[12];
	};
	s32 tz_minuteswest;
	s32 tz_dsttime;
	u32 hrtimer_res;
	u32 __unused;
	struct arch_vdso_data arch_data;
};

enum vdso_abi {
	VDSO_ABI_AA64 = 0,
	VDSO_ABI_AA32 = 1,
};

enum vvar_pages {
	VVAR_DATA_PAGE_OFFSET = 0,
	VVAR_TIMENS_PAGE_OFFSET = 1,
	VVAR_NR_PAGES = 2,
};

struct vdso_abi_info {
	const char *name;
	const char *vdso_code_start;
	const char *vdso_code_end;
	long unsigned int vdso_pages;
	struct vm_special_mapping *dm;
	struct vm_special_mapping *cm;
};

enum aarch64_map {
	AA64_MAP_VVAR = 0,
	AA64_MAP_VDSO = 1,
};

struct clone_args {
	__u64 flags;
	__u64 pidfd;
	__u64 child_tid;
	__u64 parent_tid;
	__u64 exit_signal;
	__u64 stack;
	__u64 stack_size;
	__u64 tls;
	__u64 set_tid;
	__u64 set_tid_size;
	__u64 cgroup;
};

struct trace_event_raw_task_newtask {
	struct trace_entry ent;
	pid_t pid;
	char comm[16];
	long unsigned int clone_flags;
	short int oom_score_adj;
	char __data[0];
};

struct trace_event_raw_task_rename {
	struct trace_entry ent;
	pid_t pid;
	char oldcomm[16];
	char newcomm[16];
	short int oom_score_adj;
	char __data[0];
};

struct trace_event_data_offsets_task_newtask {};

struct trace_event_data_offsets_task_rename {};

typedef void (*btf_trace_task_newtask)(void *, struct task_struct *, long unsigned int);

typedef void (*btf_trace_task_rename)(void *, struct task_struct *, const char *);

struct vm_stack {
	struct callback_head rcu;
	struct vm_struct *stack_vm_area;
};

struct audit_context;

struct trace_event_raw_timer_class {
	struct trace_entry ent;
	void *timer;
	char __data[0];
};

struct trace_event_raw_timer_start {
	struct trace_entry ent;
	void *timer;
	void *function;
	long unsigned int expires;
	long unsigned int now;
	unsigned int flags;
	char __data[0];
};

struct trace_event_raw_timer_expire_entry {
	struct trace_entry ent;
	void *timer;
	long unsigned int now;
	void *function;
	long unsigned int baseclk;
	char __data[0];
};

struct trace_event_raw_hrtimer_init {
	struct trace_entry ent;
	void *hrtimer;
	clockid_t clockid;
	enum hrtimer_mode mode;
	char __data[0];
};

struct trace_event_raw_hrtimer_start {
	struct trace_entry ent;
	void *hrtimer;
	void *function;
	s64 expires;
	s64 softexpires;
	enum hrtimer_mode mode;
	char __data[0];
};

struct trace_event_raw_hrtimer_expire_entry {
	struct trace_entry ent;
	void *hrtimer;
	s64 now;
	void *function;
	char __data[0];
};

struct trace_event_raw_hrtimer_class {
	struct trace_entry ent;
	void *hrtimer;
	char __data[0];
};

struct trace_event_raw_itimer_state {
	struct trace_entry ent;
	int which;
	long long unsigned int expires;
	long int value_sec;
	long int value_nsec;
	long int interval_sec;
	long int interval_nsec;
	char __data[0];
};

struct trace_event_raw_itimer_expire {
	struct trace_entry ent;
	int which;
	pid_t pid;
	long long unsigned int now;
	char __data[0];
};

struct trace_event_data_offsets_timer_class {};

struct trace_event_data_offsets_timer_start {};

struct trace_event_data_offsets_timer_expire_entry {};

struct trace_event_data_offsets_hrtimer_init {};

struct trace_event_data_offsets_hrtimer_start {};

struct trace_event_data_offsets_hrtimer_expire_entry {};

struct trace_event_data_offsets_hrtimer_class {};

struct trace_event_data_offsets_itimer_state {};

struct trace_event_data_offsets_itimer_expire {};

typedef void (*btf_trace_timer_init)(void *, struct timer_list *);

typedef void (*btf_trace_timer_start)(void *, struct timer_list *, long unsigned int, unsigned int);

typedef void (*btf_trace_timer_expire_entry)(void *, struct timer_list *, long unsigned int);

typedef void (*btf_trace_timer_expire_exit)(void *, struct timer_list *);

typedef void (*btf_trace_timer_cancel)(void *, struct timer_list *);

typedef void (*btf_trace_hrtimer_init)(void *, struct hrtimer *, clockid_t, enum hrtimer_mode);

typedef void (*btf_trace_hrtimer_start)(void *, struct hrtimer *, enum hrtimer_mode);

typedef void (*btf_trace_hrtimer_expire_entry)(void *, struct hrtimer *, ktime_t *);

typedef void (*btf_trace_hrtimer_expire_exit)(void *, struct hrtimer *);

typedef void (*btf_trace_hrtimer_cancel)(void *, struct hrtimer *);

typedef void (*btf_trace_itimer_state)(void *, int, const struct itimerspec64 * const, long long unsigned int);

typedef void (*btf_trace_itimer_expire)(void *, int, struct pid *, long long unsigned int);

struct timer_base {
	raw_spinlock_t lock;
	struct timer_list *running_timer;
	long unsigned int clk;
	long unsigned int next_expiry;
	unsigned int cpu;
	bool next_expiry_recalc;
	bool is_idle;
	bool timers_pending;
	long unsigned int pending_map[9];
	struct hlist_head vectors[576];
	long: 64;
	long: 64;
};

struct process_timer {
	struct timer_list timer;
	struct task_struct *task;
};

struct cpu_stop_done {
	atomic_t nr_todo;
	int ret;
	struct completion completion;
};

struct cpu_stopper {
	struct task_struct *thread;
	raw_spinlock_t lock;
	bool enabled;
	struct list_head works;
	struct cpu_stop_work stop_work;
	long unsigned int caller;
	cpu_stop_fn_t fn;
};

enum multi_stop_state {
	MULTI_STOP_NONE = 0,
	MULTI_STOP_PREPARE = 1,
	MULTI_STOP_DISABLE_IRQ = 2,
	MULTI_STOP_RUN = 3,
	MULTI_STOP_EXIT = 4,
};

struct multi_stop_data {
	cpu_stop_fn_t fn;
	void *data;
	unsigned int num_threads;
	const struct cpumask *active_cpus;
	enum multi_stop_state state;
	atomic_t thread_ack;
};

struct tracer_stat {
	const char *name;
	void * (*stat_start)(struct tracer_stat *);
	void * (*stat_next)(void *, int);
	cmp_func_t stat_cmp;
	int (*stat_show)(struct seq_file *, void *);
	void (*stat_release)(void *);
	int (*stat_headers)(struct seq_file *);
};

struct stat_node {
	struct rb_node node;
	void *stat;
};

struct stat_session {
	struct list_head session_list;
	struct tracer_stat *ts;
	struct rb_root stat_root;
	struct mutex stat_mutex;
	struct dentry *file;
};

struct ftrace_graph_ent_entry {
	struct trace_entry ent;
	struct ftrace_graph_ent graph_ent;
};

struct ftrace_graph_ret_entry {
	struct trace_entry ent;
	struct ftrace_graph_ret ret;
};

struct fgraph_cpu_data {
	pid_t last_pid;
	int depth;
	int depth_irq;
	int ignore;
	long unsigned int enter_funcs[50];
};

struct fgraph_data {
	struct fgraph_cpu_data *cpu_data;
	struct ftrace_graph_ent_entry ent;
	struct ftrace_graph_ret_entry ret;
	int failed;
	int cpu;
	long: 0;
} __attribute__((packed));

enum {
	FLAGS_FILL_FULL = 268435456,
	FLAGS_FILL_START = 536870912,
	FLAGS_FILL_END = 805306368,
};

struct kprobe_trace_entry_head {
	struct trace_entry ent;
	long unsigned int ip;
};

struct kretprobe_trace_entry_head {
	struct trace_entry ent;
	long unsigned int func;
	long unsigned int ret_ip;
};

struct trace_kprobe {
	struct dyn_event devent;
	struct kretprobe rp;
	long unsigned int *nhit;
	const char *symbol;
	struct trace_probe tp;
};

struct bpf_iter_seq_array_map_info {
	struct bpf_map *map;
	void *percpu_value_buf;
	u32 index;
};

struct prog_poke_elem {
	struct list_head list;
	struct bpf_prog_aux *aux;
};

enum bpf_struct_ops_state {
	BPF_STRUCT_OPS_STATE_INIT = 0,
	BPF_STRUCT_OPS_STATE_INUSE = 1,
	BPF_STRUCT_OPS_STATE_TOBEFREE = 2,
	BPF_STRUCT_OPS_STATE_READY = 3,
};

struct bpf_struct_ops_value {
	refcount_t refcnt;
	enum bpf_struct_ops_state state;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	char data[0];
};

struct bpf_struct_ops_map {
	struct bpf_map map;
	struct callback_head rcu;
	const struct bpf_struct_ops *st_ops;
	struct mutex lock;
	struct bpf_link **links;
	void *image;
	struct bpf_struct_ops_value *uvalue;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	long: 64;
	struct bpf_struct_ops_value kvalue;
};

struct bpf_struct_ops_link {
	struct bpf_link link;
	struct bpf_map *map;
};

struct trace_event_raw_mm_lru_insertion {
	struct trace_entry ent;
	struct folio *folio;
	long unsigned int pfn;
	enum lru_list lru;
	long unsigned int flags;
	char __data[0];
};

struct trace_event_raw_mm_lru_activate {
	struct trace_entry ent;
	struct folio *folio;
	long unsigned int pfn;
	char __data[0];
};

struct trace_event_data_offsets_mm_lru_insertion {};

struct trace_event_data_offsets_mm_lru_activate {};

typedef void (*btf_trace_mm_lru_insertion)(void *, struct folio *);

typedef void (*btf_trace_mm_lru_activate)(void *, struct folio *);

struct lru_rotate {
	local_lock_t lock;
	struct folio_batch fbatch;
};

struct cpu_fbatches {
	local_lock_t lock;
	struct folio_batch lru_add;
	struct folio_batch lru_deactivate_file;
	struct folio_batch lru_deactivate;
	struct folio_batch lru_lazyfree;
	struct folio_batch activate;
};

typedef void (*move_fn_t)(struct lruvec *, struct folio *);

struct mlock_fbatch {
	local_lock_t lock;
	struct folio_batch fbatch;
};

struct vmap_area {
	long unsigned int va_start;
	long unsigned int va_end;
	struct rb_node rb_node;
	struct list_head list;
	union {
		long unsigned int subtree_max_size;
		struct vm_struct *vm;
	};
	long unsigned int flags;
};

typedef unsigned int kasan_vmalloc_flags_t;

enum memcg_stat_item {
	MEMCG_SWAP = 40,
	MEMCG_SOCK = 41,
	MEMCG_PERCPU_B = 42,
	MEMCG_VMALLOC = 43,
	MEMCG_KMEM = 44,
	MEMCG_ZSWAP_B = 45,
	MEMCG_ZSWAPPED = 46,
	MEMCG_NR_STAT = 47,
};

struct trace_event_raw_alloc_vmap_area {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int size;
	long unsigned int align;
	long unsigned int vstart;
	long unsigned int vend;
	int failed;
	char __data[0];
};

struct trace_event_raw_purge_vmap_area_lazy {
	struct trace_entry ent;
	long unsigned int start;
	long unsigned int end;
	unsigned int npurged;
	char __data[0];
};

struct trace_event_raw_free_vmap_area_noflush {
	struct trace_entry ent;
	long unsigned int va_start;
	long unsigned int nr_lazy;
	long unsigned int nr_lazy_max;
	char __data[0];
};

struct trace_event_data_offsets_alloc_vmap_area {};

struct trace_event_data_offsets_purge_vmap_area_lazy {};

struct trace_event_data_offsets_free_vmap_area_noflush {};

typedef void (*btf_trace_alloc_vmap_area)(void *, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, int);

typedef void (*btf_trace_purge_vmap_area_lazy)(void *, long unsigned int, long unsigned int, unsigned int);

typedef void (*btf_trace_free_vmap_area_noflush)(void *, long unsigned int, long unsigned int, long unsigned int);

struct vfree_deferred {
	struct llist_head list;
	struct work_struct wq;
};

enum fit_type {
	NOTHING_FIT = 0,
	FL_FIT_TYPE = 1,
	LE_FIT_TYPE = 2,
	RE_FIT_TYPE = 3,
	NE_FIT_TYPE = 4,
};

struct vmap_block_queue {
	spinlock_t lock;
	struct list_head free;
	struct xarray vmap_blocks;
};

struct vmap_block {
	spinlock_t lock;
	struct vmap_area *va;
	long unsigned int free;
	long unsigned int dirty;
	long unsigned int used_map[16];
	long unsigned int dirty_min;
	long unsigned int dirty_max;
	struct list_head free_list;
	struct callback_head callback_head;
	struct list_head purge;
};

typedef short unsigned int ushort;

struct user_arg_ptr {
	union {
		const char * const *native;
	} ptr;
};

struct simple_transaction_argresp {
	ssize_t size;
	char data[0];
};

enum fid_type {
	FILEID_ROOT = 0,
	FILEID_INO32_GEN = 1,
	FILEID_INO32_GEN_PARENT = 2,
	FILEID_BTRFS_WITHOUT_PARENT = 77,
	FILEID_BTRFS_WITH_PARENT = 78,
	FILEID_BTRFS_WITH_PARENT_ROOT = 79,
	FILEID_UDF_WITHOUT_PARENT = 81,
	FILEID_UDF_WITH_PARENT = 82,
	FILEID_NILFS_WITHOUT_PARENT = 97,
	FILEID_NILFS_WITH_PARENT = 98,
	FILEID_FAT_WITHOUT_PARENT = 113,
	FILEID_FAT_WITH_PARENT = 114,
	FILEID_LUSTRE = 151,
	FILEID_KERNFS = 254,
	FILEID_INVALID = 255,
};

struct fid {
	union {
		struct {
			u32 ino;
			u32 gen;
			u32 parent_ino;
			u32 parent_gen;
		} i32;
		struct {
			u32 block;
			u16 partref;
			u16 parent_partref;
			u32 generation;
			u32 parent_block;
			u32 parent_generation;
		} udf;
		struct {
			struct {} __empty_raw;
			__u32 raw[0];
		};
	};
};

enum utf8_normalization {
	UTF8_NFDI = 0,
	UTF8_NFDICF = 1,
	UTF8_NMAX = 2,
};

struct simple_attr {
	int (*get)(void *, u64 *);
	int (*set)(void *, u64);
	char get_buf[24];
	char set_buf[24];
	void *data;
	const char *fmt;
	struct mutex mutex;
};

struct fs_pin {
	wait_queue_head_t wait;
	int done;
	struct hlist_node s_list;
	struct hlist_node m_list;
	void (*kill)(struct fs_pin *);
};

enum string_size_units {
	STRING_UNITS_10 = 0,
	STRING_UNITS_2 = 1,
};

struct strarray {
	char **array;
	size_t n;
};

struct rdists {
	struct {
		raw_spinlock_t rd_lock;
		void *rd_base;
		struct page *pend_page;
		phys_addr_t phys_base;
		u64 flags;
		cpumask_t *vpe_table_mask;
		void *vpe_l1_base;
	} *rdist;
	phys_addr_t prop_table_pa;
	void *prop_table_va;
	u64 flags;
	u32 gicd_typer;
	u32 gicd_typer2;
	int cpuhp_memreserve_state;
	bool has_vlpis;
	bool has_rvpeid;
	bool has_direct_lpi;
	bool has_vpend_valid_dirty;
};

struct redist_region {
	void *redist_base;
	phys_addr_t phys_base;
	bool single_redist;
};

struct gic_chip_data___2 {
	struct fwnode_handle *fwnode;
	phys_addr_t dist_phys_base;
	void *dist_base;
	struct redist_region *redist_regions;
	struct rdists rdists;
	struct irq_domain *domain;
	u64 redist_stride;
	u32 nr_redist_regions;
	u64 flags;
	bool has_rss;
	unsigned int ppi_nr;
	struct partition_desc **ppi_descs;
};

enum gic_intid_range {
	SGI_RANGE = 0,
	PPI_RANGE = 1,
	SPI_RANGE = 2,
	EPPI_RANGE = 3,
	ESPI_RANGE = 4,
	LPI_RANGE = 5,
	__INVALID_RANGE__ = 6,
};

struct clk_fixed_rate {
	struct clk_hw hw;
	long unsigned int fixed_rate;
	long unsigned int fixed_accuracy;
	long unsigned int flags;
};

struct timer_rand_state {
	long unsigned int last_time;
	long int last_delta;
	long int last_delta2;
};

enum chacha_constants {
	CHACHA_CONSTANT_EXPA = 1634760805,
	CHACHA_CONSTANT_ND_3 = 857760878,
	CHACHA_CONSTANT_2_BY = 2036477234,
	CHACHA_CONSTANT_TE_K = 1797285236,
};

enum {
	CRNG_EMPTY = 0,
	CRNG_EARLY = 1,
	CRNG_READY = 2,
};

enum {
	CRNG_RESEED_START_INTERVAL = 250,
	CRNG_RESEED_INTERVAL = 15000,
};

struct crng {
	u8 key[32];
	long unsigned int generation;
	local_lock_t lock;
};

struct batch_u8 {
	u8 entropy[96];
	local_lock_t lock;
	long unsigned int generation;
	unsigned int position;
};

struct batch_u16 {
	u16 entropy[48];
	local_lock_t lock;
	long unsigned int generation;
	unsigned int position;
};

struct batch_u32 {
	u32 entropy[24];
	local_lock_t lock;
	long unsigned int generation;
	unsigned int position;
};

struct batch_u64 {
	u64 entropy[12];
	local_lock_t lock;
	long unsigned int generation;
	unsigned int position;
};

enum {
	POOL_BITS = 256,
	POOL_READY_BITS = 256,
	POOL_EARLY_BITS = 128,
};

struct fast_pool {
	long unsigned int pool[4];
	long unsigned int last;
	unsigned int count;
	struct timer_list mix;
};

struct entropy_timer_state {
	long unsigned int entropy;
	struct timer_list timer;
	atomic_t samples;
	unsigned int samples_per_bit;
};

enum {
	NUM_TRIAL_SAMPLES = 8192,
	MAX_SAMPLES_PER_BIT = 16,
};

enum {
	MIX_INFLIGHT = 2147483648,
};

struct container_dev {
	struct device dev;
	int (*offline)(struct container_dev *);
};

typedef efi_status_t efi_query_variable_store_t(u32, long unsigned int, bool);

struct efivar_operations {
	efi_get_variable_t *get_variable;
	efi_get_next_variable_t *get_next_variable;
	efi_set_variable_t *set_variable;
	efi_set_variable_t *set_variable_nonblocking;
	efi_query_variable_store_t *query_variable_store;
};

struct efivars {
	struct kset *kset;
	const struct efivar_operations *ops;
};

struct pmu_irq_ops {
	void (*enable_pmuirq)(unsigned int);
	void (*disable_pmuirq)(unsigned int);
	void (*free_pmuirq)(unsigned int, int, void *);
};

struct efi_file_path_dev_path {
	struct efi_generic_dev_path header;
	efi_char16_t filename[0];
};

union efi_device_path_from_text_protocol {
	struct {
		efi_device_path_protocol_t * (*convert_text_to_device_node)(const efi_char16_t *);
		efi_device_path_protocol_t * (*convert_text_to_device_path)(const efi_char16_t *);
	};
	struct {
		u32 convert_text_to_device_node;
		u32 convert_text_to_device_path;
	} mixed_mode;
};

typedef union efi_device_path_from_text_protocol efi_device_path_from_text_protocol_t;

typedef struct {
	u64 size;
	u64 file_size;
	u64 phys_size;
	efi_time_t create_time;
	efi_time_t last_access_time;
	efi_time_t modification_time;
	__u64 attribute;
	efi_char16_t filename[0];
} efi_file_info_t;

union efi_file_protocol;

typedef union efi_file_protocol efi_file_protocol_t;

union efi_file_protocol {
	struct {
		u64 revision;
		efi_status_t (*open)(efi_file_protocol_t *, efi_file_protocol_t **, efi_char16_t *, u64, u64);
		efi_status_t (*close)(efi_file_protocol_t *);
		efi_status_t (*delete)(efi_file_protocol_t *);
		efi_status_t (*read)(efi_file_protocol_t *, long unsigned int *, void *);
		efi_status_t (*write)(efi_file_protocol_t *, long unsigned int, void *);
		efi_status_t (*get_position)(efi_file_protocol_t *, u64 *);
		efi_status_t (*set_position)(efi_file_protocol_t *, u64);
		efi_status_t (*get_info)(efi_file_protocol_t *, efi_guid_t *, long unsigned int *, void *);
		efi_status_t (*set_info)(efi_file_protocol_t *, efi_guid_t *, long unsigned int, void *);
		efi_status_t (*flush)(efi_file_protocol_t *);
	};
	struct {
		u64 revision;
		u32 open;
		u32 close;
		u32 delete;
		u32 read;
		u32 write;
		u32 get_position;
		u32 set_position;
		u32 get_info;
		u32 set_info;
		u32 flush;
	} mixed_mode;
};

union efi_simple_file_system_protocol;

typedef union efi_simple_file_system_protocol efi_simple_file_system_protocol_t;

union efi_simple_file_system_protocol {
	struct {
		u64 revision;
		efi_status_t (*open_volume)(efi_simple_file_system_protocol_t *, efi_file_protocol_t **);
	};
	struct {
		u64 revision;
		u32 open_volume;
	} mixed_mode;
};

struct finfo {
	efi_file_info_t info;
	efi_char16_t filename[256];
};

struct wchan_info {
	long unsigned int pc;
	int count;
};

struct unwind_state {
	long unsigned int fp;
	long unsigned int pc;
	struct llist_node *kr_cur;
	struct task_struct *task;
	struct stack_info stack;
	struct stack_info *stacks;
	int nr_stacks;
};

enum {
	CAP_HWCAP = 1,
};

enum kvm_mode {
	KVM_MODE_DEFAULT = 0,
	KVM_MODE_PROTECTED = 1,
	KVM_MODE_NV = 2,
	KVM_MODE_NONE = 3,
};

struct __ftr_reg_entry {
	u32 sys_id;
	struct arm64_ftr_reg *reg;
};

typedef void kpti_remap_fn(int, int, phys_addr_t, long unsigned int);

struct trace_event_raw_cpuhp_enter {
	struct trace_entry ent;
	unsigned int cpu;
	int target;
	int idx;
	void *fun;
	char __data[0];
};

struct trace_event_raw_cpuhp_multi_enter {
	struct trace_entry ent;
	unsigned int cpu;
	int target;
	int idx;
	void *fun;
	char __data[0];
};

struct trace_event_raw_cpuhp_exit {
	struct trace_entry ent;
	unsigned int cpu;
	int state;
	int idx;
	int ret;
	char __data[0];
};

struct trace_event_data_offsets_cpuhp_enter {};

struct trace_event_data_offsets_cpuhp_multi_enter {};

struct trace_event_data_offsets_cpuhp_exit {};

typedef void (*btf_trace_cpuhp_enter)(void *, unsigned int, int, int, int (*)(unsigned int));

typedef void (*btf_trace_cpuhp_multi_enter)(void *, unsigned int, int, int, int (*)(unsigned int, struct hlist_node *), struct hlist_node *);

typedef void (*btf_trace_cpuhp_exit)(void *, unsigned int, int, int, int);

struct cpuhp_cpu_state {
	enum cpuhp_state state;
	enum cpuhp_state target;
	enum cpuhp_state fail;
	struct task_struct *thread;
	bool should_run;
	bool rollback;
	bool single;
	bool bringup;
	struct hlist_node *node;
	struct hlist_node *last;
	enum cpuhp_state cb_state;
	int result;
	atomic_t ap_sync_state;
	struct completion done_up;
	struct completion done_down;
};

struct cpuhp_step {
	const char *name;
	union {
		int (*single)(unsigned int);
		int (*multi)(unsigned int, struct hlist_node *);
	} startup;
	union {
		int (*single)(unsigned int);
		int (*multi)(unsigned int, struct hlist_node *);
	} teardown;
	struct hlist_head list;
	bool cant_stop;
	bool multi_instance;
};

enum cpuhp_sync_state {
	SYNC_STATE_DEAD = 0,
	SYNC_STATE_KICKED = 1,
	SYNC_STATE_SHOULD_DIE = 2,
	SYNC_STATE_ALIVE = 3,
	SYNC_STATE_SHOULD_ONLINE = 4,
	SYNC_STATE_ONLINE = 5,
};

enum cpu_mitigations {
	CPU_MITIGATIONS_OFF = 0,
	CPU_MITIGATIONS_AUTO = 1,
	CPU_MITIGATIONS_AUTO_NOSMT = 2,
};

enum {
	KERNEL_PARAM_OPS_FL_NOARG = 1,
};

enum {
	KERNEL_PARAM_FL_UNSAFE = 1,
	KERNEL_PARAM_FL_HWPARAM = 2,
};

struct param_attribute {
	struct module_attribute mattr;
	const struct kernel_param *param;
};

struct module_param_attrs {
	unsigned int num;
	struct attribute_group grp;
	struct param_attribute attrs[0];
};

struct kmalloced_param {
	struct list_head list;
	char val[0];
};

struct task_cputime {
	u64 stime;
	u64 utime;
	long long unsigned int sum_exec_runtime;
};

struct dl_bandwidth {
	raw_spinlock_t dl_runtime_lock;
	u64 dl_runtime;
	u64 dl_period;
};

struct idle_timer {
	struct hrtimer timer;
	int done;
};

typedef struct rt_rq *rt_rq_iter_t;

struct trace_export {
	struct trace_export *next;
	void (*write)(struct trace_export *, const void *, unsigned int);
	int flags;
};

typedef bool (*cond_update_fn_t)(struct trace_array *, void *);

struct trace_min_max_param {
	struct mutex *lock;
	u64 *val;
	u64 *min;
	u64 *max;
};

struct saved_cmdlines_buffer {
	unsigned int map_pid_to_cmdline[4097];
	unsigned int *map_cmdline_to_pid;
	unsigned int cmdline_num;
	int cmdline_idx;
	char *saved_cmdlines;
};

struct ftrace_stack {
	long unsigned int calls[1024];
};

struct ftrace_stacks {
	struct ftrace_stack stacks[4];
};

struct trace_buffer_struct {
	int nesting;
	char buffer[4096];
};

struct ftrace_buffer_info {
	struct trace_iterator iter;
	void *spare;
	unsigned int spare_cpu;
	unsigned int read;
};

struct err_info {
	const char **errs;
	u8 type;
	u16 pos;
	u64 ts;
};

struct tracing_log_err {
	struct list_head list;
	struct err_info info;
	char loc[128];
	char *cmd;
};

struct buffer_ref {
	struct trace_buffer *buffer;
	void *page;
	int cpu;
	refcount_t refcount;
};

struct trace_event_raw_error_report_template {
	struct trace_entry ent;
	enum error_detector error_detector;
	long unsigned int id;
	char __data[0];
};

struct trace_event_data_offsets_error_report_template {};

typedef void (*btf_trace_error_report_end)(void *, enum error_detector, long unsigned int);

enum bpf_cmd {
	BPF_MAP_CREATE = 0,
	BPF_MAP_LOOKUP_ELEM = 1,
	BPF_MAP_UPDATE_ELEM = 2,
	BPF_MAP_DELETE_ELEM = 3,
	BPF_MAP_GET_NEXT_KEY = 4,
	BPF_PROG_LOAD = 5,
	BPF_OBJ_PIN = 6,
	BPF_OBJ_GET = 7,
	BPF_PROG_ATTACH = 8,
	BPF_PROG_DETACH = 9,
	BPF_PROG_TEST_RUN = 10,
	BPF_PROG_RUN = 10,
	BPF_PROG_GET_NEXT_ID = 11,
	BPF_MAP_GET_NEXT_ID = 12,
	BPF_PROG_GET_FD_BY_ID = 13,
	BPF_MAP_GET_FD_BY_ID = 14,
	BPF_OBJ_GET_INFO_BY_FD = 15,
	BPF_PROG_QUERY = 16,
	BPF_RAW_TRACEPOINT_OPEN = 17,
	BPF_BTF_LOAD = 18,
	BPF_BTF_GET_FD_BY_ID = 19,
	BPF_TASK_FD_QUERY = 20,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21,
	BPF_MAP_FREEZE = 22,
	BPF_BTF_GET_NEXT_ID = 23,
	BPF_MAP_LOOKUP_BATCH = 24,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH = 25,
	BPF_MAP_UPDATE_BATCH = 26,
	BPF_MAP_DELETE_BATCH = 27,
	BPF_LINK_CREATE = 28,
	BPF_LINK_UPDATE = 29,
	BPF_LINK_GET_FD_BY_ID = 30,
	BPF_LINK_GET_NEXT_ID = 31,
	BPF_ENABLE_STATS = 32,
	BPF_ITER_CREATE = 33,
	BPF_LINK_DETACH = 34,
	BPF_PROG_BIND_MAP = 35,
};

enum bpf_stats_type {
	BPF_STATS_RUN_TIME = 0,
};

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8 tag[8];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__u64 jited_prog_insns;
	__u64 xlated_prog_insns;
	__u64 load_time;
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__u64 map_ids;
	char name[16];
	__u32 ifindex;
	__u32 gpl_compatible: 1;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 nr_jited_ksyms;
	__u32 nr_jited_func_lens;
	__u64 jited_ksyms;
	__u64 jited_func_lens;
	__u32 btf_id;
	__u32 func_info_rec_size;
	__u64 func_info;
	__u32 nr_func_info;
	__u32 nr_line_info;
	__u64 line_info;
	__u64 jited_line_info;
	__u32 nr_jited_line_info;
	__u32 line_info_rec_size;
	__u32 jited_line_info_rec_size;
	__u32 nr_prog_tags;
	__u64 prog_tags;
	__u64 run_time_ns;
	__u64 run_cnt;
	__u64 recursion_misses;
	__u32 verified_insns;
	__u32 attach_btf_obj_id;
	__u32 attach_btf_id;
};

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char name[16];
	__u32 ifindex;
	__u32 btf_vmlinux_value_type_id;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	__u64 map_extra;
};

struct bpf_tracing_link {
	struct bpf_tramp_link link;
	enum bpf_attach_type attach_type;
	struct bpf_trampoline *trampoline;
	struct bpf_prog *tgt_prog;
};

enum bpf_audit {
	BPF_AUDIT_LOAD = 0,
	BPF_AUDIT_UNLOAD = 1,
	BPF_AUDIT_MAX = 2,
};

struct bpf_prog_kstats {
	u64 nsecs;
	u64 cnt;
	u64 misses;
};

struct bpf_raw_tp_link {
	struct bpf_link link;
	struct bpf_raw_event_map *btp;
};

struct bpf_perf_link {
	struct bpf_link link;
	struct file *perf_file;
};

typedef u64 (*btf_bpf_sys_bpf)(int, union bpf_attr *, u32);

typedef u64 (*btf_bpf_sys_close)(u32);

typedef u64 (*btf_bpf_kallsyms_lookup_name)(const char *, int, int, u64 *);

struct audit_buffer;

struct callchain_cpus_entries {
	struct callback_head callback_head;
	struct perf_callchain_entry *cpu_entries[0];
};

struct wait_page_key {
	struct folio *folio;
	int bit_nr;
	int page_match;
};

struct trace_event_raw_mm_filemap_op_page_cache {
	struct trace_entry ent;
	long unsigned int pfn;
	long unsigned int i_ino;
	long unsigned int index;
	dev_t s_dev;
	unsigned char order;
	char __data[0];
};

struct trace_event_raw_filemap_set_wb_err {
	struct trace_entry ent;
	long unsigned int i_ino;
	dev_t s_dev;
	errseq_t errseq;
	char __data[0];
};

struct trace_event_raw_file_check_and_advance_wb_err {
	struct trace_entry ent;
	struct file *file;
	long unsigned int i_ino;
	dev_t s_dev;
	errseq_t old;
	errseq_t new;
	char __data[0];
};

struct trace_event_data_offsets_mm_filemap_op_page_cache {};

struct trace_event_data_offsets_filemap_set_wb_err {};

struct trace_event_data_offsets_file_check_and_advance_wb_err {};

typedef void (*btf_trace_mm_filemap_delete_from_page_cache)(void *, struct folio *);

typedef void (*btf_trace_mm_filemap_add_to_page_cache)(void *, struct folio *);

typedef void (*btf_trace_filemap_set_wb_err)(void *, struct address_space *, errseq_t);

typedef void (*btf_trace_file_check_and_advance_wb_err)(void *, struct file *, errseq_t);

enum behavior {
	EXCLUSIVE = 0,
	SHARED = 1,
	DROP = 2,
};

struct files_stat_struct {
	long unsigned int nr_files;
	long unsigned int nr_free_files;
	long unsigned int max_files;
};

struct backing_file {
	struct file file;
	struct path real_path;
};

struct f_owner_ex {
	int type;
	__kernel_pid_t pid;
};

struct flock {
	short int l_type;
	short int l_whence;
	__kernel_off_t l_start;
	__kernel_off_t l_len;
	__kernel_pid_t l_pid;
};

struct debugfs_blob_wrapper {
	void *data;
	long unsigned int size;
};

struct debugfs_reg32 {
	char *name;
	long unsigned int offset;
};

struct debugfs_regset32 {
	const struct debugfs_reg32 *regs;
	int nregs;
	void *base;
	struct device *dev;
};

struct debugfs_u32_array {
	u32 *array;
	u32 n_elements;
};

struct debugfs_devm_entry {
	int (*read)(struct seq_file *, void *);
	struct device *dev;
};

struct genradix_root;

struct __genradix {
	struct genradix_root *root;
};

struct genradix_iter {
	size_t offset;
	size_t pos;
};

struct genradix_node {
	union {
		struct genradix_node *children[512];
		u8 data[4096];
	};
};

enum devm_ioremap_type {
	DEVM_IOREMAP = 0,
	DEVM_IOREMAP_UC = 1,
	DEVM_IOREMAP_WC = 2,
	DEVM_IOREMAP_NP = 3,
};

struct arch_io_reserve_memtype_wc_devres {
	resource_size_t start;
	resource_size_t size;
};

struct its_collection {
	u64 target_address;
	u16 col_id;
};

struct its_baser {
	void *base;
	u64 val;
	u32 order;
	u32 psz;
};

struct its_cmd_block;

struct its_device;

struct its_node {
	raw_spinlock_t lock;
	struct mutex dev_alloc_lock;
	struct list_head entry;
	void *base;
	void *sgir_base;
	phys_addr_t phys_base;
	struct its_cmd_block *cmd_base;
	struct its_cmd_block *cmd_write;
	struct its_baser tables[8];
	struct its_collection *collections;
	struct fwnode_handle *fwnode_handle;
	u64 (*get_msi_base)(struct its_device *);
	u64 typer;
	u64 cbaser_save;
	u32 ctlr_save;
	u32 mpidr;
	struct list_head its_device_list;
	u64 flags;
	long unsigned int list_nr;
	int numa_node;
	unsigned int msi_domain_flags;
	u32 pre_its_base;
	int vlpi_redist_offset;
};

struct its_cmd_block {
	union {
		u64 raw_cmd[4];
		__le64 raw_cmd_le[4];
	};
};

struct event_lpi_map {
	long unsigned int *lpi_map;
	u16 *col_map;
	irq_hw_number_t lpi_base;
	int nr_lpis;
	raw_spinlock_t vlpi_lock;
	struct its_vm *vm;
	struct its_vlpi_map *vlpi_maps;
	int nr_vlpis;
};

struct its_device {
	struct list_head entry;
	struct its_node *its;
	struct event_lpi_map event_map;
	void *itt;
	u32 nr_ites;
	u32 device_id;
	bool shared;
};

struct cpu_lpi_count {
	atomic_t managed;
	atomic_t unmanaged;
};

struct its_cmd_desc {
	union {
		struct {
			struct its_device *dev;
			u32 event_id;
		} its_inv_cmd;
		struct {
			struct its_device *dev;
			u32 event_id;
		} its_clear_cmd;
		struct {
			struct its_device *dev;
			u32 event_id;
		} its_int_cmd;
		struct {
			struct its_device *dev;
			int valid;
		} its_mapd_cmd;
		struct {
			struct its_collection *col;
			int valid;
		} its_mapc_cmd;
		struct {
			struct its_device *dev;
			u32 phys_id;
			u32 event_id;
		} its_mapti_cmd;
		struct {
			struct its_device *dev;
			struct its_collection *col;
			u32 event_id;
		} its_movi_cmd;
		struct {
			struct its_device *dev;
			u32 event_id;
		} its_discard_cmd;
		struct {
			struct its_collection *col;
		} its_invall_cmd;
		struct {
			struct its_vpe *vpe;
		} its_vinvall_cmd;
		struct {
			struct its_vpe *vpe;
			struct its_collection *col;
			bool valid;
		} its_vmapp_cmd;
		struct {
			struct its_vpe *vpe;
			struct its_device *dev;
			u32 virt_id;
			u32 event_id;
			bool db_enabled;
		} its_vmapti_cmd;
		struct {
			struct its_vpe *vpe;
			struct its_device *dev;
			u32 event_id;
			bool db_enabled;
		} its_vmovi_cmd;
		struct {
			struct its_vpe *vpe;
			struct its_collection *col;
			u16 seq_num;
			u16 its_list;
		} its_vmovp_cmd;
		struct {
			struct its_vpe *vpe;
		} its_invdb_cmd;
		struct {
			struct its_vpe *vpe;
			u8 sgi;
			u8 priority;
			bool enable;
			bool group;
			bool clear;
		} its_vsgi_cmd;
	};
};

typedef struct its_collection * (*its_cmd_builder_t)(struct its_node *, struct its_cmd_block *, struct its_cmd_desc *);

typedef struct its_vpe * (*its_cmd_vbuilder_t)(struct its_node *, struct its_cmd_block *, struct its_cmd_desc *);

struct lpi_range {
	struct list_head entry;
	u32 base_id;
	u32 span;
};

enum dpm_order {
	DPM_ORDER_NONE = 0,
	DPM_ORDER_DEV_AFTER_PARENT = 1,
	DPM_ORDER_PARENT_BEFORE_DEV = 2,
	DPM_ORDER_DEV_LAST = 3,
};

struct dev_ext_attribute {
	struct device_attribute attr;
	void *var;
};

enum device_link_state {
	DL_STATE_NONE = -1,
	DL_STATE_DORMANT = 0,
	DL_STATE_AVAILABLE = 1,
	DL_STATE_CONSUMER_PROBE = 2,
	DL_STATE_ACTIVE = 3,
	DL_STATE_SUPPLIER_UNBIND = 4,
};

struct device_link {
	struct device *supplier;
	struct list_head s_node;
	struct device *consumer;
	struct list_head c_node;
	struct device link_dev;
	enum device_link_state status;
	u32 flags;
	refcount_t rpm_active;
	struct kref kref;
	struct work_struct rm_work;
	bool supplier_preactivated;
};

struct fwnode_link {
	struct fwnode_handle *supplier;
	struct list_head s_hook;
	struct fwnode_handle *consumer;
	struct list_head c_hook;
	u8 flags;
};

union device_attr_group_devres {
	const struct attribute_group *group;
	const struct attribute_group **groups;
};

struct class_dir {
	struct kobject kobj;
	const struct class *class;
};

struct root_device {
	struct device dev;
	struct module *owner;
};

typedef struct {
	efi_guid_t guid;
	u64 table;
} efi_config_table_64_t;

struct efi_unaccepted_memory {
	u32 version;
	u32 unit_size;
	u64 phys_base;
	u64 size;
	long unsigned int bitmap[0];
};

struct of_phandle_iterator {
	const char *cells_name;
	int cell_count;
	const struct device_node *parent;
	const __be32 *list_end;
	const __be32 *phandle_end;
	const __be32 *cur;
	uint32_t cur_count;
	phandle phandle;
	struct device_node *node;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif /* __VMLINUX_H__ */
