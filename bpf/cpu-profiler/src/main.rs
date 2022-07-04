#![no_std]
#![no_main]
#![feature(core_intrinsics)]

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";
use aya_bpf::{
    bindings::{BPF_F_USER_STACK, BPF_NOEXIST},
    macros::{map, perf_event},
    maps::{HashMap, StackTrace},
    programs::PerfEventContext,
    BpfContext,
};

pub const MAX_STACK_ADDRESSES: u32 = 1024;
pub const MAX_STACK_DEPTH: u32 = 127;

#[repr(C)]
pub struct StackCountKey {
    pid: u32,
    user_stack_id: i32,
    kernel_stack_id: i32,
}

#[map(name = "counts")]
pub static mut COUNTS: HashMap<StackCountKey, u64> =
    HashMap::with_max_entries(MAX_STACK_ADDRESSES, 0);

#[map(name = "stack_traces")]
pub static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(MAX_STACK_DEPTH, 0);

#[perf_event]
pub fn profile_cpu(ctx: PerfEventContext) -> u32 {
    unsafe {
        try_profile_cpu(ctx);
    }

    0
}

#[inline(always)]
unsafe fn try_profile_cpu(ctx: PerfEventContext) {
    if ctx.pid() == 0 {
        return;
    }

    let mut key = StackCountKey {
        pid: ctx.tgid(),
        user_stack_id: 0,
        kernel_stack_id: 0,
    };

    if let Ok(stack_id) = STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
        key.user_stack_id = stack_id as i32;
    }

    if let Ok(stack_id) = STACK_TRACES.get_stackid(&ctx, 0) {
        key.kernel_stack_id = stack_id as i32;
    }

    try_update_count(&mut key);
}

#[inline(always)]
unsafe fn try_update_count(key: &mut StackCountKey) {
    let one = 1;
    let count = COUNTS.get_mut(&key);
    match count {
        Some(count) => {
            core::intrinsics::atomic_xadd_acqrel(count, 1);
        }
        None => {
            _ = COUNTS.insert(&key, &one, BPF_NOEXIST.into());
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// TODO(kakkoyun): Enable this when needed.
// #[allow(non_upper_case_globals)]
// #[allow(non_snake_case)]
// #[allow(non_camel_case_types)]
// #[allow(dead_code)]
// mod vmlinux;
//
// use vmlinux::task_struct;
