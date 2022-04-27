#![no_std]
#![no_main]

// TODO(kakkoyun): Enable this when needed.
// #[allow(non_upper_case_globals)]
// #[allow(non_snake_case)]
// #[allow(non_camel_case_types)]
// #[allow(dead_code)]
// mod vmlinux;
//
// use vmlinux::task_struct;

use aya_bpf::{
    bindings::BPF_F_USER_STACK,
    macros::{map, perf_event},
    maps::{HashMap, StackTrace},
    programs::PerfEventContext,
    BpfContext,
};
use core::sync::atomic::{AtomicU64, Ordering};

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

#[perf_event(name = "profile_cpu")]
pub fn profile_cpu(ctx: PerfEventContext) -> u32 {
    match unsafe { try_profile_cpu(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[inline(always)]
unsafe fn try_profile_cpu(ctx: PerfEventContext) -> Result<u32, u32> {
    if ctx.pid() == 0 {
        return Ok(0);
    }

    let mut key = StackCountKey {
        pid: ctx.tgid(),
        user_stack_id: 0,
        kernel_stack_id: 0,
    };

    match { STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) } {
        Ok(stack_id) => {
            key.user_stack_id = stack_id as i32;
        }
        _ => {}
    }

    match { STACK_TRACES.get_stackid(&ctx, 0) } {
        Ok(stack_id) => {
            key.kernel_stack_id = stack_id as i32;
        }
        _ => {}
    }

    return try_update_count(&mut key);
}

#[inline(always)]
unsafe fn try_update_count(key: &mut StackCountKey) -> Result<u32, u32> {
    match { COUNTS.get(&key) } {
        Some(count) => {
            let val = AtomicU64::new(*count);
            val.store(val.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
            match COUNTS.insert(&key, &val.load(Ordering::SeqCst), 0) {
                Ok(_) => Ok(0),
                Err(ret) => Err(ret as u32),
            }
        }
        None => match COUNTS.insert(&key, &1, 0) {
            Ok(_) => Ok(0),
            Err(ret) => Err(ret as u32),
        },
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
