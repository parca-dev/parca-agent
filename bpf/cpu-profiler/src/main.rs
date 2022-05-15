#![no_std]
#![no_main]

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

use aya_bpf::{
    bindings::BPF_F_USER_STACK,
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

    if let Ok(stack_id) = STACK_TRACES.get_stackid(&ctx, BPF_F_USER_STACK.into()) {
        key.user_stack_id = stack_id as i32;
    }

    if let Ok(stack_id) = STACK_TRACES.get_stackid(&ctx, 0) {
        key.kernel_stack_id = stack_id as i32;
    }

    return try_update_count(&mut key);
}

#[inline(always)]
unsafe fn try_update_count(key: &mut StackCountKey) -> Result<u32, u32> {
    let one = 1;
    match COUNTS.get(&key) {
        Some(count) => {
            let u = count + 1;
            match COUNTS.insert(&key, &u, 0) {
                Ok(_) => Ok(0),
                Err(ret) => Err(ret as u32),
            }
        }
        None => match COUNTS.insert(&key, &one, 0) {
            Ok(_) => Ok(0),
            Err(ret) => Err(ret as u32),
        },
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
