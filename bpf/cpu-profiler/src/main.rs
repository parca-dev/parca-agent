#![no_std]
#![no_main]

use aya_bpf::{
    bindings::BPF_F_USER_STACK,
    helpers::bpf_get_current_pid_tgid,
    macros::{perf_event, map},
    maps::{StackTrace, HashMap},
    programs::PerfEventContext,
};

// TODO(kakkoyun): Enable this when needed.
// TODO(kakkoyun): It might be needed for BPF_F_USER_STACK!
// #[allow(non_upper_case_globals)]
// #[allow(non_snake_case)]
// #[allow(non_camel_case_types)]
// #[allow(dead_code)]
// mod vmlinux;
//
// use vmlinux::task_struct;

// TODO(kakkoyun): Learn about Rust structs.
pub const MAX_STACK_ADDRESSES: u32 = 1024;
pub const MAX_STACK_DEPTH: u32 = 127;

#[repr(C)]
pub struct StackCountKey {
    pid: u32,
    user_stack_id: i32,
    kernel_stack_id: i32,
}

#[map(name = "counts")]
pub static mut COUNTS: HashMap<StackCountKey, u64> = HashMap::with_max_entries(MAX_STACK_ADDRESSES, 0);

#[map(name = "stack_traces")]
pub static mut STACK_TRACES: StackTrace = StackTrace::with_max_entries(MAX_STACK_DEPTH, 0);

// TODO(kakkoyun): Rename to profile_cpu. This needs to be done in Go as well.
#[perf_event(name = "do_sample")]
pub fn do_sample(ctx: PerfEventContext) -> u32 {
    match unsafe { try_profile_cpu(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_profile_cpu(ctx: PerfEventContext) -> Result<u32, u32> {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let pid = bpf_get_current_pid_tgid() as u32;
    if pid == 0 {
        return Ok(0);
    }

    let mut key = StackCountKey {
        pid: tgid,
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

    // TODO(kakkoyun): Is there a better way to implement __sync_fetch_and_add(count, 1)?
    return match { COUNTS.get(&key) } {
        Some(count) => {
            let val = count + 1;
            // TODO(kakkoyun): Check result!
            COUNTS.insert(&key, &val, 0);
            Ok(0)
        }
        None => {
            // TODO(kakkoyun): Check result!
            COUNTS.insert(&key, &1, 0);
            Ok(0)
        }
    }
    // u64 zero = 0;
    // u64 *count;
    // count = bpf_map_lookup_or_try_init(&counts, &key, &zero);
    // if (!count)
    //   return 0;
    //
    // __sync_fetch_and_add(count, 1);
}

// TODO(kakkoyun): Implement in Rust using Aya APIs.
// #[inline(always)]
// static __always_inline void *
// bpf_map_lookup_or_try_init(void *map, const void *key, const void *init) {
//   void *val;
//   long err;
//
//   val = bpf_map_lookup_elem(map, key);
//   if (val)
//     return val;
//
//   err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
//   // 17 == EEXIST
//   if (err && err != -17)
//     return 0;
//
//   return bpf_map_lookup_elem(map, key);
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}