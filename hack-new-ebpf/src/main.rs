#![no_std]
#![no_main]
#![feature(c_str_module)]
use core::ffi::c_str;

use aya_ebpf::{
    cty::c_char,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_write_user},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use hack_new_common::SyscallReadLogging;

#[map]
static MAP_BUFF_ADDRS: HashMap<u64, SyscallReadLogging> =
    HashMap::<u64, SyscallReadLogging>::with_max_entries(1024, 0);

const TARGET_COMM: &[u8] = b"behooked";

#[tracepoint]
pub fn tracepoint_sys_enter_read(ctx: TracePointContext) -> u32 {
    match sys_enter_read_check(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn sys_enter_read_check(ctx: TracePointContext) -> Result<u32, u32> {
    if let Ok(comm) = ctx.command() {
        for (index, target_char) in TARGET_COMM.iter().enumerate() {
            if *target_char != comm[index] {
                return Ok(0);
            }
        }
    } else {
        info!(&ctx, "悲");
        return Err(0);
    };

    let mut data = SyscallReadLogging::default();

    let pid_tgid = bpf_get_current_pid_tgid();

    unsafe {
        //field:char * buf; offset:24; size:8; signed:0;
        let buff_addr: u64 = ctx.read_at(24).unwrap();

        //field:size_t count; offset:32; size:8; signed:0;
        let size: u64 = ctx.read_at(32).unwrap();

        data.buffer_addr = buff_addr;

        data.calling_size = size;
    }

    MAP_BUFF_ADDRS.insert(&pid_tgid, &data, 0).unwrap();

    Ok(0)
}

#[tracepoint]
pub fn tracepoint_sys_exit_read(ctx: TracePointContext) -> u32 {
    match sys_exit_read_check(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn sys_exit_read_check(ctx: TracePointContext) -> Result<u32, u32> {
    if let Ok(comm) = ctx.command() {
        for (index, target_char) in TARGET_COMM.iter().enumerate() {
            if *target_char != comm[index] {
                return Ok(0);
            }
        }
    } else {
        info!(&ctx, "悲");
        return Err(0);
    };
    let pid_tgid = bpf_get_current_pid_tgid();

    unsafe {
        if let Some(data) = MAP_BUFF_ADDRS.get(&pid_tgid) {
            let hook = c_str::CStr::from_bytes_with_nul(b"flat{true}\0").unwrap();
            let te = data.calling_size;
            let tmpbuf = data.buffer_addr;

            if te != 4096 {
                return Ok(0);
            }
            if bpf_probe_write_user(tmpbuf as *mut c_char, hook.as_ptr()).is_ok() {
                info!(&ctx, "已经成功写入，地址是0x{:x}", { tmpbuf });
            } else {
                info!(&ctx, "其实并没有成功写入，地址是0x{:x}", {
                    tmpbuf
                });
            }
        } else {
            return Ok(0);
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
