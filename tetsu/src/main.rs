use aya::{Bpf, maps::{HashMap, PerCpuArray}, programs::Xdp};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;
use tetsu_common::{Backend, Stats};
use tokio::signal;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(long)]
    vip: String,
    #[clap(long)]
    backend_mac: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/tetsu-ebpf"))?;
    
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to initialize logger: {}", e);
    }

    let mut backends: HashMap<_, u32, Backend> = HashMap::try_from(bpf.map_mut("BACKENDS")?)?;

    let vip: Ipv4Addr = args.vip.parse()?;
    let vip_raw = u32::from_be(vip.into()); // Convert IP to u32

    let mac_bytes: Vec<u8> = args.backend_mac
        .split(':')
        .map(|s| u8::from_str_radix(s, 16).unwrap())
        .collect();
    let mut mac_array = [0u8; 6];
    mac_array.copy_from_slice(&mac_bytes);

    let backend = Backend { mac: mac_array };

    unsafe {
        backends.insert(&vip_raw, &backend, 0)?;
    }
    info!("Mapping {} -> {}", args.vip, args.backend_mac);

    let program: &mut Xdp = bpf.program_mut("tetsu_lb").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.iface, aya::programs::XdpFlags::default())?;

    info!("Load Balancer running on {}...", args.iface);
    let stats_map = bpf.map_mut("STATS")?;
    let mut per_cpu_stats = PerCpuArray::<Stats>::try_from(stats_map)?;
    let num_cpus = num_cpus::get();

    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(1));
            
            let mut total_packets = 0u64;
            let mut total_bytes = 0u64;
            for cpu_id in 0..num_cpus {
                if let Ok(Some(stat)) = per_cpu_stats.get(&0, cpu_id) {
                    total_packets += stat.packets_processed;
                    total_bytes += stat.bytes_processed;
                }
            }

            info!("[STATS] Total PPS: {} | Total Bytes: {}", total_packets, total_bytes);
        }
    });

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
