use aya::{Bpf, programs::Xdp, maps::HashMap};
use aya_log::BpfLogger;
use clap::Parser;
use log::{info, warn};
use std::net::Ipv4Addr;
use tetsu_common::Backend;
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

    // Load the eBPF program
    let mut bpf = Bpf::load(include_bytes_aligned!("../../target/bpfel-unknown-none/release/tetsu-ebpf"))?;
    
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("Failed to initialize logger: {}", e);
    }

    //Access the Map
    let mut backends: HashMap<_, u32, Backend> = HashMap::try_from(bpf.map_mut("BACKENDS")?)?;

    // Parse Inputs
    let vip: u32 = u32::from(Ipv4Addr::parse(args.vip.as_str())?); 
    let vip_raw = u32::from_be(vip);

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
    info!("Inserted mapping: {} -> {:?}", args.vip, args.backend_mac);

    //Attach XDP Program
    let program: &mut Xdp = bpf.program_mut("tetsu_lb").unwrap().try_into()?;
    program.load()?;
    program.attach(&args.iface, aya::programs::XdpFlags::default())?;

    info!("Listening for packets on {}...", args.iface);
    info!("Press Ctrl-C to exit...");

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
