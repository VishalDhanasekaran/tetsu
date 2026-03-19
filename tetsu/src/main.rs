use anyhow::{Context, Result};
use aya::{
    // Ebpf is the main struct for managing eBPF programs
    Ebpf,
    // Include the compiled eBPF bytecode at compile time
    include_bytes_aligned,
    // Map types for accessing eBPF data structures
    maps::HashMap,
    // Program types and traits
    programs::{Xdp, XdpFlags},
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use std::{
    collections::BTreeMap,
    time::Duration,
};
use tokio::{
    signal,
    time::interval,
};

// Command-line argument parsing using clap
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Network interface to attach the XDP program to
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// Polling interval in seconds for reading counters
    #[arg(short, long, default_value = "1")]
    poll_interval: u64,
}

// Protocol number to name mapping for human-readable output
fn protocol_name(proto: u8) -> &'static str {
    match proto {
        1 => "ICMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        _ => "Other",
    }
}

// Main async entry point using tokio runtime
#[tokio::main]
async fn main() -> Result<()> {
    // Parse command-line arguments
    let args = Args::parse();

   env_logger::init();

    info!("Starting eBPF packet counter on interface {}", args.interface);

   let mut ebpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tetsu"
    ))?;

   if let Err(e) = EbpfLogger::init(&mut ebpf) {
        warn!("Failed to initialize eBPF logger: {}", e);
    }

   let program: &mut Xdp = ebpf
        .program_mut("packet_counter")
        .context("Failed to find XDP program")?
        .try_into()
        .context("Program is not XDP type")?;

   program.load().context("Failed to load XDP program")?;

   program
        .attach(&args.interface, XdpFlags::default())
        .context(format!("Failed to attach to interface {}", args.interface))?;

    info!("XDP program attached successfully");

   let packet_count: HashMap<_, u8, u64> = HashMap::try_from(
        ebpf.map("PACKET_COUNT")
            .context("Failed to find PACKET_COUNT map")?,
    )?;

    let mut poll_timer = interval(Duration::from_secs(args.poll_interval));

    info!("Monitoring packets... Press Ctrl+C to stop");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received shutdown signal");
                break;
            }
            _ = poll_timer.tick() => {
                // Collect all counts into a sorted map for display
                let mut stats: BTreeMap<u8, u64> = BTreeMap::new();

                for result in packet_count.iter() {
                    if let Ok((protocol, count)) = result {
                        stats.insert(protocol, count);
                    }
                }

                if !stats.is_empty() {
                    println!("\n--- Packet Statistics ---");
                    for (protocol, count) in &stats {
                        println!(
                            "Protocol {:3} ({:8}): {} packets",
                            protocol,
                            protocol_name(*protocol),
                            count
                        );
                    }
                }
            }
        }
    }

    info!("Shutting down...");
    Ok(())
}
