#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use core::mem;
use tetsu_common::{Backend, Stats};

#[map]
static mut BACKENDS: HashMap<u32, Backend> = HashMap::with_max_entries(1024, 0);

#[map]
static mut STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;

#[xdp]
pub fn tetsu_lb(ctx: XdpContext) -> u32 {
    match try_tetsu_lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED, // Changed to ABORTED for debugging if parsing fails
    }
}

fn try_tetsu_lb(ctx: XdpContext) -> Result<u32, u32> {
    let offset = ctx.data();
    let end = ctx.data_end();

    let eth_hdr: *mut EthHdr = unsafe { ptr_at(offset, 0)? };

    let proto;
    unsafe {
        proto = u16::from_be((*eth_hdr).proto);
    }

    if proto != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_hdr_offset = offset + 14;
    let ip_hdr: *mut IpHdr = unsafe { ptr_at(ip_hdr_offset, 0)? };

    unsafe {
        let protocol = (*ip_hdr).protocol;
        if protocol != IPPROTO_TCP {
            return Ok(xdp_action::XDP_PASS);
        }

        let vip = u32::from_be((*ip_hdr).dst_addr);
        let stats = STATS.get_ptr_mut(0);
        if !stats.is_null() {
            (*stats).packets_processed += 1;
            let len = (end - offset) as u64;
            (*stats).bytes_processed += len;
        }

        if let Some(backend) = BACKENDS.get(&vip) {
            (*eth_hdr).dst = backend.mac;
            info!(&ctx, "Load balanced packet for VIP: {}", vip);
            return Ok(xdp_action::XDP_TX);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[repr(C, packed)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    proto: u16, // Needs byte order conversion
}

#[repr(C, packed)]
struct IpHdr {
    _version_ihl: u8,
    _tos: u8,
    _len: u16,
    _id: u16,
    _flags: u16,
    ttl: u8,
    protocol: u8,
    _checksum: u16,
    src_addr: u32, // Needs byte order conversion
    dst_addr: u32, // Needs byte order conversion
}

unsafe fn ptr_at<T>(offset: usize, off: usize) -> Result<*mut T, u32> {
    let ptr = (offset + off) as *const T;
    if offset + off + mem::size_of::<T>() > ctx.data_end() as usize {
        return Err(1);
    }
    Ok(ptr as *mut T)
}
