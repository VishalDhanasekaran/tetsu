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
use tetsu_common::Backend;

// This Map stores our Backend Servers.
// Key: The VIP (Virtual IP) address (u32).
// Value: The Backend's MAC address.
#[map]
static mut BACKENDS: HashMap<u32, Backend> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn tetsu_lb(ctx: XdpContext) -> u32 {
    match try_tetsu_lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS, // If we fail, let the kernel handle it
    }
}

fn try_tetsu_lb(ctx: XdpContext) -> Result<u32, u32> {
    let offset = ctx.data();
    let end = ctx.data_end();

    let eth_hdr: *mut EthHdr = unsafe { ptr_at(offset, 0)? };

    unsafe {
        if (*eth_hdr).proto != 0x08_u16 && (*eth_hdr).proto != 0x00_u16 {
        }
    }

    let ip_hdr_offset = offset + 14;
    let ip_hdr: *mut IpHdr = unsafe { ptr_at(ip_hdr_offset, 0)? };

    unsafe {
        if (*ip_hdr).protocol != 6 {
            return Ok(xdp_action::XDP_PASS);
        }

        let vip = u32::from_be((*ip_hdr).dst_addr);
        
        if let Some(backend) = BACKENDS.get(&vip) {
            (*eth_hdr).dst = backend.mac;
            
            (*eth_hdr).src = (*eth_hdr).src; // Placeholder: usually stays as is or updates to LB MAC

            info!(&ctx, "Forwarding packet to backend");
            return Ok(xdp_action::XDP_TX);
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[repr(C)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    proto: u16,
}

#[repr(C)]
struct IpHdr {
    _tos: u8,
    _len: u16,
    _id: u16,
    _flags: u16,
    ttl: u8,
    protocol: u8,
    _checksum: u16,
    src_addr: u32,
    dst_addr: u32,
}

unsafe fn ptr_at<T>(offset: usize, off: usize) -> Result<*mut T, u32> {
    let ptr = (offset + off) as *const T;
    if offset as usize + off + mem::size_of::<T>() > ctx.data_end() as usize {
        return Err(1);
    }
    Ok(ptr as *mut T)
}
