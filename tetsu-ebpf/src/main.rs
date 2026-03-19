#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

static PACKET_COUNT: HashMap<u8, u64> = HashMap::with_max_entries(256, 0);

#[xdp]
pub fn packet_counter(ctx: XdpContext) -> u32 {
    match try_packet_counter(&ctx){
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_packet_counter(ctx: &XdpContext) -> Result<u32, ()>{
    let data = ctx.data();
    let data_end = ctx.data_end();

    let eth_header_size = 14;
    
    // requires explicit bounds checking before memory access
    if data + eth_header_size > data_end{
        return Ok(xdp_action::XDP_PASS);
    }

    let ethertype_ptr = (data + 12) as *count u16;
    let ethertype = unsafe { *ethertype_ptr};

    if ethertype != 0x0008u16{
        return Ok(xdp_action::XDP_PASS);
    }

    let protocol_ptr = (ip_header_start + protocol_offset) as *count u8;
    let protocol = unsafe{*protocol_ptr};

    info!(ctx, "Recieved ipv4 packet with protocol:{}", protocol);

    if let Some(count) = unsafe {PACKET_COUNT.get_ptr_mut(&protocol)}{
        unsafe {*count += 1};
    }
    else {
        let _ = PACKET_COUNT.insert(&protocol, &1, 0);
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> !{
    loop{}
}
