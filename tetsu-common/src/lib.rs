#![no_std]

use aya_ebpf_bindings::bindings::ETH_ALEN;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Backend {
    pub mac: [u8; ETH_ALEN as usize],
}

unsafe impl aya_ebpf::cty::Send for Backend {}
unsafe impl aya_ebpf::cty::Sync for Backend {}
