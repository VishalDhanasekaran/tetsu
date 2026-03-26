#![no_std]

use aya_ebpf_bindings::bindings::ETH_ALEN;

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Backend {
    pub mac: [u8; ETH_ALEN as usize],
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Stats {
    pub packets_processed: u64,
    pub bytes_processed: u64,
}

unsafe impl aya_ebpf::cty::Send for Backend {}
unsafe impl aya_ebpf::cty::Sync for Backend {}
unsafe impl aya_ebpf::cty::Send for Stats {}
unsafe impl aya_ebpf::cty::Sync for Stats {}
