#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC},
    macros::{map, xdp},
    maps::{lpm_trie::Key, Array, LpmTrie, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use core::mem;

use common::{config_flags, drop_reason, DropEvent, PacketStats};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_DSTOPTS: u8 = 60;

const IP_MF: u16 = 0x2000;
const IP_OFFSET_MASK: u16 = 0x1FFF;

const TRAP_PORT: u16 = 44333;
const ADMIN_SSH_PORT: u16 = 2222;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct VlanHdr {
    pub tci: u16,
    pub ether_type: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ip6Hdr {
    pub ver_tc_fl: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ip6ExtHdr {
    pub next_header: u8,
    pub hdr_ext_len: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ip6FragHdr {
    pub next_header: u8,
    pub reserved: u8,
    pub frag_off: u16,
    pub id: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_reserved: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[map]
static BLOCKLIST_V4: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(65536, BPF_F_NO_PREALLOC);

#[map]
static BLOCKLIST_V6: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(65536, BPF_F_NO_PREALLOC);

#[map]
static STATS: PerCpuArray<PacketStats> = PerCpuArray::with_max_entries(1, 0);

/// Index 0: `common::config_flags` bits, written by the orchestrator before attach.
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(1, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data() as usize;
    let end = ctx.data_end() as usize;
    let len = mem::size_of::<T>();

    if offset > 0xffff || len > 0xffff {
        return Err(());
    }

    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn emit_drop_event_sampled(
    _ctx: &XdpContext,
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    pkt_len: u32,
    reason: u16,
    protocol: u8,
    ip_version: u8,
) {
    let mut should_emit = reason == drop_reason::TRAP_INTERCEPTED;

    if !should_emit {
        if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
            unsafe {
                if ((*stats_ptr).dropped_packets & 0xFF) == 0 {
                    should_emit = true;
                }
            }
        }
    }

    if !should_emit {
        return;
    }

    if let Some(mut entry) = EVENTS.reserve::<DropEvent>(0) {
        let entry_ptr = entry.as_mut_ptr();

        unsafe {
            (*entry_ptr).src_ip = *src_ip;
            (*entry_ptr).dst_ip = *dst_ip;
            (*entry_ptr).pkt_len = pkt_len;
            (*entry_ptr).reason = reason;
            (*entry_ptr).protocol = protocol;
            (*entry_ptr).ip_version = ip_version;
            (*entry_ptr)._pad = 0;
            (*entry_ptr).payload_len = 0;
        }
        entry.submit(0);
    }
}

#[xdp]
pub fn sentinel_vfr_filter(ctx: XdpContext) -> u32 {
    match try_sentinel_vfr_filter(&ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn parse_v6_next_header(ctx: &XdpContext, initial_offset: usize, initial_next: u8) -> Result<(u8, usize, bool), ()> {
    let mut curr_next = initial_next;
    let mut curr_offset = initial_offset;
    let mut non_first_fragment = false;

    for _ in 0..4 {
        match curr_next {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                let ext_ptr = ptr_at::<Ip6ExtHdr>(ctx, curr_offset)?;
                let next = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ext_ptr).next_header)) };
                let ext_len = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ext_ptr).hdr_ext_len)) };
                let len_bytes = ((ext_len as usize) + 1) * 8;

                curr_next = next;
                curr_offset += len_bytes;
            }
            IPPROTO_FRAGMENT => {
                let ext_ptr = ptr_at::<Ip6FragHdr>(ctx, curr_offset)?;
                let next = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ext_ptr).next_header)) };
                let off_raw = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ext_ptr).frag_off)) };
                curr_next = next;
                curr_offset += 8;
                if u16::from_be(off_raw) & 0xFFF8 != 0 {
                    // Non-first fragment: no L4 header follows.
                    non_first_fragment = true;
                    break;
                }
            }
            _ => break,
        }
    }

    Ok((curr_next, curr_offset, non_first_fragment))
}

#[inline(always)]
fn try_sentinel_vfr_filter(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_ptr = ptr_at::<EthHdr>(ctx, 0)?;
    let raw_eth_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*eth_ptr).ether_type)) };
    let mut eth_type = u16::from_be(raw_eth_type);
    let packet_len = (ctx.data_end() as usize - ctx.data() as usize) as u64;

    let mut ip_offset = mem::size_of::<EthHdr>();

    for _ in 0..2 {
        if eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD {
            let vlan_ptr = ptr_at::<VlanHdr>(ctx, ip_offset)?;
            let raw_next_type = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*vlan_ptr).ether_type)) };
            eth_type = u16::from_be(raw_next_type);
            ip_offset += mem::size_of::<VlanHdr>();
        } else {
            break;
        }
    }

    let is_blocked: bool;
    let protocol: u8;
    let l4_offset: usize;
    let ip_version: u8;
    // Only the first fragment carries the L4 header; later ones must not be parsed as TCP.
    let non_first_fragment: bool;

    let mut src_ip_16 = [0u8; 16];
    let mut dst_ip_16 = [0u8; 16];

    match eth_type {
        ETH_P_IP => {
            let ip_ptr = match ptr_at::<IpHdr>(ctx, ip_offset) {
                Ok(ptr) => ptr,
                Err(_) => {
                    record_drop(packet_len, drop_reason::MALFORMED_HEADER);
                    emit_drop_event_sampled(ctx, &[0u8; 16], &[0u8; 16], packet_len as u32, drop_reason::MALFORMED_HEADER, 0, 4);
                    return Ok(xdp_action::XDP_DROP);
                }
            };

            let version_ihl = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).version_ihl)) };
            let version = version_ihl >> 4;
            let ihl_bytes = ((version_ihl & 0x0F) * 4) as usize;

            if version != 4 || ihl_bytes < 20 || ihl_bytes > 60 || ctx.data() as usize + ip_offset + ihl_bytes > ctx.data_end() as usize {
                record_drop(packet_len, drop_reason::MALFORMED_HEADER);
                emit_drop_event_sampled(ctx, &[0u8; 16], &[0u8; 16], packet_len as u32, drop_reason::MALFORMED_HEADER, 0, 4);
                return Ok(xdp_action::XDP_DROP);
            }

            let frag_off_raw = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).frag_off)) };
            let frag_off = u16::from_be(frag_off_raw);
            let is_fragment = (frag_off & (IP_MF | IP_OFFSET_MASK)) != 0;
            non_first_fragment = (frag_off & IP_OFFSET_MASK) != 0;

            let src_u32 = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).src_addr)) };
            let dst_u32 = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).dst_addr)) };

            let src_bytes = src_u32.to_ne_bytes();
            let dst_bytes = dst_u32.to_ne_bytes();

            let key = Key::new(32, src_bytes);
            is_blocked = BLOCKLIST_V4.get(&key).is_some();

            protocol = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip_ptr).protocol)) };
            l4_offset = ip_offset + ihl_bytes;
            ip_version = 4;

            src_ip_16[..4].copy_from_slice(&src_bytes);
            dst_ip_16[..4].copy_from_slice(&dst_bytes);

            if is_fragment && !is_blocked && config_enabled(config_flags::DROP_IPV4_FRAGMENTS) {
                record_drop(packet_len, drop_reason::FRAGMENT_BLOCKED);
                emit_drop_event_sampled(ctx, &src_ip_16, &dst_ip_16, packet_len as u32, drop_reason::FRAGMENT_BLOCKED, protocol, ip_version);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        ETH_P_IPV6 => {
            let ip6_ptr = match ptr_at::<Ip6Hdr>(ctx, ip_offset) {
                Ok(ptr) => ptr,
                Err(_) => {
                    record_drop(packet_len, drop_reason::MALFORMED_HEADER);
                    emit_drop_event_sampled(ctx, &[0u8; 16], &[0u8; 16], packet_len as u32, drop_reason::MALFORMED_HEADER, 0, 6);
                    return Ok(xdp_action::XDP_DROP);
                }
            };

            let raw_ver = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip6_ptr).ver_tc_fl)) };
            let version = (u32::from_be(raw_ver) >> 28) as u8;

            if version != 6 {
                record_drop(packet_len, drop_reason::MALFORMED_HEADER);
                emit_drop_event_sampled(ctx, &[0u8; 16], &[0u8; 16], packet_len as u32, drop_reason::MALFORMED_HEADER, 0, 6);
                return Ok(xdp_action::XDP_DROP);
            }

            src_ip_16 = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip6_ptr).src_addr)) };
            dst_ip_16 = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip6_ptr).dst_addr)) };

            let key = Key::new(128, src_ip_16);
            is_blocked = BLOCKLIST_V6.get(&key).is_some();

            let next_hdr = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*ip6_ptr).next_header)) };
            let (real_proto, real_l4_offset, v6_non_first) = parse_v6_next_header(ctx, ip_offset + mem::size_of::<Ip6Hdr>(), next_hdr)?;

            protocol = real_proto;
            l4_offset = real_l4_offset;
            ip_version = 6;
            non_first_fragment = v6_non_first;
        }
        _ => {
            record_rx(packet_len);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if is_blocked {
        record_drop(packet_len, drop_reason::SLOW_PATH_LPM_HIT);
        emit_drop_event_sampled(ctx, &src_ip_16, &dst_ip_16, packet_len as u32, drop_reason::SLOW_PATH_LPM_HIT, protocol, ip_version);
        return Ok(xdp_action::XDP_DROP);
    }

    if protocol == IPPROTO_TCP && !non_first_fragment {
        if let Ok(tcp_ptr) = ptr_at::<TcpHdr>(ctx, l4_offset) {
            let dst_port = unsafe { core::ptr::read_unaligned(core::ptr::addr_of!((*tcp_ptr).dst_port)) };
            let port = u16::from_be(dst_port);

            if port == 80 || port == 443 || port == ADMIN_SSH_PORT {
                record_rx(packet_len);
                return Ok(xdp_action::XDP_PASS);
            }

            if port == TRAP_PORT {
                emit_drop_event_sampled(ctx, &src_ip_16, &dst_ip_16, packet_len as u32, drop_reason::TRAP_INTERCEPTED, protocol, ip_version);
                record_rx(packet_len);
                return Ok(xdp_action::XDP_PASS);
            }
        }
    }

    record_rx(packet_len);
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn config_enabled(flag: u32) -> bool {
    match CONFIG.get(0) {
        Some(flags) => flags & flag != 0,
        None => false,
    }
}

#[inline(always)]
fn record_rx(packet_len: u64) {
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).rx_packets += 1;
            (*stats_ptr).rx_bytes += packet_len;
        }
    }
}

#[inline(always)]
fn record_drop(packet_len: u64, reason: u16) {
    if let Some(stats_ptr) = STATS.get_ptr_mut(0) {
        unsafe {
            (*stats_ptr).rx_packets += 1;
            (*stats_ptr).rx_bytes += packet_len;
            (*stats_ptr).dropped_packets += 1;
            if reason == drop_reason::SLOW_PATH_LPM_HIT || reason == drop_reason::STATIC_BLOCK {
                (*stats_ptr).slow_path_hits += 1;
            }
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}