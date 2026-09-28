//! Drop events from the XDP program's ring buffer.
//!
//! Decoded field by field at the offsets `common::abi` fixes, without reinterpreting the bytes
//! as a struct: a record of any other size is refused and counted, not read.

use common::{abi::DROP_EVENT_SIZE, DropEvent};
use std::mem::offset_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};

/// Ring-buffer records refused because their size is not `DROP_EVENT_SIZE`.
pub static MALFORMED: AtomicU64 = AtomicU64::new(0);

fn field<const N: usize>(item: &[u8], offset: usize) -> Option<[u8; N]> {
    item.get(offset..offset + N)?.try_into().ok()
}

/// The audit line for one ring-buffer record, or `None` (counted in `MALFORMED`) if the record
/// is not a `DropEvent`.
pub fn audit_line(item: &[u8]) -> Option<String> {
    if item.len() != DROP_EVENT_SIZE {
        if MALFORMED.fetch_add(1, Ordering::Relaxed) == 0 {
            log::error!(
                "[eBPF RingBuf] record of {} bytes, expected {}: the XDP program and this build disagree on the event layout",
                item.len(),
                DROP_EVENT_SIZE
            );
        }
        return None;
    }
    let src: [u8; 16] = field(item, offset_of!(DropEvent, src_ip))?;
    let pkt_len = u32::from_ne_bytes(field(item, offset_of!(DropEvent, pkt_len))?);
    let reason = u16::from_ne_bytes(field(item, offset_of!(DropEvent, reason))?);
    let [protocol] = field(item, offset_of!(DropEvent, protocol))?;
    let [version] = field(item, offset_of!(DropEvent, ip_version))?;
    let ip = match version {
        4 => {
            let v4: [u8; 4] = field(&src, 0)?;
            Ipv4Addr::from(v4).to_string()
        }
        6 => Ipv6Addr::from(src).to_string(),
        _ => "-".to_string(),
    };
    Some(format!(
        "KERNEL_DROP_NOTIFY|IP:{}|Reason:{}|Proto:{}|Version:{}|PktLen:{}",
        ip, reason, protocol, version, pkt_len
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes the kernel writes, produced from the shared struct as the XDP program does.
    fn bytes_of(event: &DropEvent) -> Vec<u8> {
        // SAFETY: DropEvent is repr(C) without implicit padding (common::abi), so every byte
        // is initialised; the slice lives no longer than `event`.
        unsafe {
            std::slice::from_raw_parts((event as *const DropEvent).cast::<u8>(), DROP_EVENT_SIZE)
        }
        .to_vec()
    }

    fn event(src: [u8; 16], version: u8) -> DropEvent {
        DropEvent {
            src_ip: src,
            dst_ip: [0xAA; 16],
            pkt_len: 74,
            reason: common::drop_reason::TRAP_INTERCEPTED,
            protocol: 6,
            ip_version: version,
            payload_len: 0,
            _pad: 0,
            payload: [0xBB; common::MAX_PAYLOAD],
        }
    }

    #[test]
    fn every_field_is_read_from_its_own_bytes() {
        let mut src = [0u8; 16];
        src[..4].copy_from_slice(&[10, 231, 0, 2]);
        assert_eq!(
            audit_line(&bytes_of(&event(src, 4))).unwrap(),
            "KERNEL_DROP_NOTIFY|IP:10.231.0.2|Reason:6|Proto:6|Version:4|PktLen:74"
        );
        let v6: Ipv6Addr = "2001:db8::3".parse().unwrap();
        assert_eq!(
            audit_line(&bytes_of(&event(v6.octets(), 6))).unwrap(),
            "KERNEL_DROP_NOTIFY|IP:2001:db8::3|Reason:6|Proto:6|Version:6|PktLen:74"
        );
    }

    #[test]
    fn a_record_of_another_size_is_refused_and_counted() {
        let before = MALFORMED.load(Ordering::Relaxed);
        let good = bytes_of(&event([0; 16], 4));
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(audit_line(&longer), None);
        assert_eq!(audit_line(&good[..DROP_EVENT_SIZE - 1]), None);
        assert_eq!(MALFORMED.load(Ordering::Relaxed) - before, 2);
    }
}
