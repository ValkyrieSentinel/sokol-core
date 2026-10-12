//! The mesh envelope's framing (wire format v2): bytes any connection can send before it is
//! authenticated. It lives here, apart from the node, so that Kani can prove it
//! (`cargo kani -p common`, docs/VERIFICATION.md); `orchestrator/src/p2p.rs` calls it.
//!
//! ```text
//! "SKM" | version u8 | sender u64 | timestamp_ms u64 | nonce u64 | payload_len u32
//!       | payload | signature (the rest of the frame)
//! ```
//!
//! All integers are little-endian. The signature covers every byte before it.
use core::fmt;

/// Every frame starts with these bytes and the wire version.
pub const MAGIC: &[u8; 3] = b"SKM";
/// Wire versions this node speaks.
pub const VERSION_MIN: u8 = 2;
pub const VERSION_MAX: u8 = 2;
/// Bytes before the payload.
pub const HEADER_LEN: usize = 3 + 1 + 8 + 8 + 8 + 4;

/// The fields of an envelope's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub sender_id: u64,
    pub timestamp_ms: u64,
    pub nonce: u64,
}

/// Why a frame is not a v2 envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Does not start with `SKM`: the pre-versioned protocol (v1, Dilithium3 over bincode).
    Legacy,
    /// `SKM` with a version this node does not speak.
    Unsupported(u8),
    Malformed(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Legacy => write!(
                f,
                "peer speaks the pre-versioned mesh protocol (v1: Dilithium3 over bincode); \
                 this node speaks v{}..v{}: upgrade the peer",
                VERSION_MIN, VERSION_MAX
            ),
            Self::Unsupported(v) => write!(
                f,
                "peer sent mesh wire version {}; this node speaks v{}..v{}",
                v, VERSION_MIN, VERSION_MAX
            ),
            Self::Malformed(why) => write!(f, "malformed envelope: {}", why),
        }
    }
}

/// The header of an envelope whose payload is `payload_len` bytes.
pub fn header(h: &Header, payload_len: u32) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    let parts: [&[u8]; 6] = [
        MAGIC,
        &[h.version],
        &h.sender_id.to_le_bytes(),
        &h.timestamp_ms.to_le_bytes(),
        &h.nonce.to_le_bytes(),
        &payload_len.to_le_bytes(),
    ];
    let mut at = 0;
    for part in parts {
        if let Some(dst) = out.get_mut(at..at + part.len()) {
            dst.copy_from_slice(part);
        }
        at += part.len();
    }
    out
}

/// A frame's header, payload and signature, without copying: every byte of the frame is in
/// exactly one of them. Refuses a frame that is not `SKM`, has a version this node does not
/// speak, is shorter than its header or declares a payload longer than the frame.
pub fn split(frame: &[u8]) -> Result<(Header, &[u8], &[u8]), WireError> {
    let Some((magic, rest)) = frame.split_first_chunk::<3>() else {
        return Err(WireError::Legacy);
    };
    if magic != MAGIC {
        return Err(WireError::Legacy);
    }
    let Some((&version, rest)) = rest.split_first() else {
        return Err(WireError::Malformed("no version"));
    };
    if !(VERSION_MIN..=VERSION_MAX).contains(&version) {
        return Err(WireError::Unsupported(version));
    }
    let field = |at: usize| -> Option<[u8; 8]> { rest.get(at..at + 8)?.try_into().ok() };
    let (Some(sender), Some(timestamp), Some(nonce)) = (field(0), field(8), field(16)) else {
        return Err(WireError::Malformed("short header"));
    };
    let payload_len = rest
        .get(24..28)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_le_bytes)
        .ok_or(WireError::Malformed("short header"))? as usize;
    let body = rest.get(28..).unwrap_or_default();
    let (payload, signature) = body
        .split_at_checked(payload_len)
        .ok_or(WireError::Malformed("payload longer than the frame"))?;
    let h = Header {
        version,
        sender_id: u64::from_le_bytes(sender),
        timestamp_ms: u64::from_le_bytes(timestamp),
        nonce: u64::from_le_bytes(nonce),
    };
    Ok((h, payload, signature))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The framing the proofs below cover, on concrete frames: `cargo test` does not run Kani
    /// harnesses.
    #[test]
    fn a_frame_splits_into_its_header_payload_and_signature() {
        let h = Header {
            version: 2,
            sender_id: 7,
            timestamp_ms: 1_700_000_000_000,
            nonce: 42,
        };
        let mut frame = header(&h, 3).to_vec();
        frame.extend_from_slice(b"abcSIG");
        assert_eq!(split(&frame), Ok((h, &b"abc"[..], &b"SIG"[..])));
        assert_eq!(frame.get(..3), Some(&MAGIC[..]));
        assert_eq!(split(b""), Err(WireError::Legacy));
        assert_eq!(split(b"XKM\x02"), Err(WireError::Legacy));
        assert_eq!(split(b"SKM"), Err(WireError::Malformed("no version")));
        assert_eq!(split(b"SKM\x03"), Err(WireError::Unsupported(3)));
        assert_eq!(
            split(b"SKM\x02short"),
            Err(WireError::Malformed("short header"))
        );
        let long = header(&h, 7);
        assert_eq!(
            split(&long),
            Err(WireError::Malformed("payload longer than the frame"))
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Frames up to this many bytes: the header and a few bytes past it, so every branch of
    /// `split` is reached (each field short, the payload shorter, equal or longer than the
    /// rest). Longer frames take no other path.
    const FRAME: usize = HEADER_LEN + 6;

    /// On any frame, `split` returns; when it accepts, the frame starts with `SKM` and a version
    /// this node speaks, and its header, payload and signature account for every byte, the
    /// payload being exactly as long as the header says.
    #[kani::proof]
    #[kani::unwind(8)]
    fn every_byte_of_an_accepted_frame_is_accounted_for() {
        let bytes: [u8; FRAME] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= FRAME);
        let frame = &bytes[..len];
        if let Ok((h, payload, signature)) = split(frame) {
            let declared = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
            let accounted = frame[..3] == *MAGIC
                && (VERSION_MIN..=VERSION_MAX).contains(&h.version)
                && payload.len() == declared as usize
                && HEADER_LEN + payload.len() + signature.len() == len;
            assert!(accounted);
        }
    }

    /// A frame that does not start with `SKM` is the legacy protocol, never an envelope.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_frame_without_the_magic_is_refused() {
        let bytes: [u8; FRAME] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= FRAME);
        kani::assume(len < 3 || bytes[..3] != *MAGIC);
        assert!(split(&bytes[..len]) == Err(WireError::Legacy));
    }

    /// What `header` writes, followed by the payload and the signature, splits back into the
    /// same header and the same two parts.
    #[kani::proof]
    #[kani::unwind(8)]
    fn a_written_frame_splits_back() {
        let h = Header {
            version: kani::any(),
            sender_id: kani::any(),
            timestamp_ms: kani::any(),
            nonce: kani::any(),
        };
        kani::assume((VERSION_MIN..=VERSION_MAX).contains(&h.version));
        let body: [u8; 6] = kani::any();
        let payload_len: usize = kani::any();
        kani::assume(payload_len <= body.len());
        let mut frame = [0u8; FRAME];
        frame[..HEADER_LEN].copy_from_slice(&header(&h, payload_len as u32));
        frame[HEADER_LEN..].copy_from_slice(&body);
        let (got, payload, signature) = match split(&frame) {
            Ok(parts) => parts,
            Err(_) => panic!("a written frame is refused"),
        };
        let same = got == h && payload == &body[..payload_len] && signature == &body[payload_len..];
        assert!(same);
    }
}
