#![no_main]
use common::wire::{header, split, HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((h, payload, signature)) = split(data) {
        assert_eq!(HEADER_LEN + payload.len() + signature.len(), data.len());
        let encoded = header(&h, u32::try_from(payload.len()).expect("bounded input"));
        assert_eq!(&data[..HEADER_LEN], &encoded);
        assert_eq!(&data[HEADER_LEN..HEADER_LEN + payload.len()], payload);
        assert_eq!(&data[HEADER_LEN + payload.len()..], signature);
    }
});
