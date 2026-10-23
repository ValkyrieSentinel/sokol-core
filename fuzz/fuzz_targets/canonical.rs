#![no_main]
use common::canonical::{CanonicalError, CanonicalParser};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if CanonicalParser::validate_strict_json_object(text).is_ok() {
            let bytes = text.as_bytes().trim_ascii();
            assert!(bytes.starts_with(b"{") && bytes.ends_with(b"}"));
        }
    }
    let key: String = data.iter().take(32).map(|b| format!("{b:02x}")).collect();
    let duplicate = format!("{{\"{key}\":{},\"{key}\":0}}", data.len());
    assert_eq!(
        CanonicalParser::validate_strict_json_object(&duplicate),
        Err(CanonicalError::DuplicateKey)
    );
});
