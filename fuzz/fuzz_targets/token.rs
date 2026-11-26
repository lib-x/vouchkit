#![no_main]

use libfuzzer_sys::fuzz_target;
use vouchkit_core::{Verifier, VerifyOptions, decode_token, inspect_license};

fuzz_target!(|data: &[u8]| {
    let _ = inspect_license(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = decode_token(text);
        let _ = Verifier::new(&[], None).verify(text, &VerifyOptions::new("fuzz", (1, 0, 0), 0));
    }
});
