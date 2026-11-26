#![no_main]

use libfuzzer_sys::fuzz_target;
use vouchkit_core::{SigningKey, Verifier};

fuzz_target!(|data: &[u8]| {
    let key = SigningKey::from_seed(&[17; 32]);
    let verifier = Verifier::new(&[(255, key.public())], None);
    let _ = verifier.verify_delegation(data);
    if data.len() <= 187 {
        let Ok(length) = u16::try_from(data.len()) else {
            return;
        };
        let body = [&[1, 3, 255][..], &length.to_be_bytes(), data].concat();
        let signature = key.sign(&[b"vouchkit-delegation-v1\0" as &[u8], &body].concat());
        let _ = verifier.verify_delegation(&[body.as_slice(), &signature].concat());
    }
});
