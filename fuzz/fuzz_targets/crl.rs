#![no_main]

use libfuzzer_sys::fuzz_target;
use vouchkit_core::{SigningKey, Verifier};

fuzz_target!(|data: &[u8]| {
    let key = SigningKey::from_seed(&[17; 32]);
    let verifier = Verifier::new(&[(255, key.public())], None);
    let _ = verifier.verify_crl(data);
    if data.len() <= vouchkit_core::protocol::MAX_CRL_BYTES {
        let Ok(length) = u32::try_from(data.len()) else {
            return;
        };
        let body = [&[1, 2, 255][..], &length.to_be_bytes(), data].concat();
        let signature = key.sign(&[b"vouchkit-crl-v1\0" as &[u8], &body].concat());
        let _ = verifier.verify_crl(&[body.as_slice(), &signature].concat());
    }
});
