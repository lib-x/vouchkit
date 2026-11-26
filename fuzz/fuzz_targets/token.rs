#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use vouchkit_core::{
    PublicKey, SigningKey, Verifier, VerifyOptions, decode_token, inspect_license,
};

static VERIFIER: LazyLock<Verifier> = LazyLock::new(|| {
    Verifier::with_public_keys(
        &[
            (
                254,
                PublicKey::P256(*include_bytes!(
                    "../../crates/vouchkit-core/src/self-test-p256.pub"
                )),
            ),
            (255, SigningKey::from_seed(&[17; 32]).public().into()),
        ],
        None,
    )
});

fuzz_target!(|data: &[u8]| {
    let _ = inspect_license(data);
    let opts = VerifyOptions::new("vouchkit-self-test", (1, 0, 0), 1_700_000_001);
    let _ = VERIFIER.verify_bytes(data, &opts);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = decode_token(text);
        let _ = VERIFIER.verify(text, &opts);
    }
});
