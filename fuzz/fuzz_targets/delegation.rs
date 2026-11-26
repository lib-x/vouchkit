#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use vouchkit_core::{SigningAlgorithm, SigningKey, SigningProvider, SoftwareSigningKey, Verifier};

static KEYS: LazyLock<(SigningKey, SoftwareSigningKey, Verifier)> = LazyLock::new(|| {
    let ed = SigningKey::from_seed(&[17; 32]);
    let p256 = SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &[68; 32])
        .expect("fixed test scalar");
    let verifier =
        Verifier::with_public_keys(&[(254, p256.public_key()), (255, ed.public().into())], None);
    (ed, p256, verifier)
});

fuzz_target!(|data: &[u8]| {
    let (ed, p256, verifier) = &*KEYS;
    let _ = verifier.verify_delegation(data);
    let Some((&format, payload)) = data.split_first() else {
        return;
    };
    if payload.len() > 186 {
        return;
    }
    let Ok(length) = u16::try_from(payload.len()) else {
        return;
    };
    let (header, domain, signer): (&[u8], &[u8], &dyn SigningProvider) = if format & 1 == 0 {
        (&[1, 3, 255], b"vouchkit-delegation-v1\0", ed)
    } else {
        (&[2, 3, 254, 1], b"vouchkit-delegation-v2\0", p256)
    };
    let body = [header, &length.to_be_bytes(), payload].concat();
    let Ok(signature) = signer.try_sign(&[domain, &body].concat()) else {
        return;
    };
    let _ = verifier.verify_delegation(&[body.as_slice(), &signature].concat());
});
