# vouchkit-core

Ed25519-based license format, signing and verification with delegation, leases and revocation. Verification has no network dependencies.

```toml
[dependencies]
vouchkit-core = "0.1"
```

```rust
use vouchkit_core::{Verifier, VerifyOptions, VerifyOutcome};

fn check(
    master_public_key: [u8; 32],
    token: &str,
    unix_seconds: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = Verifier::new(&[(1, master_public_key)], None);
    let opts = VerifyOptions::new("my-product", (1, 2, 0), unix_seconds);
    match verifier.verify(token, &opts)? {
        VerifyOutcome::NeedsActivation(_) => println!("Activate this purchase"),
        outcome => {
            if let Some(license) = outcome.license() {
                println!("Reporting enabled = {}", license.payload().features.contains(1000));
            }
        }
    }
    Ok(())
}
```

Generate the public key and license with the `vouch` command from `vouchkit-cli`. Embed the public key in your app. For expiring credentials, `Verifier::verify_with_store` supports a persisted clock and CRL watermark. Supply `VerifyOptions::device` when verifying a device-bound credential.

Feature slots are inclusive ranges of `u16` IDs. Allocate stable ranges by module and use individual slots for subfeatures. A whole-range grant includes future features you assign to that range.

Optional tags, resource keys and self-tests raise tampering cost. The Ed25519 signature chain is the security boundary. See the [workspace documentation](https://github.com/lib-x/vouchkit) for the protocol and operational limits.
