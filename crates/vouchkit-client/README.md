# vouchkit-client

Activation and lease renewal for vouchkit. An application can verify its cached
lease while the activation server is unreachable. Applications that only need
offline issuance and verification can depend directly on `vouchkit-core`.

```toml
[dependencies]
vouchkit-core = "0.1"
vouchkit-client = { version = "0.1", features = ["reqwest"] }
```

Load the application’s embedded publisher keys and its private state directory,
then call this flow from your async runtime. Call `activate` only when the
customer supplies a purchase credential.

```rust
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use vouchkit_client::{DeviceKey, FileStateStore, Renewer, ReqwestTransport};
use vouchkit_core::{LicenseState, Verifier};

async fn update_license(
    app_data: &Path,
    master_keys: &[(u8, [u8; 32])],
    entitlement: Option<&str>,
) -> Result<LicenseState, Box<dyn std::error::Error>> {
    let mut store = FileStateStore::open(app_data.join("license.state"))?;
    let device = DeviceKey::open_or_create_file(app_data.join("device.key"))?;
    let transport = ReqwestTransport::new("https://activation.example.com")?;
    let verifier = Verifier::new(master_keys, None);
    let mut renewer = Renewer::new(verifier, "editor", (1, 0, 0))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    if let Some(entitlement) = entitlement {
        renewer.activate(now, entitlement, &transport, &mut store, &device).await?;
    }

    if let Err(error) = renewer.renew_if_needed(now, &transport, &mut store, &device).await {
        eprintln!("license renewal: {error}");
    }
    Ok(renewer.state(now, &mut store, &device))
}
```

- Keep a `Renewer` instance for the application session so retry backoff survives
  successive callbacks. Restore its schedule with `verify_cached_lease` after
  startup. Host functions can use the returned `VerifiedLicense` to check
  feature grants.
- Use one state file per device, product and publisher key ring. It stores the
  lease, signed purchase, and the highest observed time and CRL sequence. The
  retained purchase limits the grants and expiry of subsequent leases. An
  imported lease without its signed purchase relies on the certificate and
  existing lease limits. The file holds an exclusive lock while open and
  belongs in a private directory. Offline revocation reflects the most recent
  signed CRL the device has received. Call `refresh_crl` to refresh it outside
  the renewal schedule.
- The default device-key file stores a 32-byte Ed25519 seed with Unix mode 0600.
  The `keyring` feature uses the system credential store on Linux, macOS and
  Windows. For keys that must stay in hardware, implement
  `vouchkit_core::DeviceProver` using your platform’s Ed25519 signing handle.
- The `reqwest` feature supplies the HTTPS transport. Custom integrations can
  implement `Transport`. Authorization is enforced through signatures and
  device proof. The transport also protects the privacy of requests and responses.
