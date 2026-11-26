# vouchkit

Offline-first software licensing for Rust, built on Ed25519 signatures.

The master private key stays with the author. Sign licenses offline and verify them in your app with the author's public key. For seat limits and automatic renewal, deploy an optional activation server with a short-lived delegation certificate and its matching delegate key. The app verifies the resulting leases locally.

| Crate | Use |
| --- | --- |
| [vouchkit-core](crates/vouchkit-core) | Offline signing and verification, delegation, device proof, feature slots and signed revocation |
| [vouchkit-client](crates/vouchkit-client) | Activation, automatic renewal, device key storage and durable local state |
| [vouchkit-server](crates/vouchkit-server) | Reference Axum and SQLite activation server |
| [vouchkit-cli](crates/vouchkit-cli) | Offline author commands under the `vouch` binary |

## Issue and verify offline

```sh
cargo install vouchkit-cli --locked

vouch keygen --kind master --key-id 1 --out-dir author
vouch issue --key author/master.key.enc --class standalone \
  --product editor --subject "Example customer" --tier 1 \
  --feature-slots 1000-1099,2050 --format file --out license.vk \
  --ledger author/issued.jsonl
vouch verify license.vk --pubkey author/master.pub --product editor
```

Embed the output `PUBLIC_KEYS` table in your app and use `vouchkit-core` to verify a `VK1-` token or armored license file. The [core crate](crates/vouchkit-core) includes a minimal Rust verification example. The CLI encrypts the author seed by default using Argon2id and XChaCha20-Poly1305. When the app needs time or revocation rollback protection, use `verify_with_store` and durable state.

For online use, issue a purchase with `--class entitlement`, deploy only the delegate key, its signed certificate, the trusted master public keys and the current signed CRL, then call `Renewer::activate` from the app. Later checks can use the persisted lease, and `renew_if_needed` schedules renewal with backoff. See the [server configuration](crates/vouchkit-server/config.example.toml) and [examples](examples).

## Feature and device policy

- Allocate stable feature slot IDs across the product's modules. A license grants up to 16 disjoint intervals in the range `0..=65535`. A whole-module interval also grants features added to it later. Issue individual slots when upgrades should require a new grant.
- A standalone license can optionally bind to an Ed25519 device public key. Online activation counts distinct active public keys per purchase. Copying a token preserves the device binding, and exporting its device seed would also copy the device identity. Use a non-exportable signing handle through `DeviceProver` when a hardware-backed key is required.
- An app can opt into a file-backed key or the operating system keyring. Host-supplied `device_hint` is diagnostic metadata. Hardware IDs such as drive serials or MAC addresses can change and should be scoped or hashed locally before being transmitted.
- `Ed25519Signer` supports caller-supplied author and delegate providers. Each provider signs a whole message using pure Ed25519. Keep the master key in author-controlled offline storage or hardware. A delegate can use a server-side HSM or KMS. The version 1 wire format uses Ed25519 for all digital signatures.

## Security boundaries

The Ed25519 signature chain is the authorization boundary. Delegation bounds the product, tier, feature set, issuance window and maximum lease lifetime including grace. The reference server also enforces the original purchase's expiry and grants. Clients that retain the signed entitlement can apply those purchase limits to renewal responses.

A local clock watermark detects system-time rollback while that state survives. Restoring a VM snapshot or rolling back all writable local state can also restore the watermark. Use online activation and a live server decision when strict expiry or authoritative seat counts are required. Offline revocation takes effect when the app sees the new signed CRL, and already-issued leases remain usable after seat deactivation until expiration or revocation.

The optional hardening layer raises the cost of patching. Use different tag slots across releases, verify them from multiple protected call sites, and use the verified capability to decrypt protected resources. A capable attacker can patch a binary, and a legitimate license holder can extract included unlock keys. Treat the layer as an added cost, with protection proportional to the value of the resource.

For deployment choices and signed-format evolution, see the [design review](docs/design.md). The [interoperability vectors](testdata) cover all three license classes, a delegation certificate and a CRL.
