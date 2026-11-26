# vouchkit

[English](README.md) · [简体中文](README.zh-CN.md)

[![vouchkit-core on crates.io](https://img.shields.io/crates/v/vouchkit-core.svg?label=vouchkit-core)](https://crates.io/crates/vouchkit-core)
[![vouchkit-cli on crates.io](https://img.shields.io/crates/v/vouchkit-cli.svg?label=vouchkit-cli)](https://crates.io/crates/vouchkit-cli)
[![vouchkit-client on crates.io](https://img.shields.io/crates/v/vouchkit-client.svg?label=vouchkit-client)](https://crates.io/crates/vouchkit-client)
[![vouchkit-server on crates.io](https://img.shields.io/crates/v/vouchkit-server.svg?label=vouchkit-server)](https://crates.io/crates/vouchkit-server)

Offline-first software licensing for Rust, with pluggable signing providers and built-in Ed25519 and ECDSA P-256.

The master private key stays with the author. Issue licenses offline and verify them in your app with the master's public key. For online activation and renewal, deploy a service with a short-lived delegation certificate and its matching signer. The app can still verify the resulting lease offline.

| Crate | Use |
| --- | --- |
| [vouchkit-core](crates/vouchkit-core) | Credential encoding, signing, local verification, delegation, device proof, feature slots and revocation |
| [vouchkit-cli](crates/vouchkit-cli) | Offline author operations through the `vouch` command |
| [vouchkit-client](crates/vouchkit-client) | Optional online activation, renewal, device keys and durable client state |
| [vouchkit-server](crates/vouchkit-server) | Optional activation and seat policy, with pluggable storage and an Axum reference service |

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

Embed the master public key in your app and use `vouchkit-core` to validate a token or an armored license file. The [core README](crates/vouchkit-core) has a minimal Rust example. The CLI encrypts the author key by default using Argon2id and XChaCha20-Poly1305. For expiring credentials or signed revocation, use durable state with `Verifier::verify_with_store`.

Key generation defaults to Ed25519. Use `vouch keygen --algorithm p256` when you need ECDSA P-256. Credentials whose entire signing chain and device binding use Ed25519 retain the original `VK1-` format. The verifier also accepts `VK2-` credentials and supports mixed Ed25519 and P-256 chains.

## Runtime extensions

- Supply a `SigningProvider` for author or delegate operations, or a `DeviceProver` for software and hardware device keys. Implementations can be selected at runtime. Ed25519 and ECDSA P-256 are the two built-in wire algorithms. Keep the master key in author-controlled offline storage or hardware. A delegate can use a server-side HSM or KMS.
- Issue an entitlement and use `Renewer::activate` and `renew_if_needed` for online activation. The transport is pluggable. Install the signed delegation certificate, matching signer, trusted master public keys and current CRL on your activation service.
- Embed the activation engine with an `ActivationStore` implementation of your choice. SQLite is the default packaged reference backend and can be disabled at compile time. The reference binary also provides an in-memory backend for disposable deployments. Production seat counts and replay protection across restarts require a durable transaction backend.

Configuration and runnable examples are available in the [server crate](crates/vouchkit-server) and [examples directory](examples).

## Upgrade from 0.1

Existing Ed25519 keys and `VK1-` licenses remain valid. Existing `DeviceProver` implementations return `PublicKey` in 0.2. For an Ed25519 public key, return `raw_public_key.into()`. The SQLite backend upgrades existing databases on startup. Back up the database before upgrading.

## Feature and device policy

- Allocate stable feature IDs by module. A license grants up to 16 disjoint intervals in `0..=65535`. A whole-module interval also grants features later assigned to the interval.
- A standalone license can bind to a device public key. Online activation counts distinct active device keys per purchase. Copying a token preserves the device binding. Exporting its device private key copies the device identity. A non-exportable hardware key can provide device signing through `DeviceProver`.
- A soft device hint can support diagnostics. Hardware IDs such as drive serials and MAC addresses can change. If the host uses them to derive a hint, scope or hash the inputs locally before transmission.

## Security boundaries

The digital signature chain defines the authorization boundary. Delegation bounds the product, tier, feature set, issuance window and maximum lease lifetime including offline grace. The activation engine enforces the original purchase's expiry and grants. Clients that retain the signed entitlement can apply those limits to renewals.

A local clock watermark detects rollback while its state survives. Restoring all writable state or a VM snapshot can restore the watermark as well. Use a live server decision when strict expiry or authoritative seat counts are required. Offline revocation takes effect when the application sees the signed CRL. Deactivated seats stop renewing, and leases already issued remain usable until expiration or revocation.

The optional hardening layer raises patching cost. Use build-specific tag slots and resource keys at multiple protected call sites. A capable attacker can patch the binary, and a legitimate holder can extract included unlock keys.

See the [design review](docs/design.md) and [interoperability vectors](testdata).
