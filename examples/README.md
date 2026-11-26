# Examples

- [Offline verification](../crates/vouchkit-core/examples/offline_verify.rs) reads a master public key and an issued license. Run it with `cargo run -p vouchkit-core --example offline_verify -- master.pub license.vouch my-product`.
- [Hardware adapter](../crates/vouchkit-core/examples/hardware_device.rs) shows how to connect an Ed25519- or P-256-capable dongle or HSM through `DeviceProver`. The example uses a local test key so it runs without hardware.
- [Offline issuance walkthrough](../crates/vouchkit-cli/examples/offline.sh) generates one offline license and verifies it using `vouch`.
- [Activation integration](../crates/vouchkit-server/tests/activation.rs) starts a temporary server on loopback and exercises the Rust client.
