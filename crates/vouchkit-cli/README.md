# vouchkit-cli

The `vouch` command-line tool for issuing, inspecting, verifying and revoking licenses. Every command runs offline.

## Issue and verify an offline license

```sh
cargo install --path crates/vouchkit-cli
vouch keygen --kind master --key-id 1 --out-dir author

vouch issue --key author/master.key.enc --class standalone \
  --product demo --subject "Example customer" --tier 1 \
  --features 0x08 --feature-slots 64,100-105 --max-version 2.x.x \
  --format file --out customer.vk --ledger author/issued.jsonl

vouch verify customer.vk --pubkey author/master.pub --product demo --app-version 2.4.0
vouch inspect customer.vk
```

Key generation prompts for a passphrase and creates `master.key.enc`, `master.pub`, and `public_keys.rs`. Keep the encrypted key and its passphrase under the author's control. For new keys, add `--algorithm p256` to select ECDSA P-256. Without this flag, `vouch` generates Ed25519 keys in the original file formats. Load generated P-256 public key constants with `Verifier::with_public_keys` in your Rust application. For unattended use, set `--passphrase-file FILE` to an owner-only file. A final LF or CRLF in this file is ignored. On Unix the tool requires owner-only permissions for private key and passphrase files. The explicit `--insecure-plaintext` flag writes `master.key` and is convenient for disposable examples.

The first verification prints `Active`. An entitlement prints `NeedsActivation`. For bound licenses, `--device-key FILE` accepts the client's file-based device key. Ed25519 uses a raw 32-byte seed. P-256 uses the ASCII marker `VOUCHKIT-DEVICE-P256-2` followed by a NUL and a 32-byte scalar. `inspect` prints unverified metadata and resource-key IDs. `verify` authenticates the signature chain and applies the CRL when `--crl FILE` is supplied. Pass a file path for real credentials to keep them out of shell history and process arguments.

The [offline example](examples/offline.sh) can be run with `sh examples/offline.sh` after installing `vouch`. It uses one disposable directory and an ephemeral master key.

## Issue a delegated online purchase

```sh
vouch keygen --kind delegate --out-dir activation
vouch delegate --key author/master.key.enc --delegate-pub activation/delegate.pub \
  --product demo --valid-days 90 --max-lease 35d --max-tier 2 \
  --feature-mask 0x08 --feature-slots 64,100-105 \
  --out activation/cert.bin --ledger author/issued.jsonl

vouch issue --key author/master.key.enc --class entitlement \
  --product demo --subject "Example subscriber" --tier 2 \
  --features 0x08 --feature-slots 64 --max-devices 2 \
  --format file --out purchase.vk --ledger author/issued.jsonl
```

To issue with a P-256 delegate, add `--algorithm p256` when generating the delegate key. Master and delegate keys can use different algorithms. Ed25519 public keys keep the existing Base64 form. P-256 uses `p256:<base64>` or `<id>:p256:<base64>` for a master key. Use the tagged form with `--device-pub`.

Deploy `activation/delegate.key`, `activation/cert.bin`, and `author/master.pub` to the activation service. Install the current signed CRL when one exists. The certificate's lease duration includes offline grace, and authorizes only its signed feature slots and tiers.

`--features` and `--feature-mask` accept a hexadecimal mask for slots 0–31. `--feature-slots` adds decimal IDs or inclusive ranges through 65535, with up to 16 disjoint intervals after adjacent ranges are merged. Give entire ranges only when you intend to authorize their future slots. `--unlock 3,64` adds keys only for already-granted features. Use `vouch seal-asset` to encrypt resources with one of these derived keys and `vouch profile` with `--slots 1,4,6` to generate per-build tag configuration. Build profiles and resource keys raise reverse-engineering costs. Ed25519 signatures and delegation limits enforce authorization. The CLI supports resource files up to 64 MiB.

## Revoke a credential

```sh
vouch ledger list --ledger author/issued.jsonl
vouch revoke --key author/master.key.enc --ledger author/issued.jsonl \
  --entitlement <entitlement-id-from-ledger> --out crl.bin
```

Use `--license ID` for a ledgered license or `--lease FILE` for an authenticated server-issued lease. `--cert ID --since UNIX_SECONDS` revokes leases from that certificate issued at or after the cutoff. Revocation validates the identifiers against the issuance ledger. Keep `issued.jsonl` and its `issued.jsonl.crl` sidecar together as the authoritative state. The sidecar preserves a monotonically increasing sequence when the exported file is moved or changed. Back it up with the ledger and pass prior `--pubkey` files to authenticate an existing CRL when rotating the master key. Exchange credentials and CRLs using their documented file encodings.
