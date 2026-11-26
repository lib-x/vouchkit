# Specification mapping

The repository started with no source implementation. Observable behavior comes from the supplied specification and its acceptance scenarios.

| Spec behavior | Rust implementation and coverage |
| --- | --- |
| Binary envelopes, standalone licenses, purchases, delegation and CRLs | `vouchkit-core` and the fixed OpenSSL-generated fixtures under `testdata/` |
| Purpose-bound device challenges and request parsing | `DeviceProver`, shared DTOs and tests in `vouchkit-core`, plus parser fuzz targets |
| Activation, renewal, seats, deactivation and revocation | Reference server and client, covered by loopback tests with temporary SQLite |
| Rollback and offline grace | Core verification options, client `StateStore` and state-machine tests |
| Offline author tools and key storage | `vouchkit-cli` integration tests covering issuance, wrong passphrase and cumulative revocation |
| Per-build hardening and feature resources | Core tag, asset and verifier self-test coverage |

The first release starts with `VK1-`. The design uses extensible feature intervals, operation-bound activation proofs and a total lease lifetime that includes grace. [Design details](docs/design.md)
