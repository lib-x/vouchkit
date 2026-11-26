# vouchkit-server

Reference activation server for vouchkit, running on a delegated key. Integrate it when an application needs seat limits and short-lived renewals. Apps verify signed leases locally with the author's public key and their device key.

## Run the server

Create the delegate key pair with `vouch keygen --kind delegate --out-dir delegate`. On the offline author machine, sign a certificate with `vouch delegate`. Deploy the author's `master.pub`, the signed `cert.bin` and the delegate's `delegate.key`. Keep the master private key on the offline author machine.

Copy [config.example.toml](config.example.toml) to `config.toml` and set the paths and limits. Relative paths resolve against the configuration file. Run the server:

```sh
cargo install vouchkit-server --locked
vouchkit-server --config config.toml
```

For a container, build from the repository root with
`docker build -f crates/vouchkit-server/Dockerfile -t vouchkit-server .`. Set the
container configuration's `listen` to `0.0.0.0:8080`, choose an absolute database path
under `/data`, mount the state directory there, and mount the configuration and key
files under `/config` with read access for UID 10001. Terminate HTTPS at a trusted
reverse proxy. IP limits use the direct TCP peer address. Configure per-client IP
rate limiting at the proxy and size the backend's peer limit for aggregate traffic,
including health checks.

## Operations

- The API exposes `POST /v1/activate`, `POST /v1/renew`, `POST /v1/deactivate`,
  `GET /v1/crl`, and `GET /healthz`. A successful CRL download returns signed binary
  data. An empty CRL store returns HTTP 204.
- Lease issuance defaults to 14 days with seven days of offline grace. The
  delegation must cover both durations. A dated purchase caps the complete
  validity of its leases. The server rejects renewal beyond a lease's grace
  period, after which a valid purchase can activate again.
- A seat is unique to a purchase and device key. A repeated activation from that
  device keeps the existing seat. Deactivation deletes the registration's renewal
  rights and frees the seat. Already-issued offline leases remain usable until
  expiration or revocation.
- Each purchase ID has one canonical signed entitlement in this database. Use a
  new purchase ID to replace the signed authorization. Request proofs bind the
  operation, signed credential, nonce and relevant request fields. Durable
  nonce history prevents replay across restarts. Because permanent purchases
  have no freshness deadline, those records grow with authenticated request
  volume and must be retained to preserve this guarantee.
- Deploy fresh author-signed CRLs atomically to the configured path. The process
  checks for updates every 30 seconds and stores the highest signed revision
  in SQLite. Copy the persisted database using SQLite's backup API or stop the
  process first. Restoring a database snapshot also restores its seat, replay
  and revocation state, so keep the newest signed CRL available during recovery.
- Rotate the delegation certificate before its signing window closes. The
  health endpoint reports the remaining days, and the process begins emitting
  warnings 14 days before expiry. Include previous master public keys while
  existing author-issued credentials continue to use them.

Use a local disk or volume for SQLite. The service creates a new database with
mode 0600 on Unix. Restrict access to the database directory and its backups,
which contain signed entitlements and device registration metadata. The
transaction protects concurrent seat allocation against a single database. Separate database files have independent
seat counts.

## Custom delegated signer

An embedding application can pass an `Ed25519Signer` to
`ActivationServer::load_with_delegate`. Use it for a non-exportable Ed25519
provider that can sign the exact protocol transcript, such as an HSM with
Ed25519 support. The provider's public key must match `cert.bin`. Configure a
bounded signing deadline for the provider, since signing participates in the
atomic seat transaction. The bundled binary uses the file or environment
configuration shown above.
