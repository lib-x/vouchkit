CREATE TABLE entitlements (
    entitlement_id BLOB PRIMARY KEY NOT NULL CHECK(length(entitlement_id) = 16),
    signed_token BLOB NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE activations (
    entitlement_id BLOB NOT NULL REFERENCES entitlements,
    device_pub BLOB NOT NULL CHECK(length(device_pub) = 32),
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    deactivated_at INTEGER,
    app_version INTEGER NOT NULL,
    device_hint BLOB CHECK(device_hint IS NULL OR length(device_hint) = 16),
    PRIMARY KEY(entitlement_id, device_pub)
) STRICT, WITHOUT ROWID;

CREATE INDEX active_seats ON activations(entitlement_id) WHERE deactivated_at IS NULL;

CREATE TABLE issued_leases (
    license_id BLOB PRIMARY KEY NOT NULL CHECK(length(license_id) = 16),
    entitlement_id BLOB NOT NULL,
    device_pub BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(entitlement_id, device_pub) REFERENCES activations
) STRICT, WITHOUT ROWID;

CREATE INDEX issued_leases_by_device ON issued_leases(entitlement_id, device_pub, expires_at);

CREATE TABLE request_nonces (
    entitlement_id BLOB NOT NULL CHECK(length(entitlement_id) = 16),
    device_pub BLOB NOT NULL CHECK(length(device_pub) = 32),
    nonce BLOB NOT NULL CHECK(length(nonce) = 16),
    PRIMARY KEY(entitlement_id, device_pub, nonce)
) STRICT, WITHOUT ROWID;

CREATE TABLE server_state (
    id INTEGER PRIMARY KEY NOT NULL CHECK(id = 1),
    last_seen_time INTEGER NOT NULL,
    crl_seq BLOB CHECK(crl_seq IS NULL OR length(crl_seq) = 8),
    crl BLOB,
    CHECK((crl_seq IS NULL) = (crl IS NULL))
) STRICT;

INSERT INTO server_state(id, last_seen_time) VALUES (1, 0);
