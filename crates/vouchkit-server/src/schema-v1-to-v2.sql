CREATE TABLE activations_v2 (
    entitlement_id BLOB NOT NULL REFERENCES entitlements,
    device_pub BLOB NOT NULL CHECK(length(device_pub) IN (32, 33)),
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    deactivated_at INTEGER,
    app_version INTEGER NOT NULL,
    device_hint BLOB CHECK(device_hint IS NULL OR length(device_hint) = 16),
    PRIMARY KEY(entitlement_id, device_pub)
) STRICT, WITHOUT ROWID;

CREATE TABLE issued_leases_v2 (
    license_id BLOB PRIMARY KEY NOT NULL CHECK(length(license_id) = 16),
    entitlement_id BLOB NOT NULL,
    device_pub BLOB NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY(entitlement_id, device_pub) REFERENCES activations_v2
) STRICT, WITHOUT ROWID;

CREATE TABLE request_nonces_v2 (
    entitlement_id BLOB NOT NULL CHECK(length(entitlement_id) = 16),
    device_pub BLOB NOT NULL CHECK(length(device_pub) IN (32, 33)),
    nonce BLOB NOT NULL CHECK(length(nonce) = 16),
    PRIMARY KEY(entitlement_id, device_pub, nonce)
) STRICT, WITHOUT ROWID;

INSERT INTO activations_v2 SELECT * FROM activations;
INSERT INTO issued_leases_v2 SELECT * FROM issued_leases;
INSERT INTO request_nonces_v2 SELECT * FROM request_nonces;

DROP TABLE issued_leases;
DROP TABLE activations;
DROP TABLE request_nonces;

ALTER TABLE activations_v2 RENAME TO activations;
ALTER TABLE issued_leases_v2 RENAME TO issued_leases;
ALTER TABLE request_nonces_v2 RENAME TO request_nonces;

CREATE INDEX active_seats ON activations(entitlement_id) WHERE deactivated_at IS NULL;
CREATE INDEX issued_leases_by_device ON issued_leases(entitlement_id, device_pub, expires_at);
