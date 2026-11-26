#![cfg(feature = "sqlite")]

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use vouchkit_core::{SigningAlgorithm, SigningKey, SigningProvider, SoftwareSigningKey};
use vouchkit_server::{
    ActivationStore, ActivationTransaction, DeviceIdentity, Registration, SqliteActivationStore,
    TransactionControl, TransactionMode,
};

fn transaction<T>(
    store: &SqliteActivationStore,
    mode: TransactionMode,
    operation: impl FnOnce(&mut dyn ActivationTransaction) -> Result<T>,
) -> Result<T> {
    let mut operation = Some(operation);
    let mut outcome = None;
    store.transaction(mode, &mut |tx| {
        let Some(operation) = operation.take() else {
            return TransactionControl::Rollback;
        };
        let result = operation(tx);
        let control = if result.is_ok() {
            TransactionControl::Commit
        } else {
            TransactionControl::Rollback
        };
        outcome = Some(result);
        control
    })?;
    outcome.context("transaction callback")?
}

#[test]
fn schema_v1_keeps_existing_seats_leases_nonces_and_snapshot() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("old.sqlite");
    let id = [3; 16];
    let lease = [4; 16];
    let nonce = [5; 16];
    let hint: Option<[u8; 16]> = Some([6; 16]);
    let old_key = SigningKey::from_seed(&[7; 32]);
    let old_device = DeviceIdentity {
        entitlement_id: id,
        public_key: old_key.public().into(),
    };
    let credential = b"original signed entitlement bytes";
    let revocations = b"original signed CRL bytes";
    let original = Connection::open(&db)?;
    original.pragma_update(None, "foreign_keys", "ON")?;
    original.execute_batch(include_str!("fixtures/schema-v1.sql"))?;
    original.pragma_update(None, "user_version", 1)?;
    original.execute(
        "INSERT INTO entitlements VALUES (?1, ?2)",
        params![id, credential],
    )?;
    original.execute(
        "INSERT INTO activations VALUES (?1, ?2, 100, 200, NULL, 4295098371, ?3)",
        params![id, old_key.public(), hint],
    )?;
    original.execute(
        "INSERT INTO issued_leases VALUES (?1, ?2, ?3, 1000)",
        params![lease, id, old_key.public()],
    )?;
    original.execute(
        "INSERT INTO request_nonces VALUES (?1, ?2, ?3)",
        params![id, old_key.public(), nonce],
    )?;
    original.execute(
        "UPDATE server_state SET last_seen_time=200, crl_seq=?1, crl=?2",
        params![4u64.to_be_bytes(), revocations],
    )?;
    drop(original);

    let store = SqliteActivationStore::open(&db)?;
    let p256 = SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &[8; 32])?;
    let new_device = DeviceIdentity {
        entitlement_id: id,
        public_key: p256.public_key(),
    };
    transaction(&store, TransactionMode::Write, |tx| {
        assert_eq!(tx.last_seen_time()?, 200);
        let crl = tx.crl()?.context("migrated CRL")?;
        assert_eq!(crl.sequence, 4);
        assert_eq!(crl.bytes, revocations);
        assert_eq!(tx.entitlement(id)?.as_deref(), Some(credential.as_slice()));
        assert_eq!(tx.active_devices(id)?, 1);
        let old = tx
            .registration(old_device)?
            .context("migrated registration")?;
        assert_eq!(old.app_version, (1, 2, 3));
        assert_eq!(old.device_hint, hint);
        assert!(tx.has_lease(old_device, lease)?);
        assert!(!tx.insert_nonce(old_device, nonce)?);
        assert!(tx.insert_nonce(new_device, nonce)?);
        tx.activate(
            new_device,
            Registration {
                app_version: (2, 0, 0),
                device_hint: None,
            },
            201,
        )?;
        tx.register_lease(new_device, [9; 16], 1000, 201)?;
        Ok(())
    })?;
    drop(store);

    let store = SqliteActivationStore::open(&db)?;
    transaction(&store, TransactionMode::Write, |tx| {
        assert_eq!(tx.active_devices(id)?, 2);
        assert!(!tx.insert_nonce(new_device, nonce)?);
        assert!(tx.has_lease(new_device, [9; 16])?);
        tx.deactivate(old_device, 202)?;
        assert!(!tx.has_lease(old_device, lease)?);
        assert!(tx.has_lease(new_device, [9; 16])?);
        Ok(())
    })?;
    Ok(())
}
