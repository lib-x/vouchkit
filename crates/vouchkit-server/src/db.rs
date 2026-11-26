use std::{path::Path, sync::Mutex, time::Duration};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use vouchkit_core::{AppVersion, Id};

use crate::{
    ActivationStore, ActivationTransaction, DeviceIdentity, Registration, StoreError, StoredCrl,
    TransactionControl, TransactionMode,
};

const DATABASE_VERSION: u32 = 2;

/// Durable reference activation store using SQLite transactions.
///
/// Instances using the same local database share a seat limit, replay state,
/// clock and CRLs. Transactions use SQLite's immediate write lock to serialize
/// count-and-insert operations across processes.
pub struct SqliteActivationStore {
    connection: Mutex<Connection>,
}

impl std::fmt::Debug for SqliteActivationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SqliteActivationStore")
            .finish_non_exhaustive()
    }
}

impl SqliteActivationStore {
    /// Opens the database and applies supported schema migrations atomically.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable storage or an unsupported schema version.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        #[cfg(unix)]
        {
            use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

            // SQLite creates WAL files using the existing database file's mode.
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(StoreError::backend)?;
        }
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        match version {
            0 => tx.execute_batch(include_str!("schema.sql"))?,
            1 => tx.execute_batch(include_str!("schema-v1-to-v2.sql"))?,
            DATABASE_VERSION => {}
            _ => {
                return Err(StoreError::InvalidState(
                    "unsupported activation database schema",
                ));
            }
        }
        if version != DATABASE_VERSION {
            tx.pragma_update(None, "user_version", DATABASE_VERSION)?;
        }
        tx.commit()?;
        Ok(Self {
            connection: Mutex::new(conn),
        })
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::backend(error)
    }
}

impl ActivationStore for SqliteActivationStore {
    fn transaction(
        &self,
        mode: TransactionMode,
        operation: &mut dyn FnMut(&mut dyn ActivationTransaction) -> TransactionControl,
    ) -> Result<(), StoreError> {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| StoreError::InvalidState("activation mutex poisoned"))?;
        let behavior = match mode {
            TransactionMode::Read => TransactionBehavior::Deferred,
            TransactionMode::Write => TransactionBehavior::Immediate,
        };
        let tx = conn.transaction_with_behavior(behavior)?;
        let control = operation(&mut SqliteTransaction {
            connection: &tx,
            mode,
        });
        match control {
            TransactionControl::Commit => tx.commit()?,
            TransactionControl::Rollback => tx.rollback()?,
        }
        Ok(())
    }
}

struct SqliteTransaction<'a> {
    connection: &'a Connection,
    mode: TransactionMode,
}

impl SqliteTransaction<'_> {
    fn writer(&self) -> Result<&Connection, StoreError> {
        if self.mode == TransactionMode::Read {
            return Err(StoreError::ReadOnly);
        }
        Ok(self.connection)
    }
}

impl ActivationTransaction for SqliteTransaction<'_> {
    fn last_seen_time(&self) -> Result<u64, StoreError> {
        let seen = self.connection.query_row(
            "SELECT last_seen_time FROM server_state WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        Ok(seen)
    }

    fn set_last_seen_time(&mut self, time: u64) -> Result<(), StoreError> {
        self.writer()?.execute(
            "UPDATE server_state SET last_seen_time=?1 WHERE id=1",
            [time],
        )?;
        Ok(())
    }

    fn crl_sequence(&self) -> Result<Option<u64>, StoreError> {
        let seq: Option<[u8; 8]> =
            self.connection
                .query_row("SELECT crl_seq FROM server_state WHERE id=1", [], |r| {
                    r.get(0)
                })?;
        Ok(seq.map(u64::from_be_bytes))
    }

    fn crl(&self) -> Result<Option<StoredCrl>, StoreError> {
        let crl = self
            .connection
            .query_row(
                "SELECT crl_seq, crl FROM server_state WHERE id=1 AND crl_seq IS NOT NULL",
                [],
                |r| {
                    Ok(StoredCrl {
                        sequence: u64::from_be_bytes(r.get(0)?),
                        bytes: r.get(1)?,
                    })
                },
            )
            .optional()?;
        Ok(crl)
    }

    fn set_crl(&mut self, sequence: u64, bytes: &[u8]) -> Result<(), StoreError> {
        self.writer()?.execute(
            "UPDATE server_state SET crl_seq=?1, crl=?2 WHERE id=1",
            params![sequence.to_be_bytes(), bytes],
        )?;
        Ok(())
    }

    fn insert_nonce(&mut self, device: DeviceIdentity, nonce: Id) -> Result<bool, StoreError> {
        let inserted = self.writer()?.execute(
            "INSERT INTO request_nonces(entitlement_id, device_pub, nonce) VALUES (?1, ?2, ?3)
             ON CONFLICT DO NOTHING",
            params![device.entitlement_id, device.public_key.as_bytes(), nonce],
        )?;
        Ok(inserted != 0)
    }

    fn entitlement(&self, id: Id) -> Result<Option<Vec<u8>>, StoreError> {
        let token = self
            .connection
            .query_row(
                "SELECT signed_token FROM entitlements WHERE entitlement_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(token)
    }

    fn insert_entitlement(&mut self, id: Id, token: &[u8]) -> Result<(), StoreError> {
        self.writer()?.execute(
            "INSERT INTO entitlements(entitlement_id, signed_token) VALUES (?1, ?2)
             ON CONFLICT DO NOTHING",
            params![id, token],
        )?;
        Ok(())
    }

    fn registration(&self, device: DeviceIdentity) -> Result<Option<Registration>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT app_version, device_hint FROM activations
             WHERE entitlement_id=?1 AND device_pub=?2 AND deactivated_at IS NULL",
                params![device.entitlement_id, device.public_key.as_bytes()],
                |r| {
                    Ok(Registration {
                        app_version: unpack_version(r.get(0)?),
                        device_hint: r.get(1)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    fn active_devices(&self, id: Id) -> Result<u64, StoreError> {
        let count = self.connection.query_row(
            "SELECT count(*) FROM activations WHERE entitlement_id=?1 AND deactivated_at IS NULL",
            [id],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    fn activate(
        &mut self,
        device: DeviceIdentity,
        registration: Registration,
        now: u64,
    ) -> Result<(), StoreError> {
        self.writer()?.execute(
            "INSERT INTO activations(entitlement_id, device_pub, first_seen, last_seen,
                                    deactivated_at, app_version, device_hint)
             VALUES (?1, ?2, ?3, ?3, NULL, ?4, ?5)
             ON CONFLICT(entitlement_id, device_pub) DO UPDATE SET
                last_seen=excluded.last_seen, deactivated_at=NULL,
                app_version=excluded.app_version, device_hint=excluded.device_hint",
            params![
                device.entitlement_id,
                device.public_key.as_bytes(),
                now,
                pack_version(registration.app_version),
                registration.device_hint
            ],
        )?;
        Ok(())
    }

    fn touch(&mut self, device: DeviceIdentity, now: u64) -> Result<(), StoreError> {
        self.writer()?.execute(
            "UPDATE activations SET last_seen=?3
             WHERE entitlement_id=?1 AND device_pub=?2 AND deactivated_at IS NULL",
            params![device.entitlement_id, device.public_key.as_bytes(), now],
        )?;
        Ok(())
    }

    fn register_lease(
        &mut self,
        device: DeviceIdentity,
        lease_id: Id,
        expires_at: u64,
        now: u64,
    ) -> Result<(), StoreError> {
        let writer = self.writer()?;
        // Insert first so that even an expired ID already in the table cannot be reused.
        writer.execute(
            "INSERT INTO issued_leases(license_id, entitlement_id, device_pub, expires_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                lease_id,
                device.entitlement_id,
                device.public_key.as_bytes(),
                expires_at
            ],
        )?;
        writer.execute(
            "DELETE FROM issued_leases WHERE entitlement_id=?1 AND device_pub=?2 AND expires_at<=?3",
            params![device.entitlement_id, device.public_key.as_bytes(), now],
        )?;
        Ok(())
    }

    fn has_lease(&self, device: DeviceIdentity, lease_id: Id) -> Result<bool, StoreError> {
        let current = self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM issued_leases
             WHERE license_id=?1 AND entitlement_id=?2 AND device_pub=?3)",
            params![
                lease_id,
                device.entitlement_id,
                device.public_key.as_bytes()
            ],
            |r| r.get(0),
        )?;
        Ok(current)
    }

    fn deactivate(&mut self, device: DeviceIdentity, now: u64) -> Result<(), StoreError> {
        let writer = self.writer()?;
        writer.execute(
            "UPDATE activations SET deactivated_at=?3, last_seen=?3
             WHERE entitlement_id=?1 AND device_pub=?2 AND deactivated_at IS NULL",
            params![device.entitlement_id, device.public_key.as_bytes(), now],
        )?;
        writer.execute(
            "DELETE FROM issued_leases WHERE entitlement_id=?1 AND device_pub=?2",
            params![device.entitlement_id, device.public_key.as_bytes()],
        )?;
        Ok(())
    }
}

fn pack_version((major, minor, patch): AppVersion) -> u64 {
    (u64::from(major) << 32) | (u64::from(minor) << 16) | u64::from(patch)
}

fn unpack_version(version: u64) -> AppVersion {
    let [_, _, a, b, c, d, e, f] = version.to_be_bytes();
    (
        u16::from_be_bytes([a, b]),
        u16::from_be_bytes([c, d]),
        u16::from_be_bytes([e, f]),
    )
}
