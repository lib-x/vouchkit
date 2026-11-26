use std::{path::Path, time::Duration};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use vouchkit_core::{AppVersion, Id, LicenseError};
use zeroize::Zeroizing;

use crate::ServerError;

const DATABASE_VERSION: u32 = 1;
pub(crate) const CLOCK_SKEW_SECS: u64 = 300;

pub(crate) fn open(path: &Path) -> Result<Connection, ServerError> {
    #[cfg(unix)]
    {
        use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};

        // SQLite creates WAL files using the existing database file's mode.
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
    }
    let mut conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: u32 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        0 => {
            tx.execute_batch(include_str!("schema.sql"))?;
            tx.pragma_update(None, "user_version", DATABASE_VERSION)?;
        }
        DATABASE_VERSION => {}
        _ => {
            return Err(ServerError::Config(
                "unsupported activation database schema",
            ));
        }
    }
    tx.commit()?;
    Ok(conn)
}

pub(crate) fn monotonic_time(tx: &Transaction<'_>, local_now: u64) -> Result<u64, ServerError> {
    let last = last_time(tx)?;
    if local_now.saturating_add(CLOCK_SKEW_SECS) < last {
        return Err(LicenseError::ClockRollback.into());
    }
    if local_now > last {
        tx.execute(
            "UPDATE server_state SET last_seen_time=?1 WHERE id=1",
            [local_now],
        )?;
    }
    Ok(local_now.max(last))
}

pub(crate) fn last_time(conn: &Connection) -> Result<u64, ServerError> {
    Ok(conn.query_row(
        "SELECT last_seen_time FROM server_state WHERE id=1",
        [],
        |r| r.get(0),
    )?)
}

pub(crate) fn stored_crl(conn: &Connection) -> Result<Option<Vec<u8>>, ServerError> {
    Ok(conn.query_row("SELECT crl FROM server_state WHERE id=1", [], |r| r.get(0))?)
}

pub(crate) fn stored_crl_snapshot(conn: &Connection) -> Result<Option<StoredCrl>, ServerError> {
    Ok(conn
        .query_row(
            "SELECT crl_seq, crl FROM server_state WHERE id=1 AND crl_seq IS NOT NULL",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
}

type StoredCrl = ([u8; 8], Vec<u8>);

pub(crate) fn stored_crl_seq(conn: &Connection) -> Result<Option<[u8; 8]>, ServerError> {
    Ok(
        conn.query_row("SELECT crl_seq FROM server_state WHERE id=1", [], |r| {
            r.get(0)
        })?,
    )
}

pub(crate) fn store_crl(tx: &Transaction<'_>, seq: u64, raw: &[u8]) -> Result<(), ServerError> {
    tx.execute(
        "UPDATE server_state SET crl_seq=?1, crl=?2 WHERE id=1",
        params![seq.to_be_bytes(), raw],
    )?;
    Ok(())
}

pub(crate) fn consume_nonce(
    tx: &Transaction<'_>,
    device: &Device,
    nonce: Id,
) -> Result<(), ServerError> {
    let inserted = tx.execute(
        "INSERT INTO request_nonces(entitlement_id, device_pub, nonce) VALUES (?1, ?2, ?3)
         ON CONFLICT DO NOTHING",
        params![device.entitlement_id, device.public, nonce],
    )?;
    if inserted == 0 {
        return Err(LicenseError::Replay.into());
    }
    Ok(())
}

pub(crate) fn entitlement(
    tx: &Transaction<'_>,
    id: Id,
) -> Result<Option<Zeroizing<Vec<u8>>>, ServerError> {
    Ok(tx
        .query_row(
            "SELECT signed_token FROM entitlements WHERE entitlement_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?
        .map(Zeroizing::new))
}

pub(crate) fn store_entitlement(
    tx: &Transaction<'_>,
    id: Id,
    raw: &[u8],
) -> Result<(), ServerError> {
    tx.execute(
        "INSERT INTO entitlements(entitlement_id, signed_token) VALUES (?1, ?2)
         ON CONFLICT DO NOTHING",
        params![id, raw],
    )?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Device {
    pub(crate) entitlement_id: Id,
    pub(crate) public: [u8; 32],
}

pub(crate) fn active_version(
    tx: &Transaction<'_>,
    device: &Device,
) -> Result<Option<AppVersion>, ServerError> {
    let version: Option<u64> = tx
        .query_row(
            "SELECT app_version FROM activations
             WHERE entitlement_id=?1 AND device_pub=?2 AND deactivated_at IS NULL",
            params![device.entitlement_id, device.public],
            |r| r.get(0),
        )
        .optional()?;
    Ok(version.map(unpack_version))
}

pub(crate) fn active_devices(tx: &Transaction<'_>, id: Id) -> Result<u64, ServerError> {
    Ok(tx.query_row(
        "SELECT count(*) FROM activations WHERE entitlement_id=?1 AND deactivated_at IS NULL",
        [id],
        |r| r.get(0),
    )?)
}

pub(crate) fn activate(
    tx: &Transaction<'_>,
    device: &Device,
    version: AppVersion,
    hint: Option<Id>,
    now: u64,
) -> Result<(), ServerError> {
    tx.execute(
        "INSERT INTO activations(entitlement_id, device_pub, first_seen, last_seen,
                                deactivated_at, app_version, device_hint)
         VALUES (?1, ?2, ?3, ?3, NULL, ?4, ?5)
         ON CONFLICT(entitlement_id, device_pub) DO UPDATE SET
            last_seen=excluded.last_seen, deactivated_at=NULL,
            app_version=excluded.app_version, device_hint=excluded.device_hint",
        params![
            device.entitlement_id,
            device.public,
            now,
            pack_version(version),
            hint
        ],
    )?;
    Ok(())
}

pub(crate) fn device_hint(
    tx: &Transaction<'_>,
    device: &Device,
) -> Result<Option<Id>, ServerError> {
    Ok(tx.query_row(
        "SELECT device_hint FROM activations
         WHERE entitlement_id=?1 AND device_pub=?2 AND deactivated_at IS NULL",
        params![device.entitlement_id, device.public],
        |r| r.get(0),
    )?)
}

pub(crate) fn touch(tx: &Transaction<'_>, device: &Device, now: u64) -> Result<(), ServerError> {
    tx.execute(
        "UPDATE activations SET last_seen=?3
         WHERE entitlement_id=?1 AND device_pub=?2 AND deactivated_at IS NULL",
        params![device.entitlement_id, device.public, now],
    )?;
    Ok(())
}

pub(crate) fn register_lease(
    tx: &Transaction<'_>,
    device: &Device,
    id: Id,
    expires_at: u64,
    now: u64,
) -> Result<(), ServerError> {
    // Under continued renewal, prune authorizations that cannot be renewed.
    tx.execute(
        "DELETE FROM issued_leases WHERE entitlement_id=?1 AND device_pub=?2 AND expires_at<=?3",
        params![device.entitlement_id, device.public, now],
    )?;
    tx.execute(
        "INSERT INTO issued_leases(license_id, entitlement_id, device_pub, expires_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![id, device.entitlement_id, device.public, expires_at],
    )?;
    Ok(())
}

pub(crate) fn require_registered_lease(
    tx: &Transaction<'_>,
    device: &Device,
    id: Id,
) -> Result<(), ServerError> {
    let current: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM issued_leases
         WHERE license_id=?1 AND entitlement_id=?2 AND device_pub=?3)",
        params![id, device.entitlement_id, device.public],
        |r| r.get(0),
    )?;
    if !current {
        return Err(LicenseError::Deactivated.into());
    }
    Ok(())
}

pub(crate) fn deactivate(
    tx: &Transaction<'_>,
    device: &Device,
    now: u64,
) -> Result<(), ServerError> {
    tx.execute(
        "UPDATE activations SET deactivated_at=?3, last_seen=?3
         WHERE entitlement_id=?1 AND device_pub=?2 AND deactivated_at IS NULL",
        params![device.entitlement_id, device.public, now],
    )?;
    tx.execute(
        "DELETE FROM issued_leases WHERE entitlement_id=?1 AND device_pub=?2",
        params![device.entitlement_id, device.public],
    )?;
    Ok(())
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
