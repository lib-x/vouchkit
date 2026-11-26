//! Optional HTTP activation with SQLite-backed seats and delegated lease signing.

mod config;
mod db;
mod http;
mod rate_limit;

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::Router;
use rusqlite::{Connection, Transaction, TransactionBehavior};
use thiserror::Error;
use tokio::sync::Semaphore;
use vouchkit_core::{
    AppVersion, Class, Crl, DelegationCert, Ed25519Signer, Id, LicenseError, LicensePayload,
    SignedLicense, Verifier, decode_token, encode_token,
    protocol::{ActivateRequest, DeactivateRequest, LeaseResponse, RenewRequest},
    random_bytes, sign_lease,
};
use zeroize::Zeroizing;

pub use config::ServerConfig;
use config::{DAY_SECS, MAX_CRL_BYTES, is_missing, read_limited};
use db::Device;
use rate_limit::{Limits, lock};

const MAX_PENDING_REQUESTS: usize = 32;
const EXPIRY_WARNING_DAYS: u64 = 14;
const MAX_SQLITE_TIMESTAMP: u64 = i64::MAX.unsigned_abs();

/// A configuration, storage, or delegated issuance failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServerError {
    /// A configured file could not be read or the listener could not start.
    #[error("server I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Required settings could not be applied.
    #[error("{0}")]
    Config(&'static str),
    /// SQLite rejected an activation state operation.
    #[error("activation database operation failed")]
    Database(#[from] rusqlite::Error),
    /// The license or its proof did not satisfy server policy.
    #[error(transparent)]
    License(#[from] LicenseError),
    /// A signed CRL conflicted with the one already stored at that sequence.
    #[error("conflicting revocation lists share a sequence number")]
    CrlConflict,
    /// The delegation certificate is outside its issuance window.
    #[error("delegation certificate is not active")]
    CertificateInactive,
    /// The request exceeded a configured rate limit.
    #[error("activation rate limit exceeded")]
    RateLimited,
    /// A worker or lock failed.
    #[error("activation state worker unavailable")]
    Poisoned,
    /// The current clock did not yield a usable Unix time.
    #[error("system clock is before the Unix epoch")]
    Clock,
}

/// A cloneable activation service backed by a delegated signing provider.
#[derive(Clone)]
pub struct ActivationServer {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ActivationServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivationServer")
            .field("product", &self.inner.cert.product)
            .field("cert_id", &self.inner.cert.cert_id)
            .finish_non_exhaustive()
    }
}

struct Inner {
    verifier: Verifier,
    delegate: Box<dyn Ed25519Signer + Send + Sync>,
    cert_key_id: u8,
    cert: DelegationCert,
    cert_bytes: Vec<u8>,
    lease_secs: u64,
    grace_secs: u32,
    storage: Mutex<Storage>,
    limits: Limits,
    http_slots: Arc<Semaphore>,
}

struct Storage {
    conn: Connection,
    crl: Option<Crl>,
}

impl ActivationServer {
    /// Opens the SQLite state and validates the delegate's author-signed certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if any key, certificate, rate limit, CRL or database is invalid.
    pub fn load(config: &ServerConfig) -> Result<Self, ServerError> {
        Self::load_with_delegate(config, config.read_delegate()?)
    }

    /// Opens the service with a caller-provided Ed25519 delegate signing provider.
    ///
    /// The provider owns private-key custody and is called on a blocking worker.
    /// Supply a provider with bounded signing latency to protect concurrent issuance.
    /// The local delegate file and environment settings are unused with this constructor.
    ///
    /// # Errors
    ///
    /// Returns an error if the provider's public key differs from the signed certificate
    /// or if the configured trust roots, certificate, limits or database are invalid.
    pub fn load_with_delegate(
        config: &ServerConfig,
        delegate: impl Ed25519Signer + Send + Sync + 'static,
    ) -> Result<Self, ServerError> {
        let verifier = Verifier::new(&config.read_master_keys()?, None);
        let cert_bytes = read_limited(&config.delegation_cert, 512)?;
        let (cert_key_id, cert) = verifier.verify_delegation(&cert_bytes)?;
        if cert.delegate_pub != delegate.public() {
            return Err(ServerError::Config(
                "delegate private key does not match delegation certificate",
            ));
        }
        if config.lease_secs == 0 {
            return Err(ServerError::Config("lease lifetime must be positive"));
        }
        let total_seconds = config.lease_secs.checked_add(u64::from(config.grace_secs));
        if total_seconds.is_none_or(|seconds| seconds > cert.max_lease_secs) {
            return Err(ServerError::Config(
                "configured lease lifetime and grace exceed the delegation certificate",
            ));
        }

        let conn = db::open(&config.database)?;
        let crl = load_stored_crl(&conn, &verifier)?;
        let has_crl = crl.is_some();
        let server = Self {
            inner: Arc::new(Inner {
                verifier,
                delegate: Box::new(delegate),
                cert_key_id,
                cert,
                cert_bytes,
                lease_secs: config.lease_secs,
                grace_secs: config.grace_secs,
                storage: Mutex::new(Storage { conn, crl }),
                limits: Limits::new(
                    config.requests_per_ip_per_minute,
                    config.requests_per_entitlement_per_minute,
                    config.requests_per_minute,
                )?,
                http_slots: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            }),
        };

        if let Some(path) = &config.crl {
            if has_crl && is_missing(path)? {
                tracing::warn!(
                    "configured revocation file unavailable, using persisted signed CRL"
                );
            } else {
                server.install_crl_file(path)?;
            }
        }
        Ok(server)
    }

    /// Creates the activation HTTP router. Supply TCP connection info when serving it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::{net::SocketAddr, path::Path};
    /// use vouchkit_server::{ActivationServer, ServerConfig};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ServerConfig::load(Path::new("config.toml"))?;
    /// let service = ActivationServer::load(&config)?;
    /// let listener = tokio::net::TcpListener::bind(config.listen()).await?;
    /// axum::serve(
    ///     listener,
    ///     service.router().into_make_service_with_connect_info::<SocketAddr>(),
    /// )
    /// .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn router(&self) -> Router {
        http::router(self.clone())
    }

    /// Authenticates an on-disk author-signed CRL and installs it if newer.
    ///
    /// # Errors
    ///
    /// Returns an error for unreadable, invalid or rolled-back CRLs.
    pub fn install_crl_file(&self, path: &Path) -> Result<bool, ServerError> {
        self.install_crl(&read_limited(path, MAX_CRL_BYTES)?)
    }

    /// Persists an author-signed CRL before serving its state to any client.
    ///
    /// Returns `false` when the identical signed CRL is already installed.
    ///
    /// # Errors
    ///
    /// Returns an error if signature verification, rollback protection or storage fails.
    pub fn install_crl(&self, bytes: &[u8]) -> Result<bool, ServerError> {
        let crl = self.inner.verifier.verify_crl(bytes)?;
        if crl.seq == 0 {
            return Err(LicenseError::Malformed.into());
        }
        let mut storage = lock(&self.inner.storage)?;
        let tx = storage
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;

        if let Some(stored_seq) = db::stored_crl_seq(&tx)? {
            match crl.seq.cmp(&u64::from_be_bytes(stored_seq)) {
                std::cmp::Ordering::Less => return Err(LicenseError::CrlRollback.into()),
                std::cmp::Ordering::Equal => {
                    let same = db::stored_crl(&tx)?.as_deref() == Some(bytes);
                    return if same {
                        Ok(false)
                    } else {
                        Err(ServerError::CrlConflict)
                    };
                }
                std::cmp::Ordering::Greater => {}
            }
        }

        db::store_crl(&tx, crl.seq, bytes)?;
        tx.commit()?;
        storage.crl = Some(crl);
        Ok(true)
    }

    /// Logs a warning when the certificate needs operator attention.
    ///
    /// # Errors
    ///
    /// Returns an error when certificate health cannot be determined.
    pub fn warn_if_certificate_expiring(&self) -> Result<(), ServerError> {
        let health = self.health()?;
        if health.status != "ok" || health.certificate_remaining_days <= EXPIRY_WARNING_DAYS {
            tracing::warn!(
                status = health.status,
                remaining_days = health.certificate_remaining_days,
                "check delegation certificate validity"
            );
        }
        Ok(())
    }

    fn activate(&self, request: &ActivateRequest) -> Result<LeaseResponse, ServerError> {
        let purchase = self.inner.entitlement(&request.entitlement_token)?;
        let entitlement_id = purchase.payload().entitlement_id;
        request.verify_proof(entitlement_id)?;
        let device = Device {
            entitlement_id,
            public: request.device_pub,
        };
        self.inner
            .run_request(&device, request.nonce, |tx, context| {
                self.inner
                    .check_entitlement(&purchase, request.app_version, &context)?;
                if let Some(stored) = db::entitlement(tx, entitlement_id)?
                    && stored.as_slice() != purchase.bytes()
                {
                    return Err(LicenseError::Malformed.into());
                }
                let max_devices = u64::from(purchase.payload().max_devices);
                if db::active_version(tx, &device)?.is_none()
                    && db::active_devices(tx, entitlement_id)? >= max_devices
                {
                    return Err(LicenseError::SeatLimit.into());
                }

                let issued = self
                    .inner
                    .issue(&purchase, &device, request.device_hint, &context)?;
                db::store_entitlement(tx, entitlement_id, purchase.bytes())?;
                db::activate(
                    tx,
                    &device,
                    request.app_version,
                    request.device_hint,
                    context.now,
                )?;
                db::register_lease(tx, &device, issued.id, issued.accepted_until, context.now)?;
                Ok(issued.response)
            })
    }

    fn renew(&self, request: &RenewRequest) -> Result<LeaseResponse, ServerError> {
        let lease = self.inner.lease(&request.lease_token)?;
        let claims = lease.payload();
        let device = Device {
            entitlement_id: claims.entitlement_id,
            public: claims.device_pub.ok_or(LicenseError::Malformed)?,
        };
        request.verify_proof(device.entitlement_id, device.public)?;

        self.inner
            .run_request(&device, request.nonce, |tx, context| {
                lease.check_revocation(context.crl)?;
                check_lease_time(claims, context.now)?;
                db::require_registered_lease(tx, &device, claims.license_id)?;
                let version = db::active_version(tx, &device)?.ok_or(LicenseError::Deactivated)?;
                let source =
                    db::entitlement(tx, device.entitlement_id)?.ok_or(LicenseError::Deactivated)?;
                let purchase = self.inner.verifier.authenticate(&source)?;
                self.inner.check_entitlement(&purchase, version, &context)?;

                let hint = db::device_hint(tx, &device)?;
                let issued = self.inner.issue(&purchase, &device, hint, &context)?;
                db::touch(tx, &device, context.now)?;
                db::register_lease(tx, &device, issued.id, issued.accepted_until, context.now)?;
                Ok(issued.response)
            })
    }

    fn deactivate(&self, request: &DeactivateRequest) -> Result<(), ServerError> {
        let token = match (&request.lease_token, &request.entitlement_token) {
            (Some(token), None) => self.inner.lease(token)?,
            (None, Some(token)) => self.inner.entitlement(token)?,
            _ => return Err(LicenseError::Malformed.into()),
        };

        let claims = token.payload();
        if claims.class == Class::Lease && claims.device_pub != Some(request.device_pub) {
            return Err(LicenseError::DeviceProofFailed.into());
        }
        let device = Device {
            entitlement_id: claims.entitlement_id,
            public: request.device_pub,
        };
        request.verify_proof(device.entitlement_id)?;

        self.inner
            .run_request(&device, request.nonce, |tx, context| {
                token.check_revocation(context.crl)?;
                if claims.class == Class::Lease {
                    if db::active_version(tx, &device)?.is_none() {
                        return Ok(());
                    }
                    db::require_registered_lease(tx, &device, claims.license_id)?;
                } else if let Some(stored) = db::entitlement(tx, device.entitlement_id)?
                    && stored.as_slice() != token.bytes()
                {
                    return Err(LicenseError::Malformed.into());
                }
                db::deactivate(tx, &device, context.now)
            })
    }

    fn crl(&self) -> Result<Option<Vec<u8>>, ServerError> {
        let storage = lock(&self.inner.storage)?;
        db::stored_crl(&storage.conn)
    }

    fn health(&self) -> Result<http::Health, ServerError> {
        let storage = lock(&self.inner.storage)?;
        let now = unix_now()?;
        let last = db::last_time(&storage.conn)?;
        let clock_good = now.saturating_add(db::CLOCK_SKEW_SECS) >= last;
        let now = now.max(last);
        let remaining = self.inner.cert.not_after.saturating_sub(now);
        let crl = current_crl(&storage.conn, &self.inner.verifier, storage.crl.as_ref())?;
        let crl = crl.as_ref().or(storage.crl.as_ref());
        let status = if !clock_good {
            "clock_rollback"
        } else if now < self.inner.cert.not_before {
            "certificate_not_yet_valid"
        } else if now > self.inner.cert.not_after {
            "certificate_expired"
        } else if self.inner.cert_revoked(crl, now) {
            "certificate_revoked"
        } else {
            "ok"
        };
        Ok(http::Health {
            status,
            certificate_remaining_days: remaining.div_ceil(DAY_SECS),
        })
    }
}

impl Inner {
    fn entitlement(&self, token: &str) -> Result<SignedLicense, ServerError> {
        self.authenticate_class(token, Class::Entitlement)
    }

    fn lease(&self, token: &str) -> Result<SignedLicense, ServerError> {
        self.authenticate_class(token, Class::Lease)
    }

    fn authenticate_class(&self, token: &str, class: Class) -> Result<SignedLicense, ServerError> {
        let raw = Zeroizing::new(decode_token(token)?);
        let signed = self.verifier.authenticate(&raw)?;
        if signed.payload().class != class {
            return Err(LicenseError::Malformed.into());
        }
        if signed.payload().product != self.cert.product {
            return Err(LicenseError::WrongProduct.into());
        }
        Ok(signed)
    }

    fn run_request<T>(
        &self,
        device: &Device,
        nonce: Id,
        business: impl FnOnce(&Transaction<'_>, RequestContext<'_>) -> Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        self.limits.check_entitlement(device.entitlement_id)?;
        let mut storage = lock(&self.storage)?;
        let Storage { conn, crl } = &mut *storage;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = db::monotonic_time(&tx, unix_now()?)?;
        let fresh_crl = current_crl(&tx, &self.verifier, crl.as_ref())?;
        let context = RequestContext {
            now,
            crl: fresh_crl.as_ref().or(crl.as_ref()),
        };
        db::consume_nonce(&tx, device, nonce)?;
        let result = business(&tx, context);
        // Policy rejections consume the authenticated nonce. A transient signer
        // or storage failure leaves the request eligible for an exact retry.
        let commit = match &result {
            Ok(_) | Err(ServerError::CertificateInactive) => true,
            Err(ServerError::License(error)) => {
                !matches!(error, LicenseError::Randomness | LicenseError::Signing(_))
            }
            Err(_) => false,
        };
        if commit {
            tx.commit()?;
        }
        if let Some(fresh_crl) = fresh_crl {
            *crl = Some(fresh_crl);
        }
        result
    }

    fn check_entitlement(
        &self,
        purchase: &SignedLicense,
        app_version: AppVersion,
        context: &RequestContext<'_>,
    ) -> Result<(), ServerError> {
        let claims = purchase.payload();
        if claims.class != Class::Entitlement {
            return Err(LicenseError::Malformed.into());
        }
        if claims.product != self.cert.product {
            return Err(LicenseError::WrongProduct.into());
        }
        purchase.check_revocation(context.crl)?;
        if context.now
            < claims
                .not_before
                .unwrap_or(claims.issued_at)
                .max(claims.issued_at)
        {
            return Err(LicenseError::NotYetValid.into());
        }
        if claims
            .expires_at
            .is_some_and(|expiry| context.now >= expiry)
        {
            return Err(LicenseError::Expired.into());
        }
        if claims
            .max_app_version
            .is_some_and(|version| app_version > version)
        {
            return Err(LicenseError::VersionNotCovered.into());
        }
        Ok(())
    }

    fn cert_revoked(&self, crl: Option<&Crl>, now: u64) -> bool {
        crl.is_some_and(|crl| {
            crl.revoked_certs
                .iter()
                .any(|(id, since)| id == &self.cert.cert_id && now >= *since)
        })
    }

    fn issue(
        &self,
        purchase: &SignedLicense,
        device: &Device,
        hint: Option<Id>,
        context: &RequestContext<'_>,
    ) -> Result<Issued, ServerError> {
        let now = context.now;
        if now < self.cert.not_before || now > self.cert.not_after {
            return Err(ServerError::CertificateInactive);
        }
        if self.cert_revoked(context.crl, now) {
            return Err(LicenseError::CertRevoked.into());
        }
        let claims = purchase.payload();
        if claims.tier > self.cert.max_tier
            || !claims.features.is_subset_of(&self.cert.feature_mask)
        {
            return Err(LicenseError::DelegationViolation.into());
        }

        let times = LeaseTimes::new(now, self.lease_secs, self.grace_secs, claims.expires_at)?;
        let id = random_bytes()?;
        let payload = LicensePayload {
            class: Class::Lease,
            license_id: id,
            entitlement_id: claims.entitlement_id,
            product: claims.product.clone(),
            subject: claims.subject.clone(),
            tier: claims.tier,
            features: claims.features.clone(),
            issued_at: now,
            not_before: None,
            expires_at: Some(times.expires_at),
            renew_after: Some(times.renew_after),
            grace_secs: times.grace_secs,
            max_app_version: claims.max_app_version,
            max_devices: 0,
            device_pub: Some(device.public),
            device_hint: hint,
            tags: claims.tags,
            unlock: claims.unlock.clone(),
        };

        let bytes = Zeroizing::new(sign_lease(
            self.cert_key_id,
            self.delegate.as_ref(),
            &self.cert_bytes,
            &payload,
        )?);
        Ok(Issued {
            id,
            accepted_until: times.expires_at + u64::from(times.grace_secs),
            response: LeaseResponse {
                lease_token: encode_token(&bytes),
                server_time: now,
                crl_seq: context.crl.map_or(0, |crl| crl.seq),
            },
        })
    }
}

#[derive(Clone, Copy)]
struct RequestContext<'a> {
    now: u64,
    crl: Option<&'a Crl>,
}

struct Issued {
    id: Id,
    accepted_until: u64,
    response: LeaseResponse,
}

struct LeaseTimes {
    expires_at: u64,
    renew_after: u64,
    grace_secs: u32,
}

impl LeaseTimes {
    fn new(
        now: u64,
        lease_secs: u64,
        grace_secs: u32,
        purchase_expires: Option<u64>,
    ) -> Result<Self, LicenseError> {
        let hard_end = purchase_expires
            .unwrap_or(MAX_SQLITE_TIMESTAMP)
            .min(MAX_SQLITE_TIMESTAMP);
        let expires_at = now.saturating_add(lease_secs).min(hard_end);
        if expires_at <= now {
            return Err(LicenseError::Expired);
        }
        let grace_secs = u64::from(grace_secs).min(hard_end - expires_at) as u32;
        Ok(Self {
            expires_at,
            renew_after: now + (expires_at - now) / 2,
            grace_secs,
        })
    }
}

fn check_lease_time(claims: &LicensePayload, now: u64) -> Result<(), LicenseError> {
    if now < claims.issued_at.max(claims.not_before.unwrap_or_default()) {
        return Err(LicenseError::NotYetValid);
    }
    let expires = claims.expires_at.ok_or(LicenseError::Malformed)?;
    if now >= expires.saturating_add(u64::from(claims.grace_secs)) {
        return Err(LicenseError::Expired);
    }
    Ok(())
}

fn load_stored_crl(conn: &Connection, verifier: &Verifier) -> Result<Option<Crl>, ServerError> {
    let Some((sequence, raw)) = db::stored_crl_snapshot(conn)? else {
        return Ok(None);
    };
    let crl = verifier.verify_crl(&raw)?;
    if sequence != crl.seq.to_be_bytes() {
        return Err(ServerError::CrlConflict);
    }
    Ok(Some(crl))
}

/// Returns a freshly authenticated snapshot when another database writer changed it.
fn current_crl(
    conn: &Connection,
    verifier: &Verifier,
    cached: Option<&Crl>,
) -> Result<Option<Crl>, ServerError> {
    let stored = db::stored_crl_seq(conn)?.map(u64::from_be_bytes);
    let cached = cached.map(|crl| crl.seq);
    match (stored, cached) {
        (Some(revision), _) if Some(revision) > cached => load_stored_crl(conn, verifier),
        _ if stored < cached => Err(LicenseError::CrlRollback.into()),
        _ => Ok(None),
    }
}

fn unix_now() -> Result<u64, ServerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ServerError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_grace_cannot_outlive_its_purchase() -> Result<(), LicenseError> {
        let times = LeaseTimes::new(100, 10, 6, Some(112))?;
        assert_eq!(times.expires_at, 110);
        assert_eq!(times.renew_after, 105);
        assert_eq!(times.grace_secs, 2);
        let times = LeaseTimes::new(105, 10, 6, Some(112))?;
        assert_eq!(times.expires_at, 112);
        assert_eq!(times.renew_after, 108);
        assert_eq!(times.grace_secs, 0);
        assert!(matches!(
            LeaseTimes::new(112, 10, 6, Some(112)),
            Err(LicenseError::Expired)
        ));
        Ok(())
    }
}
