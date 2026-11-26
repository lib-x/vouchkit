//! Optional online activation and delegated lease signing with pluggable storage.

mod config;
#[cfg(feature = "sqlite")]
mod db;
mod http;
mod memory;
mod rate_limit;
mod store;

use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::Router;
use thiserror::Error;
use tokio::sync::Semaphore;
use vouchkit_core::{
    AppVersion, Class, Crl, DelegationCert, Id, LicenseError, LicensePayload, SignedLicense,
    SigningProvider, Verifier, decode_token, encode_token,
    protocol::{ActivateRequest, DeactivateRequest, LeaseResponse, RenewRequest},
    random_bytes, sign_lease,
};
use zeroize::Zeroizing;

pub use config::ServerConfig;
use config::{DAY_SECS, MAX_CRL_BYTES, is_missing, read_limited};
#[cfg(feature = "sqlite")]
pub use db::SqliteActivationStore;
pub use memory::MemoryActivationStore;
use rate_limit::{Limits, lock};
pub use store::{
    ActivationStore, ActivationTransaction, DeviceIdentity, Registration, StoreError, StoredCrl,
    TransactionControl, TransactionMode,
};

const MAX_PENDING_REQUESTS: usize = 32;
const EXPIRY_WARNING_DAYS: u64 = 14;
const CLOCK_SKEW_SECS: u64 = 300;
const MAX_LEASE_TIMESTAMP: u64 = i64::MAX.unsigned_abs();

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
    /// An activation transaction or its backend failed.
    #[error(transparent)]
    Storage(#[from] StoreError),
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
    delegate: Box<dyn SigningProvider + Send + Sync>,
    cert_key_id: u8,
    cert: DelegationCert,
    cert_bytes: Vec<u8>,
    lease_secs: u64,
    grace_secs: u32,
    store: Box<dyn ActivationStore>,
    crl_cache: Mutex<Option<Arc<Crl>>>,
    limits: Limits,
    http_slots: Arc<Semaphore>,
}

impl ActivationServer {
    /// Opens the reference SQLite backend with the configured signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the files, backend, key, certificate or limits are invalid.
    #[cfg(feature = "sqlite")]
    pub fn load(config: &ServerConfig) -> Result<Self, ServerError> {
        Self::load_with_delegate(config, config.read_delegate()?)
    }

    /// Opens the reference SQLite backend with a caller-provided signer.
    ///
    /// # Errors
    ///
    /// Returns an error if SQLite, the signer, or the configured files are invalid.
    #[cfg(feature = "sqlite")]
    pub fn load_with_delegate(
        config: &ServerConfig,
        delegate: impl SigningProvider + Send + Sync + 'static,
    ) -> Result<Self, ServerError> {
        Self::load_with_store_and_delegate(
            config,
            SqliteActivationStore::open(&config.database)?,
            delegate,
        )
    }

    /// Uses the given storage backend and the signing key configured on disk or in the environment.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend, files, key, certificate or limits are invalid.
    pub fn load_with_store(
        config: &ServerConfig,
        store: impl ActivationStore + 'static,
    ) -> Result<Self, ServerError> {
        Self::load_with_store_and_delegate(config, store, config.read_delegate()?)
    }

    /// Uses caller-owned implementations of activation storage and signing custody.
    ///
    /// Configure bounded signing latency. Issuing a lease signs within the same
    /// atomic transaction that checks seats, the clock and revocation state.
    ///
    /// # Errors
    ///
    /// Returns an error if the signing key differs from the signed certificate or
    /// the configured trust roots, files, limits or storage state are invalid.
    pub fn load_with_store_and_delegate(
        config: &ServerConfig,
        store: impl ActivationStore + 'static,
        delegate: impl SigningProvider + Send + Sync + 'static,
    ) -> Result<Self, ServerError> {
        let verifier = Verifier::with_public_keys(&config.read_master_keys()?, None);
        let cert_bytes = read_limited(&config.delegation_cert, 512)?;
        let (cert_key_id, cert) = verifier.verify_delegation(&cert_bytes)?;
        if cert.delegate_pub != delegate.public_key() {
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

        let server = Self {
            inner: Arc::new(Inner {
                verifier,
                delegate: Box::new(delegate),
                cert_key_id,
                cert,
                cert_bytes,
                lease_secs: config.lease_secs,
                grace_secs: config.grace_secs,
                store: Box::new(store),
                crl_cache: Mutex::new(None),
                limits: Limits::new(
                    config.requests_per_ip_per_minute,
                    config.requests_per_entitlement_per_minute,
                    config.requests_per_minute,
                )?,
                http_slots: Arc::new(Semaphore::new(MAX_PENDING_REQUESTS)),
            }),
        };
        let has_crl = server.inner.state_operation(TransactionMode::Read, |tx| {
            Ok(server.inner.current_crl(tx)?.is_some())
        })?;
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
    /// use vouchkit_server::{ActivationServer, MemoryActivationStore, ServerConfig};
    ///
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ServerConfig::load(Path::new("config.toml"))?;
    /// let service = ActivationServer::load_with_store(&config, MemoryActivationStore::new())?;
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
        self.inner.state_operation(TransactionMode::Write, |tx| {
            if let Some(current) = self.inner.current_crl(tx)? {
                match crl.seq.cmp(&current.seq) {
                    std::cmp::Ordering::Less => return Err(LicenseError::CrlRollback.into()),
                    std::cmp::Ordering::Equal => {
                        let same = tx.crl()?.is_some_and(|stored| stored.bytes == bytes);
                        return if same {
                            Ok(false)
                        } else {
                            Err(ServerError::CrlConflict)
                        };
                    }
                    std::cmp::Ordering::Greater => {}
                }
            }
            tx.set_crl(crl.seq, bytes)?;
            Ok(true)
        })
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

    /// Verifies an activation proof, reserves a seat and issues a signed lease.
    ///
    /// The router applies TCP peer limits before calling this method. Embedders
    /// accepting requests through another transport can limit callers there.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials, unavailable seats or state failures.
    pub fn activate(&self, request: &ActivateRequest) -> Result<LeaseResponse, ServerError> {
        let purchase = self.inner.entitlement(&request.entitlement_token)?;
        let entitlement_id = purchase.payload().entitlement_id;
        request.verify_proof(entitlement_id)?;
        let device = DeviceIdentity {
            entitlement_id,
            public_key: request.device_pub,
        };
        self.inner
            .run_request(device, request.nonce, |tx, context| {
                self.inner
                    .check_entitlement(&purchase, request.app_version, &context)?;
                if let Some(stored) = tx.entitlement(entitlement_id)?.map(Zeroizing::new)
                    && stored.as_slice() != purchase.bytes()
                {
                    return Err(LicenseError::Malformed.into());
                }
                let max_devices = u64::from(purchase.payload().max_devices);
                if tx.registration(device)?.is_none()
                    && tx.active_devices(entitlement_id)? >= max_devices
                {
                    return Err(LicenseError::SeatLimit.into());
                }

                let issued = self
                    .inner
                    .issue(&purchase, device, request.device_hint, &context)?;
                tx.insert_entitlement(entitlement_id, purchase.bytes())?;
                tx.activate(
                    device,
                    Registration {
                        app_version: request.app_version,
                        device_hint: request.device_hint,
                    },
                    context.now,
                )?;
                tx.register_lease(device, issued.id, issued.accepted_until, context.now)?;
                Ok(issued.response)
            })
    }

    /// Authenticates the lease and its device before signing a renewal.
    ///
    /// # Errors
    ///
    /// Returns an error when the original lease or purchase is no longer usable.
    pub fn renew(&self, request: &RenewRequest) -> Result<LeaseResponse, ServerError> {
        let lease = self.inner.lease(&request.lease_token)?;
        let claims = lease.payload();
        let device = DeviceIdentity {
            entitlement_id: claims.entitlement_id,
            public_key: claims.device_pub.ok_or(LicenseError::Malformed)?,
        };
        request.verify_proof(device.entitlement_id, device.public_key)?;

        self.inner
            .run_request(device, request.nonce, |tx, context| {
                lease.check_revocation(context.crl)?;
                check_lease_time(claims, context.now)?;
                if !tx.has_lease(device, claims.license_id)? {
                    return Err(LicenseError::Deactivated.into());
                }
                let registration = tx.registration(device)?.ok_or(LicenseError::Deactivated)?;
                let source = tx
                    .entitlement(device.entitlement_id)?
                    .map(Zeroizing::new)
                    .ok_or(LicenseError::Deactivated)?;
                let purchase = self.inner.verifier.authenticate(&source)?;
                self.inner
                    .check_entitlement(&purchase, registration.app_version, &context)?;

                let issued =
                    self.inner
                        .issue(&purchase, device, registration.device_hint, &context)?;
                tx.touch(device, context.now)?;
                tx.register_lease(device, issued.id, issued.accepted_until, context.now)?;
                Ok(issued.response)
            })
    }

    /// Authenticates the caller's device and frees its seat.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials, proofs or storage state.
    pub fn deactivate(&self, request: &DeactivateRequest) -> Result<(), ServerError> {
        let token = match (&request.lease_token, &request.entitlement_token) {
            (Some(token), None) => self.inner.lease(token)?,
            (None, Some(token)) => self.inner.entitlement(token)?,
            _ => return Err(LicenseError::Malformed.into()),
        };

        let claims = token.payload();
        if claims.class == Class::Lease && claims.device_pub != Some(request.device_pub) {
            return Err(LicenseError::DeviceProofFailed.into());
        }
        let device = DeviceIdentity {
            entitlement_id: claims.entitlement_id,
            public_key: request.device_pub,
        };
        request.verify_proof(device.entitlement_id)?;

        self.inner
            .run_request(device, request.nonce, |tx, context| {
                token.check_revocation(context.crl)?;
                if claims.class == Class::Lease {
                    if tx.registration(device)?.is_none() {
                        return Ok(());
                    }
                    if !tx.has_lease(device, claims.license_id)? {
                        return Err(LicenseError::Deactivated.into());
                    }
                } else if let Some(stored) =
                    tx.entitlement(device.entitlement_id)?.map(Zeroizing::new)
                    && stored.as_slice() != token.bytes()
                {
                    return Err(LicenseError::Malformed.into());
                }
                tx.deactivate(device, context.now)?;
                Ok(())
            })
    }

    fn crl(&self) -> Result<Option<Vec<u8>>, ServerError> {
        self.inner.state_operation(TransactionMode::Read, |tx| {
            self.inner.current_crl(tx)?;
            Ok(tx.crl()?.map(|stored| stored.bytes))
        })
    }

    fn health(&self) -> Result<http::Health, ServerError> {
        self.inner.state_operation(TransactionMode::Read, |tx| {
            let now = unix_now()?;
            let last = tx.last_seen_time()?;
            let clock_good = now.saturating_add(CLOCK_SKEW_SECS) >= last;
            let now = now.max(last);
            let remaining = self.inner.cert.not_after.saturating_sub(now);
            let crl = self.inner.current_crl(tx)?;
            let status = if !clock_good {
                "clock_rollback"
            } else if now < self.inner.cert.not_before {
                "certificate_not_yet_valid"
            } else if now > self.inner.cert.not_after {
                "certificate_expired"
            } else if self.inner.cert_revoked(crl.as_deref(), now) {
                "certificate_revoked"
            } else {
                "ok"
            };
            Ok(http::Health {
                status,
                certificate_remaining_days: remaining.div_ceil(DAY_SECS),
            })
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

    fn transact<T>(
        &self,
        mode: TransactionMode,
        operation: impl FnOnce(
            &mut dyn ActivationTransaction,
        ) -> (TransactionControl, Result<T, ServerError>),
    ) -> Result<T, ServerError> {
        let mut operation = Some(operation);
        let mut outcome =
            Err(StoreError::InvalidState("activation store omitted its callback").into());
        self.store.transaction(mode, &mut |tx| {
            let Some(operation) = operation.take() else {
                outcome =
                    Err(StoreError::InvalidState("activation store repeated its callback").into());
                return TransactionControl::Rollback;
            };
            let (control, result) = operation(tx);
            outcome = result;
            control
        })?;
        outcome
    }

    fn state_operation<T>(
        &self,
        mode: TransactionMode,
        operation: impl FnOnce(&mut dyn ActivationTransaction) -> Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        self.transact(mode, |tx| {
            let outcome = operation(tx);
            let control = if outcome.is_ok() {
                TransactionControl::Commit
            } else {
                TransactionControl::Rollback
            };
            (control, outcome)
        })
    }

    fn current_crl(&self, tx: &dyn ActivationTransaction) -> Result<Option<Arc<Crl>>, ServerError> {
        let stored = tx.crl_sequence()?;
        if stored.is_none() && tx.crl()?.is_some() {
            return Err(
                StoreError::InvalidState("missing sequence for stored revocation list").into(),
            );
        }
        let mut cache = lock(&self.crl_cache)?;
        let cached = cache.as_ref().map(|crl| crl.seq);
        match stored.cmp(&cached) {
            std::cmp::Ordering::Less => Err(LicenseError::CrlRollback.into()),
            std::cmp::Ordering::Equal => Ok(cache.clone()),
            std::cmp::Ordering::Greater => {
                let raw = tx
                    .crl()?
                    .ok_or(StoreError::InvalidState("missing stored revocation bytes"))?;
                let crl = self.verifier.verify_crl(&raw.bytes)?;
                if Some(raw.sequence) != stored || raw.sequence != crl.seq {
                    return Err(ServerError::CrlConflict);
                }
                let crl = Arc::new(crl);
                *cache = Some(Arc::clone(&crl));
                Ok(Some(crl))
            }
        }
    }

    fn run_request<T>(
        &self,
        device: DeviceIdentity,
        nonce: Id,
        business: impl FnOnce(
            &mut dyn ActivationTransaction,
            RequestContext<'_>,
        ) -> Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        self.limits.check_entitlement(device.entitlement_id)?;
        self.transact(TransactionMode::Write, |tx| {
            let (now, crl) = match self.prepare_request(tx, device, nonce) {
                Ok(prepared) => prepared,
                Err(error) => return (TransactionControl::Rollback, Err(error)),
            };
            let result = business(
                tx,
                RequestContext {
                    now,
                    crl: crl.as_deref(),
                },
            );
            // Policy rejections consume the authenticated nonce. A transient signer
            // or storage failure leaves the request eligible for an exact retry.
            let commit = match &result {
                Ok(_) | Err(ServerError::CertificateInactive) => true,
                Err(ServerError::License(error)) => {
                    !matches!(error, LicenseError::Randomness | LicenseError::Signing(_))
                }
                Err(_) => false,
            };
            let control = if commit {
                TransactionControl::Commit
            } else {
                TransactionControl::Rollback
            };
            (control, result)
        })
    }

    fn prepare_request(
        &self,
        tx: &mut dyn ActivationTransaction,
        device: DeviceIdentity,
        nonce: Id,
    ) -> Result<(u64, Option<Arc<Crl>>), ServerError> {
        let local_now = unix_now()?;
        let last = tx.last_seen_time()?;
        if local_now.saturating_add(CLOCK_SKEW_SECS) < last {
            return Err(LicenseError::ClockRollback.into());
        }
        if local_now > last {
            tx.set_last_seen_time(local_now)?;
        }
        let crl = self.current_crl(tx)?;
        if !tx.insert_nonce(device, nonce)? {
            return Err(LicenseError::Replay.into());
        }
        Ok((local_now.max(last), crl))
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
        device: DeviceIdentity,
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
            device_pub: Some(device.public_key),
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
            .unwrap_or(MAX_LEASE_TIMESTAMP)
            .min(MAX_LEASE_TIMESTAMP);
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
