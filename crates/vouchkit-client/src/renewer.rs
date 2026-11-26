use thiserror::Error;
use vouchkit_core::protocol::{
    ActivateRequest, DeactivateRequest, ErrorCode, LeaseResponse, RenewRequest,
};
use vouchkit_core::{
    AppVersion, Class, Crl, Id, LicenseError, LicensePayload, LicenseState, SignedLicense,
    StateStore, Verifier, VerifyOptions, VerifyOutcome, check_clock_with_skew, decode_token,
    random_bytes, validate_product,
};
use zeroize::Zeroizing;

use crate::{DeviceKeyStore, Transport, TransportError};

const DEFAULT_CLOCK_SKEW_SECS: u64 = 300;
const RETRY_BASE_SECS: u64 = 5;
const RETRY_CAP_SECS: u64 = 3_600;

/// The network work recommended by the renewal scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// No renewal is currently due.
    None,
    /// The host can attempt renewal now.
    Renew,
}

/// The result of running a scheduled renewal check.
#[derive(Debug)]
#[non_exhaustive]
pub enum Renewal {
    /// No usable lease is currently due for renewal.
    NotDue,
    /// A verified replacement lease was persisted.
    Renewed(VerifyOutcome),
}

/// The credential to present when releasing an activation seat.
#[derive(Clone, Copy)]
pub enum Deactivation<'a> {
    /// Proves ownership using the locally cached lease.
    Lease,
    /// Uses the supplied entitlement when its lease is unavailable locally.
    Entitlement(&'a str),
}

impl std::fmt::Debug for Deactivation<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Lease => "Lease",
            Self::Entitlement(_) => "Entitlement([redacted])",
        })
    }
}

/// Failures during activation, renewal, or local verification.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Signed data or a local policy check failed.
    #[error(transparent)]
    License(#[from] LicenseError),
    /// The activation channel failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// An operation requiring a previously cached lease started without one.
    #[error("no cached lease")]
    MissingLease,
    /// The server response failed to match the operation's authenticated data.
    #[error("activation response does not match the request")]
    UnexpectedResponse,
}

#[derive(Debug)]
struct Schedule {
    license_id: Id,
    renew_at: u64,
    valid_until: u64,
}

struct Acceptance<'a> {
    now: u64,
    source: GrantSource<'a>,
    earliest_issue: u64,
    latest_issue: u64,
}

enum GrantSource<'a> {
    Activation {
        purchase: &'a SignedLicense,
        token: &'a str,
    },
    Renewal {
        lease: &'a LicensePayload,
        purchase: Option<&'a SignedLicense>,
    },
}

/// Verifies and refreshes one device's lease without owning a runtime or timer.
///
/// # Examples
///
/// Read the current capability from a private, persistent state file.
///
/// ```no_run
/// use std::time::{SystemTime, UNIX_EPOCH};
/// use vouchkit_client::{DeviceKey, FileStateStore, Renewer};
/// use vouchkit_core::Verifier;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let publisher_key = [0_u8; 32];
/// let verifier = Verifier::new(&[(7, publisher_key)], None);
/// let mut renewer = Renewer::new(verifier, "editor", (1, 0, 0))?;
/// let mut store = FileStateStore::open("app-data/license.state")?;
/// let key = DeviceKey::open_or_create_file("app-data/device.key")?;
/// let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
/// if let Some(outcome) = renewer.verify_cached_lease(now, &mut store, &key)?
///     && let Some(license) = outcome.license()
/// {
///     let feature_available = license.payload().features.contains(42);
///     println!("{feature_available}");
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Renewer {
    verifier: Verifier,
    product: String,
    app_version: AppVersion,
    clock_skew_secs: u64,
    schedule: Option<Schedule>,
    retry_at: u64,
    failures: u32,
}

impl Renewer {
    /// Configures activation for a product and an application version.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid product identifier.
    pub fn new(
        verifier: Verifier,
        product: &str,
        app_version: AppVersion,
    ) -> Result<Self, LicenseError> {
        validate_product(product)?;
        Ok(Self {
            verifier,
            product: product.to_owned(),
            app_version,
            clock_skew_secs: DEFAULT_CLOCK_SKEW_SECS,
            schedule: None,
            retry_at: 0,
            failures: 0,
        })
    }

    /// Sets the permitted clock skew around signed issuance and earlier observations.
    pub fn with_clock_skew(mut self, seconds: u64) -> Self {
        self.clock_skew_secs = seconds;
        self
    }

    /// Returns the network action due for the last locally verified lease.
    ///
    /// Call [Self::verify_cached_lease] after process startup to restore the
    /// schedule. Network operations repeat verification against current state.
    pub fn tick(&self, now: u64) -> Action {
        if self.schedule.as_ref().is_some_and(|schedule| {
            now >= schedule.renew_at && now >= self.retry_at && now < schedule.valid_until
        }) {
            Action::Renew
        } else {
            Action::None
        }
    }

    /// Verifies the cached lease offline, returning its current capability if present.
    ///
    /// # Errors
    ///
    /// Returns an error for unauthorized state, a rollback or a failed update.
    pub fn verify_cached_lease(
        &mut self,
        now: u64,
        store: &mut dyn StateStore,
        keys: &dyn DeviceKeyStore,
    ) -> Result<Option<VerifyOutcome>, ClientError> {
        let result = self.read_cached_lease(now, store, keys);
        let outcome = result.as_ref().ok().and_then(Option::as_ref);
        let schedule = outcome
            .and_then(VerifyOutcome::license)
            .and_then(|license| Self::schedule(license.payload()));
        self.update_schedule(schedule);
        result
    }

    /// Computes the current cached lease state for user-facing status.
    pub fn state(
        &mut self,
        now: u64,
        store: &mut dyn StateStore,
        keys: &dyn DeviceKeyStore,
    ) -> LicenseState {
        match self.verify_cached_lease(now, store, keys) {
            Ok(Some(outcome)) => outcome.state(),
            Ok(None) => LicenseState::NeedsActivation,
            Err(ClientError::License(LicenseError::Expired)) => LicenseState::Expired,
            Err(ClientError::License(error)) => LicenseState::Invalid(error),
            Err(_) => LicenseState::Invalid(LicenseError::Malformed),
        }
    }

    /// Obtains a lease for a locally authenticated entitlement.
    ///
    /// # Errors
    ///
    /// Returns an error if the purchase, response, revocation data or
    /// persistence fails validation.
    pub async fn activate(
        &mut self,
        now: u64,
        entitlement: &str,
        transport: &dyn Transport,
        store: &mut (dyn StateStore + Send),
        keys: &dyn DeviceKeyStore,
    ) -> Result<VerifyOutcome, ClientError> {
        self.activate_with_hint(now, entitlement, transport, store, keys, None)
            .await
    }

    /// Obtains a lease and supplies an optional diagnostic device hint.
    ///
    /// # Errors
    ///
    /// Returns an error if the purchase, response, revocation data or
    /// persistence fails validation.
    pub async fn activate_with_hint(
        &mut self,
        now: u64,
        entitlement: &str,
        transport: &dyn Transport,
        store: &mut (dyn StateStore + Send),
        keys: &dyn DeviceKeyStore,
        hint: Option<Id>,
    ) -> Result<VerifyOutcome, ClientError> {
        let latest_issue = now.saturating_add(self.clock_skew_secs);
        let now = check_clock_with_skew(now, store, self.clock_skew_secs)?;
        let crl = self.cached_crl(store)?;
        let options = self.options(now, crl.as_ref(), keys);
        let VerifyOutcome::NeedsActivation(info) = self.verifier.verify(entitlement, &options)?
        else {
            return Err(LicenseError::Malformed.into());
        };
        let request = ActivateRequest::new(
            entitlement.to_owned(),
            info.entitlement_id,
            keys,
            hint,
            self.app_version,
        )?;
        let bytes = Zeroizing::new(decode_token(entitlement)?);
        let source = self.verifier.authenticate(&bytes)?;
        let expected = Acceptance {
            now,
            source: GrantSource::Activation {
                purchase: &source,
                token: entitlement,
            },
            earliest_issue: now.saturating_sub(self.clock_skew_secs),
            latest_issue,
        };
        let response = transport.activate(&request).await?;
        self.accept_lease(response, expected, transport, store, keys)
            .await
    }

    /// Attempts renewal when due, applying capped exponential backoff with jitter.
    ///
    /// A signed issue time older than the current lease cannot replace it.
    /// Same-second issuance is accepted for idempotent activation services.
    ///
    /// The current lease is retained after transport and response errors. A
    /// signed CRL received during a failure can still revoke that lease.
    ///
    /// # Errors
    ///
    /// Returns verification, network, response or persistence errors.
    pub async fn renew_if_needed(
        &mut self,
        now: u64,
        transport: &dyn Transport,
        store: &mut (dyn StateStore + Send),
        keys: &dyn DeviceKeyStore,
    ) -> Result<Renewal, ClientError> {
        let latest_issue = now.saturating_add(self.clock_skew_secs);
        let Some(outcome) = self.verify_cached_lease(now, store, keys)? else {
            return Ok(Renewal::NotDue);
        };
        let now = now.max(store.get_last_seen_time().unwrap_or_default());
        if self.tick(now) == Action::None {
            return Ok(Renewal::NotDue);
        }
        let license = outcome.license().ok_or(LicenseError::Malformed)?;
        let entitlement_id = license.payload().entitlement_id;
        let earliest_issue = license
            .payload()
            .issued_at
            .max(now.saturating_sub(self.clock_skew_secs));
        let token = token_text(store.get_lease())?.ok_or(ClientError::MissingLease)?;
        let purchase = self.cached_purchase(store)?;
        let request = RenewRequest::new(token.to_string(), entitlement_id, keys)?;
        let response = transport.renew(&request).await;
        let result = match response {
            Ok(response) => {
                let expected = Acceptance {
                    now,
                    source: GrantSource::Renewal {
                        lease: license.payload(),
                        purchase: purchase.as_ref(),
                    },
                    earliest_issue,
                    latest_issue,
                };
                self.accept_lease(response, expected, transport, store, keys)
                    .await
            }
            Err(error @ TransportError::Rejected(ErrorCode::Revoked | ErrorCode::CertRevoked)) => {
                if let Err(crl_error) = self.refresh_crl(transport, store).await {
                    self.record_failure(now);
                    return Err(crl_error);
                }
                Err(error.into())
            }
            Err(error) => Err(error.into()),
        };
        match result {
            Ok(outcome) => Ok(Renewal::Renewed(outcome)),
            Err(error) => {
                self.record_failure(now);
                Err(error)
            }
        }
    }

    /// Releases a seat and clears a matching local lease after confirmation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid credentials, network failure, or failure
    /// to persist the cleared lease.
    pub async fn deactivate(
        &mut self,
        credential: Deactivation<'_>,
        transport: &dyn Transport,
        store: &mut (dyn StateStore + Send),
        keys: &dyn DeviceKeyStore,
    ) -> Result<(), ClientError> {
        let cached = match credential {
            Deactivation::Lease => token_text(store.get_lease())?,
            Deactivation::Entitlement(_) => token_text(store.get_lease()).ok().flatten(),
        };
        let (token, expected_class) = match credential {
            Deactivation::Lease => (
                cached.as_deref().ok_or(ClientError::MissingLease)?.as_str(),
                Class::Lease,
            ),
            Deactivation::Entitlement(token) => (token, Class::Entitlement),
        };
        let bytes = Zeroizing::new(decode_token(token)?);
        let signed = self.verifier.authenticate(&bytes)?;
        let payload = signed.payload();
        if payload.product != self.product {
            return Err(LicenseError::WrongProduct.into());
        }
        if payload.class != expected_class {
            return Err(LicenseError::Malformed.into());
        }
        if expected_class == Class::Lease && payload.device_pub != Some(keys.public()) {
            return Err(LicenseError::DeviceProofFailed.into());
        }
        let entitlement_id = payload.entitlement_id;
        let request = match credential {
            Deactivation::Lease => DeactivateRequest::lease(token.to_owned(), entitlement_id, keys),
            Deactivation::Entitlement(_) => {
                DeactivateRequest::entitlement(token.to_owned(), entitlement_id, keys)
            }
        }?;
        let result = transport.deactivate(&request).await?;
        if !result.ok {
            return Err(ClientError::UnexpectedResponse);
        }
        let clears_cached = matches!(credential, Deactivation::Lease)
            || cached.as_ref().is_some_and(|cached| {
                let Ok(bytes) = decode_token(cached) else {
                    return false;
                };
                let bytes = Zeroizing::new(bytes);
                self.verifier.authenticate(&bytes).is_ok_and(|lease| {
                    lease.payload().class == Class::Lease
                        && lease.payload().product == self.product
                        && lease.payload().entitlement_id == entitlement_id
                        && lease.payload().device_pub == Some(keys.public())
                })
            });
        let clears_purchase = self.cached_purchase(store).is_ok_and(|purchase| {
            purchase.is_some_and(|signed| signed.payload().entitlement_id == entitlement_id)
        });
        if clears_cached {
            store.set_lease(&[]);
            self.update_schedule(None);
        }
        if clears_cached || clears_purchase {
            store.set_entitlement(&[]);
            store.flush()?;
        }
        Ok(())
    }

    /// Pulls and persists a signed revocation list independently of lease renewal.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid, unavailable, stale, or unpersistable CRL data.
    pub async fn refresh_crl(
        &mut self,
        transport: &dyn Transport,
        store: &mut (dyn StateStore + Send),
    ) -> Result<Option<Crl>, ClientError> {
        let Some(bytes) = transport.fetch_crl().await? else {
            if store.get_max_crl_seq().unwrap_or_default() > 0 {
                return Err(LicenseError::CrlUnavailable.into());
            }
            return Ok(None);
        };
        Ok(Some(self.verifier.load_crl(&bytes, store)?))
    }

    fn read_cached_lease(
        &self,
        now: u64,
        store: &mut dyn StateStore,
        keys: &dyn DeviceKeyStore,
    ) -> Result<Option<VerifyOutcome>, ClientError> {
        let now = check_clock_with_skew(now, store, self.clock_skew_secs)?;
        let Some(token) = token_text(store.get_lease())? else {
            return Ok(None);
        };
        let crl = self.cached_crl(store)?;
        let opts = self.options(now, crl.as_ref(), keys);
        let outcome = self.verifier.verify(&token, &opts)?;
        let license = outcome.license().ok_or(LicenseError::Malformed)?;
        let claims = license.payload();
        if claims.class != Class::Lease {
            return Err(LicenseError::Malformed.into());
        }
        if self
            .cached_purchase(store)?
            .is_some_and(|purchase| Self::expands_grant(claims, purchase.payload()))
        {
            return Err(ClientError::UnexpectedResponse);
        }
        Ok(Some(outcome))
    }

    fn cached_crl(&self, store: &dyn StateStore) -> Result<Option<Crl>, LicenseError> {
        let known = store.get_max_crl_seq().unwrap_or_default();
        let Some(bytes) = store.get_crl() else {
            return if known == 0 {
                Ok(None)
            } else {
                Err(LicenseError::CrlUnavailable)
            };
        };
        let crl = self.verifier.verify_crl(&bytes)?;
        if crl.seq != known {
            return Err(LicenseError::CrlRollback);
        }
        Ok(Some(crl))
    }

    fn cached_purchase(
        &self,
        store: &dyn StateStore,
    ) -> Result<Option<SignedLicense>, LicenseError> {
        let Some(token) = token_text(store.get_entitlement())? else {
            return Ok(None);
        };
        let bytes = Zeroizing::new(decode_token(&token)?);
        let signed = self.verifier.authenticate(&bytes)?;
        if signed.payload().class != Class::Entitlement {
            return Err(LicenseError::Malformed);
        }
        if signed.payload().product != self.product {
            return Err(LicenseError::WrongProduct);
        }
        Ok(Some(signed))
    }

    fn options<'a>(
        &'a self,
        now: u64,
        crl: Option<&'a Crl>,
        keys: &'a dyn DeviceKeyStore,
    ) -> VerifyOptions<'a> {
        let mut opts = VerifyOptions::new(&self.product, self.app_version, now);
        opts.crl = crl;
        opts.device = Some(keys);
        opts.clock_skew_secs = self.clock_skew_secs;
        opts
    }

    async fn accept_lease(
        &mut self,
        response: LeaseResponse,
        expected: Acceptance<'_>,
        transport: &dyn Transport,
        store: &mut (dyn StateStore + Send),
        keys: &dyn DeviceKeyStore,
    ) -> Result<VerifyOutcome, ClientError> {
        let bytes = Zeroizing::new(decode_token(&response.lease_token)?);
        let signed = self.verifier.authenticate(&bytes)?;
        let claims = signed.payload();
        let (prior_lease, purchase, purchased_token) = match expected.source {
            GrantSource::Activation { purchase, token } => (None, Some(purchase), Some(token)),
            GrantSource::Renewal { lease, purchase } => (Some(lease), purchase, None),
        };
        if claims.class != Class::Lease
            || claims.product != self.product
            || claims.device_pub != Some(keys.public())
            || prior_lease.is_some_and(|lease| Self::expands_grant(claims, lease))
            || purchase.is_some_and(|signed| Self::expands_grant(claims, signed.payload()))
            || claims.issued_at != response.server_time
            || response.server_time < expected.earliest_issue
            || response.server_time > expected.latest_issue
        {
            return Err(ClientError::UnexpectedResponse);
        }

        let cached_seq = store.get_max_crl_seq().unwrap_or_default();
        if response.crl_seq < cached_seq {
            return Err(LicenseError::CrlRollback.into());
        }
        let crl = if response.crl_seq > cached_seq || (cached_seq > 0 && store.get_crl().is_none())
        {
            let crl = self
                .refresh_crl(transport, store)
                .await?
                .ok_or(LicenseError::CrlUnavailable)?;
            if crl.seq < response.crl_seq {
                return Err(LicenseError::CrlUnavailable.into());
            }
            Some(crl)
        } else {
            self.cached_crl(store)?
        };
        if let Some(purchase) = purchase {
            purchase.check_revocation(crl.as_ref())?;
        }

        let now = expected.now.max(response.server_time);
        let opts = self.options(now, crl.as_ref(), keys);
        let outcome = self.verifier.verify_bytes(&bytes, &opts)?;
        let license = outcome.license().ok_or(LicenseError::Malformed)?;
        let schedule = Self::schedule(license.payload()).ok_or(LicenseError::Malformed)?;
        let previous = store.get_lease().map(Zeroizing::new);
        let mut prior_purchase = None;
        if let Some(token) = purchased_token {
            prior_purchase = store.get_entitlement().map(Zeroizing::new);
            store.set_entitlement(token.as_bytes());
        }
        store.set_last_seen_time(now);
        store.set_lease(response.lease_token.as_bytes());
        if let Err(error) = store.flush() {
            store.set_lease(previous.as_deref().map_or(&[], Vec::as_slice));
            if purchased_token.is_some() {
                store.set_entitlement(prior_purchase.as_deref().map_or(&[], Vec::as_slice));
            }
            return Err(error.into());
        }

        self.schedule = Some(schedule);
        self.failures = 0;
        self.retry_at = 0;
        Ok(outcome)
    }

    fn expands_grant(lease: &LicensePayload, source: &LicensePayload) -> bool {
        let extends_version = source
            .max_app_version
            .is_some_and(|max| lease.max_app_version.is_none_or(|actual| actual > max));
        let extends_end = source.class == Class::Entitlement
            && source.expires_at.is_some_and(|end| {
                lease
                    .expires_at
                    .is_none_or(|expiry| expiry.saturating_add(u64::from(lease.grace_secs)) > end)
            });
        let starts_early = source.class == Class::Entitlement
            && lease.issued_at < source.issued_at.max(source.not_before.unwrap_or_default());
        lease.entitlement_id != source.entitlement_id
            || lease.tier > source.tier
            || !lease.features.is_subset_of(&source.features)
            || extends_version
            || extends_end
            || starts_early
            || lease
                .unlock
                .iter()
                .any(|grant| !source.unlock.contains(grant))
    }

    fn schedule(payload: &LicensePayload) -> Option<Schedule> {
        let expires = payload.expires_at?;
        let lifetime = expires.saturating_sub(payload.issued_at);
        let renew_at = payload
            .renew_after
            .unwrap_or(payload.issued_at + lifetime / 2);
        Some(Schedule {
            license_id: payload.license_id,
            renew_at,
            valid_until: expires.saturating_add(u64::from(payload.grace_secs)),
        })
    }

    fn update_schedule(&mut self, schedule: Option<Schedule>) {
        if self.schedule.as_ref().map(|current| current.license_id)
            != schedule.as_ref().map(|next| next.license_id)
        {
            self.failures = 0;
            self.retry_at = 0;
        }
        self.schedule = schedule;
    }

    fn record_failure(&mut self, now: u64) {
        let cap = RETRY_BASE_SECS
            .saturating_mul(1 << self.failures.min(16))
            .min(RETRY_CAP_SECS);
        let floor = cap / 2;
        let random = random_bytes::<8>().map(u64::from_le_bytes).unwrap_or(0);
        self.retry_at = now.saturating_add(floor + random % (cap - floor + 1));
        self.failures = self.failures.saturating_add(1);
    }
}

fn token_text(bytes: Option<Vec<u8>>) -> Result<Option<Zeroizing<String>>, LicenseError> {
    let Some(bytes) = bytes.filter(|bytes| !bytes.is_empty()) else {
        return Ok(None);
    };
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map(Some)
        .map_err(|error| {
            drop(Zeroizing::new(error.into_bytes()));
            LicenseError::Malformed
        })
}
