use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroize;

use crate::{FeatureSlots, PublicKey, SigningError, Verifier, wire::SignedLicense};

/// A random identifier for a license, purchase or delegation certificate.
pub type Id = [u8; 16];
/// The three numeric components of an application version.
pub type AppVersion = (u16, u16, u16);

/// The authorization represented by a license.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Class {
    /// Author-issued authorization for offline use.
    Standalone,
    /// Author-issued purchase that requires an activation server.
    Entitlement,
    /// Delegated, time-limited authorization for one device.
    Lease,
}

/// The signed claims carried by an authorization.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicensePayload<K = PublicKey> {
    /// Type of authorization.
    pub class: Class,
    /// Unique identifier for this signed authorization.
    pub license_id: Id,
    /// Purchase identifier shared by an entitlement and its leases.
    pub entitlement_id: Id,
    /// ASCII product identifier.
    pub product: String,
    /// Human-readable license holder.
    pub subject: String,
    /// Product-defined feature tier.
    pub tier: u8,
    /// Authorized product-defined slots and intervals.
    pub features: FeatureSlots,
    /// Unix seconds at issuance.
    pub issued_at: u64,
    /// Earliest usable Unix time.
    pub not_before: Option<u64>,
    /// Exclusive expiration timestamp.
    pub expires_at: Option<u64>,
    /// Suggested renewal timestamp.
    pub renew_after: Option<u64>,
    /// Offline grace after expiration in seconds.
    pub grace_secs: u32,
    /// Highest covered application version.
    pub max_app_version: Option<AppVersion>,
    /// Activation seats on an entitlement.
    pub max_devices: u8,
    /// Algorithm-tagged public key for a bound device.
    pub device_pub: Option<K>,
    /// Optional diagnostic device hint.
    pub device_hint: Option<Id>,
    /// Optional build-specific tag check values.
    pub tags: Option<[[u8; 4]; 8]>,
    /// Feature identifiers and their resource decryption keys.
    pub unlock: Vec<(u16, [u8; 32])>,
}

impl<K> LicensePayload<K> {
    pub(crate) fn map_device<T>(
        mut self,
        transform: impl FnOnce(K) -> Result<T, LicenseError>,
    ) -> Result<LicensePayload<T>, LicenseError> {
        use std::mem::take;
        Ok(LicensePayload {
            class: self.class,
            license_id: self.license_id,
            entitlement_id: self.entitlement_id,
            product: take(&mut self.product),
            subject: take(&mut self.subject),
            tier: self.tier,
            features: take(&mut self.features),
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            renew_after: self.renew_after,
            grace_secs: self.grace_secs,
            max_app_version: self.max_app_version,
            max_devices: self.max_devices,
            device_pub: self.device_pub.take().map(transform).transpose()?,
            device_hint: self.device_hint,
            tags: self.tags,
            unlock: take(&mut self.unlock),
        })
    }
}

impl<K> fmt::Debug for LicensePayload<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LicensePayload")
            .field("class", &self.class)
            .field("license_id", &self.license_id)
            .field("entitlement_id", &self.entitlement_id)
            .field("product", &self.product)
            .field("tier", &self.tier)
            .field("features", &self.features)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("unlock_count", &self.unlock.len())
            .finish_non_exhaustive()
    }
}

impl<K> Drop for LicensePayload<K> {
    fn drop(&mut self) {
        self.unlock.zeroize();
    }
}

/// Author-signed limits on a delegate's authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationCert<K = PublicKey> {
    /// Identifier used for revocation.
    pub cert_id: Id,
    /// Delegate's algorithm-tagged public key.
    pub delegate_pub: K,
    /// Product for which the delegate may sign leases.
    pub product: String,
    /// Earliest permitted issuance time, inclusive.
    pub not_before: u64,
    /// Latest permitted issuance time, inclusive.
    pub not_after: u64,
    /// Maximum lease lifetime including its offline grace, in seconds.
    pub max_lease_secs: u64,
    /// Highest tier the delegate may grant.
    pub max_tier: u8,
    /// Product-defined slots and intervals the delegate may grant.
    pub feature_mask: FeatureSlots,
}

impl<K> DelegationCert<K> {
    pub(crate) fn with_delegate<T>(self, delegate_pub: T) -> DelegationCert<T> {
        DelegationCert {
            cert_id: self.cert_id,
            delegate_pub,
            product: self.product,
            not_before: self.not_before,
            not_after: self.not_after,
            max_lease_secs: self.max_lease_secs,
            max_tier: self.max_tier,
            feature_mask: self.feature_mask,
        }
    }
}

/// The claims of an author-signed revocation list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Crl {
    /// Positive publisher-wide sequence number.
    pub seq: u64,
    /// Unix seconds at issuance.
    pub issued_at: u64,
    /// Revoked individual licenses.
    pub revoked_licenses: Vec<Id>,
    /// Revoked purchases and their leases.
    pub revoked_entitlements: Vec<Id>,
    /// Revoked certificates and earliest affected issuance time, inclusive.
    pub revoked_certs: Vec<(Id, u64)>,
}

/// Causes for failure when handling licenses and authenticated state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LicenseError {
    /// The wire framing or payload is invalid.
    #[error("malformed license data")]
    Malformed,
    /// The envelope version is unsupported.
    #[error("unsupported envelope version")]
    UnsupportedVersion,
    /// The envelope names an unsupported signature algorithm.
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
    /// The indicated master key is unavailable or ambiguous.
    #[error("unknown or ambiguous master key id")]
    UnknownKeyId,
    /// The data failed strict Ed25519 verification.
    #[error("bad signature")]
    BadSignature,
    /// The embedded delegation certificate could not be authenticated.
    #[error("bad delegation certificate")]
    BadDelegation,
    /// A lease exceeds its delegation's authority.
    #[error("lease exceeds delegation authority")]
    DelegationViolation,
    /// The license authorizes another product.
    #[error("wrong product")]
    WrongProduct,
    /// The authorization has not started.
    #[error("license is not yet valid")]
    NotYetValid,
    /// All authorized use, including grace, has expired.
    #[error("license expired")]
    Expired,
    /// The application version exceeds the licensed maximum.
    #[error("application version is not covered")]
    VersionNotCovered,
    /// Proof of possession of the designated device key failed.
    #[error("device proof failed")]
    DeviceProofFailed,
    /// The configured device signer could not sign a challenge.
    #[error(transparent)]
    DeviceKey(#[from] DeviceKeyError),
    /// A license or its purchase has been revoked.
    #[error("license or entitlement revoked")]
    Revoked,
    /// The delegate was revoked for this issuance time.
    #[error("delegation certificate revoked")]
    CertRevoked,
    /// The clock moved backwards beyond the configured tolerance.
    #[error("clock rollback")]
    ClockRollback,
    /// A signed CRL is older than one already accepted.
    #[error("revocation list rollback")]
    CrlRollback,
    /// The current authenticated revocation list is missing.
    #[error("current revocation list unavailable")]
    CrlUnavailable,
    /// A configured build tag check failed.
    #[error("license tag mismatch")]
    TagMismatch,
    /// The built-in verification self-test failed.
    #[error("verification self-test failed")]
    Tampered,
    /// The SKU has no available activation seat.
    #[error("activation seat limit reached")]
    SeatLimit,
    /// The device has no active registration.
    #[error("device is deactivated")]
    Deactivated,
    /// This authenticated request has already been seen.
    #[error("request nonce already used")]
    Replay,
    /// The operating system random source failed.
    #[error("operating system randomness unavailable")]
    Randomness,
    /// Authenticated client state could not be persisted.
    #[error("license state storage failed")]
    StateStorage,
    /// The configured author or delegate signing provider failed.
    #[error(transparent)]
    Signing(#[from] SigningError),
}

/// Causes for failure when asking a device provider to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DeviceKeyError {
    /// The device or key handle is unavailable.
    #[error("device signing key is unavailable")]
    Unavailable,
    /// Access is denied or the user canceled authorization.
    #[error("device signing was denied")]
    Denied,
    /// The device did not produce an Ed25519 signature.
    #[error("device signing failed")]
    SigningFailed,
}

/// Local interface to a device signing key, including non-exportable hardware keys.
///
/// An adapter can retain a hardware key handle and delegate signing to the device.
/// The contract requires an canonical signature for the advertised public-key algorithm.
/// A valid signature establishes possession. Device hardware is not attested.
pub trait DeviceProver {
    /// Returns the device's algorithm-tagged public key.
    fn public(&self) -> PublicKey;
    /// Signs a challenge with the device private key.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider is unavailable or fails to authorize or sign.
    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], DeviceKeyError>;
}

impl<T: DeviceProver + ?Sized> DeviceProver for Box<T> {
    fn public(&self) -> PublicKey {
        self.as_ref().public()
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], DeviceKeyError> {
        self.as_ref().sign(msg)
    }
}

/// Application-supplied conditions for local verification.
pub struct VerifyOptions<'a> {
    /// Expected product identifier.
    pub product: &'a str,
    /// Current application version.
    pub app_version: AppVersion,
    /// Unix seconds from the caller's clock.
    pub now: u64,
    /// Local device key, if available.
    pub device: Option<&'a dyn DeviceProver>,
    /// An authenticated, current revocation list.
    pub crl: Option<&'a Crl>,
    /// Tolerance for a future activation timestamp and clock rollback.
    pub clock_skew_secs: u64,
}

impl fmt::Debug for VerifyOptions<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("product", &self.product)
            .field("app_version", &self.app_version)
            .field("now", &self.now)
            .field("has_device", &self.device.is_some())
            .field("crl_seq", &self.crl.map(|crl| crl.seq))
            .field("clock_skew_secs", &self.clock_skew_secs)
            .finish()
    }
}

impl<'a> VerifyOptions<'a> {
    /// Builds options with the default 300-second clock tolerance.
    pub fn new(product: &'a str, app_version: AppVersion, now: u64) -> Self {
        Self {
            product,
            app_version,
            now,
            device: None,
            crl: None,
            clock_skew_secs: 300,
        }
    }
}

/// Metadata for a verified purchase requiring activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementInfo {
    /// Purchase identifier used for device proofs.
    pub entitlement_id: Id,
    /// Product to activate.
    pub product: String,
    /// Maximum active seats.
    pub max_devices: u8,
}

/// A locally verified authorization or an authenticated purchase.
#[derive(Debug)]
pub enum VerifyOutcome {
    /// The authorization is currently active.
    Active(VerifiedLicense),
    /// The authorization remains usable and renewal is suggested.
    RenewSoon(VerifiedLicense),
    /// Offline grace remains available for the given number of seconds.
    Grace(VerifiedLicense, u64),
    /// The purchase still requires activation.
    NeedsActivation(EntitlementInfo),
}

/// The current renewal and usability state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseState {
    /// The authorization is active.
    Active,
    /// The authorization is active and eligible for renewal.
    RenewSoon {
        /// First suggested renewal time, in Unix seconds.
        since: u64,
    },
    /// Offline grace is in effect.
    Grace {
        /// Seconds until grace ends.
        remaining_secs: u64,
    },
    /// Authorization and grace have expired.
    Expired,
    /// The purchase must be activated.
    NeedsActivation,
    /// The presented data failed verification.
    Invalid(LicenseError),
}

impl VerifyOutcome {
    /// Gets the current renewal state without exposing the original token.
    pub fn state(&self) -> LicenseState {
        match self {
            Self::Active(_) => LicenseState::Active,
            Self::RenewSoon(license) => LicenseState::RenewSoon {
                since: license.signed.payload().renew_after.unwrap_or_default(),
            },
            Self::Grace(_, remaining_secs) => LicenseState::Grace {
                remaining_secs: *remaining_secs,
            },
            Self::NeedsActivation(_) => LicenseState::NeedsActivation,
        }
    }

    /// Returns a usable authorization if verification granted access.
    pub fn license(&self) -> Option<&VerifiedLicense> {
        match self {
            Self::Active(license) | Self::RenewSoon(license) | Self::Grace(license, _) => {
                Some(license)
            }
            Self::NeedsActivation(_) => None,
        }
    }
}

/// A verified capability retaining the original signed bytes for later checks.
#[derive(Debug)]
pub struct VerifiedLicense {
    pub(crate) signed: Box<SignedLicense>,
}

impl VerifiedLicense {
    /// Exposes authenticated license claims.
    pub fn payload(&self) -> &LicensePayload {
        self.signed.payload()
    }

    /// Looks up the resource key for a licensed feature.
    pub fn unlock_key(&self, feature_id: u16) -> Option<&[u8; 32]> {
        self.payload()
            .unlock
            .iter()
            .find_map(|(id, key)| (*id == feature_id).then_some(key))
    }

    /// Re-authenticates the original bytes and checks their time and build tags.
    ///
    /// # Errors
    ///
    /// Returns a verification error if the signature, time or build tags fail.
    /// For fresh CRL and device checks, use [Self::recheck_with].
    pub fn recheck(&self, verifier: &Verifier, now: u64) -> Result<(), LicenseError> {
        verifier.recheck(self, now)
    }

    /// Repeats full verification with the caller's current device and CRL.
    ///
    /// # Errors
    ///
    /// Returns a verification error if the authorization is no longer usable.
    pub fn recheck_with(
        &self,
        verifier: &Verifier,
        opts: &VerifyOptions<'_>,
    ) -> Result<(), LicenseError> {
        verifier.verify_bytes(self.signed.bytes(), opts).map(|_| ())
    }
}

/// Durable monotonic state used by the verifier and activation client.
pub trait StateStore {
    /// Reads the highest authenticated CRL sequence observed.
    fn get_max_crl_seq(&self) -> Option<u64>;
    /// Records the highest authenticated CRL sequence observed.
    fn set_max_crl_seq(&mut self, seq: u64);
    /// Reads the highest time observed.
    fn get_last_seen_time(&self) -> Option<u64>;
    /// Records a new highest time.
    fn set_last_seen_time(&mut self, time: u64);
    /// Reads the current lease as textual token bytes.
    fn get_lease(&self) -> Option<Vec<u8>>;
    /// Replaces the current lease.
    fn set_lease(&mut self, token: &[u8]);
    /// Reads the signed purchase from the last activation if this store retains it.
    fn get_entitlement(&self) -> Option<Vec<u8>> {
        None
    }
    /// Records the signed purchase. An empty token clears it.
    fn set_entitlement(&mut self, _token: &[u8]) {}
    /// Reads the signed CRL bytes if supported by this store.
    fn get_crl(&self) -> Option<Vec<u8>> {
        None
    }
    /// Records the signed CRL bytes if supported by this store.
    fn set_crl(&mut self, _bytes: &[u8]) {}
    /// Persists preceding changes before returning.
    ///
    /// # Errors
    ///
    /// Returns an error if the update cannot be persisted.
    fn flush(&mut self) -> Result<(), LicenseError> {
        Ok(())
    }
}

/// Advances the observed time using the default 300-second tolerance.
///
/// # Errors
///
/// Returns an error if clock rollback is detected or storage fails.
pub fn check_clock(now: u64, store: &mut dyn StateStore) -> Result<(), LicenseError> {
    check_clock_with_skew(now, store, 300).map(|_| ())
}

/// Advances the observed time and returns the effective monotonic time.
///
/// # Errors
///
/// Returns an error if clock rollback is detected or storage fails.
pub fn check_clock_with_skew(
    now: u64,
    store: &mut dyn StateStore,
    skew: u64,
) -> Result<u64, LicenseError> {
    let last = store.get_last_seen_time().unwrap_or_default();
    if now.saturating_add(skew) < last {
        return Err(LicenseError::ClockRollback);
    }
    if now > last {
        store.set_last_seen_time(now);
    }
    // The in-memory watermark may already include an earlier failed write.
    store.flush()?;
    Ok(now.max(last))
}

/// Gets bytes from the operating system CSPRNG.
///
/// # Errors
///
/// Returns an error if the operating system random source fails.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], LicenseError> {
    let mut output = [0; N];
    getrandom::fill(&mut output).map_err(|_| LicenseError::Randomness)?;
    Ok(output)
}

/// Validates the product identifier accepted by the wire format.
///
/// # Errors
///
/// Returns [LicenseError::Malformed] for an empty, oversized or non-printable identifier.
pub fn validate_product(product: &str) -> Result<(), LicenseError> {
    if product.is_empty()
        || product.len() > 32
        || !product
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err(LicenseError::Malformed);
    }
    Ok(())
}
