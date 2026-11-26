//! Shared activation messages and request-bound device proofs.

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::{
    AppVersion, DeviceProver, Id, LicenseError, decode_token, random_bytes, wire::public_key,
};

/// Maximum allowed binary size of a signed revocation list.
pub const MAX_CRL_BYTES: usize = crate::wire::MAX_CRL_BYTES;
/// Maximum allowed response or request size for activation JSON.
pub const MAX_JSON_BYTES: usize = 8_192;
const PROOF_DOMAIN: &[u8] = b"vouchkit-activate-v1\0";

fn serialize_bytes<const N: usize, S: Serializer>(
    value: &[u8; N],
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode_base64(value))
}

fn deserialize_bytes<'de, const N: usize, D: Deserializer<'de>>(d: D) -> Result<[u8; N], D::Error> {
    let text = String::deserialize(d)?;
    decode_base64(&text).map_err(D::Error::custom)
}

fn serialize_hint<S: Serializer>(value: &Option<Id>, s: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(bytes) => s.serialize_some(&encode_base64(bytes)),
        None => s.serialize_none(),
    }
}

fn deserialize_hint<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Id>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|text| decode_base64(&text).map_err(D::Error::custom))
        .transpose()
}

/// Encodes a binary protocol field with unpadded Base64URL.
pub fn encode_base64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes a fixed-size unpadded Base64URL field.
///
/// # Errors
///
/// Returns [LicenseError::Malformed] for incorrect size or encoding.
pub fn decode_base64<const N: usize>(text: &str) -> Result<[u8; N], LicenseError> {
    if text.len() != N.saturating_mul(8).div_ceil(6) {
        return Err(LicenseError::Malformed);
    }
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| LicenseError::Malformed)?
        .try_into()
        .map_err(|_| LicenseError::Malformed)
}

/// Reads a standard Base64 Ed25519 public key, with optional padding.
///
/// # Errors
///
/// Returns [LicenseError::Malformed] for invalid keys.
pub fn decode_public_key(text: &str) -> Result<[u8; 32], LicenseError> {
    let text = text.trim();
    let decoded = match text.len() {
        43 => STANDARD_NO_PAD.decode(text),
        44 => STANDARD.decode(text),
        _ => return Err(LicenseError::Malformed),
    }
    .map_err(|_| LicenseError::Malformed)?;
    let key: [u8; 32] = decoded.try_into().map_err(|_| LicenseError::Malformed)?;
    public_key(&key).map_err(|_| LicenseError::Malformed)?;
    Ok(key)
}

/// Parses an author public key line in `key_id:base64` form.
///
/// # Errors
///
/// Returns [LicenseError::Malformed] if the format or public key is invalid.
pub fn parse_master_public_key(text: &str) -> Result<(u8, [u8; 32]), LicenseError> {
    let (id, key) = text.trim().split_once(':').ok_or(LicenseError::Malformed)?;
    Ok((
        id.parse().map_err(|_| LicenseError::Malformed)?,
        decode_public_key(key)?,
    ))
}

/// Device-authenticated request to activate a purchase.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateRequest {
    /// Signed purchase credential.
    pub entitlement_token: String,
    /// Device public key to bind.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub device_pub: [u8; 32],
    /// Optional diagnostic fingerprint.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_hint",
        deserialize_with = "deserialize_hint"
    )]
    pub device_hint: Option<Id>,
    /// Requesting application's version.
    pub app_version: AppVersion,
    /// Fresh random request nonce.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub nonce: Id,
    /// Ed25519 request proof.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub proof: [u8; 64],
}

/// Device-authenticated request to renew a lease.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewRequest {
    /// Current or recently expired signed lease.
    pub lease_token: String,
    /// Fresh random request nonce.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub nonce: Id,
    /// Ed25519 request proof.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub proof: [u8; 64],
}

/// Device-authenticated request to release an activation seat.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeactivateRequest {
    /// Lease credential when deactivating via lease.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_token: Option<String>,
    /// Purchase credential when deactivating via entitlement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entitlement_token: Option<String>,
    /// Public key of the seat to release.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub device_pub: [u8; 32],
    /// Fresh random request nonce.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub nonce: Id,
    /// Ed25519 request proof.
    #[serde(
        serialize_with = "serialize_bytes",
        deserialize_with = "deserialize_bytes"
    )]
    pub proof: [u8; 64],
}

/// Response to a successful activation or renewal.
#[derive(Clone, Serialize, Deserialize)]
pub struct LeaseResponse {
    /// Device-bound signed lease.
    pub lease_token: String,
    /// Issuance time authenticated by the signed lease.
    pub server_time: u64,
    /// Current server CRL sequence, or zero if no CRL has been installed.
    pub crl_seq: u64,
}

macro_rules! redact_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    )+};
}
redact_debug!(
    ActivateRequest,
    RenewRequest,
    DeactivateRequest,
    LeaseResponse
);

/// Response to a successful deactivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeactivateResponse {
    /// Whether the requested seat was released.
    pub ok: bool,
}

/// Machine-readable error response from an activation server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable error code for host and UI handling.
    pub code: ErrorCode,
}

/// Stable wire error names for reference activation servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ErrorCode {
    /// The request did not match the schema.
    BadRequest,
    /// The supplied authorization could not be authenticated or used.
    InvalidLicense,
    /// The device failed proof of possession.
    DeviceProofFailed,
    /// There are no available activation seats.
    SeatLimit,
    /// The device's activation was removed.
    Deactivated,
    /// The underlying license or purchase was revoked.
    Revoked,
    /// The lease was issued within a revoked delegate period.
    CertRevoked,
    /// The user must obtain a fresh usable credential.
    Expired,
    /// The requesting application version is not covered.
    VersionNotCovered,
    /// The request has already been processed.
    Replay,
    /// The caller exceeded its request budget.
    RateLimited,
    /// The server cannot currently issue leases.
    Unavailable,
    /// An internal service failure occurred.
    Internal,
    /// Fallback for a code added by a newer server.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy)]
enum Operation {
    Activate = 1,
    Renew = 2,
    DeactivateLease = 3,
    DeactivateEntitlement = 4,
}

struct ProofInput<'a> {
    operation: Operation,
    token: &'a str,
    public: [u8; 32],
    nonce: Id,
    activation: Option<(AppVersion, Option<Id>)>,
}

impl ProofInput<'_> {
    fn message(&self, entitlement_id: Id) -> Result<Vec<u8>, LicenseError> {
        let token = zeroize::Zeroizing::new(decode_token(self.token)?);
        let mut message = Vec::with_capacity(144);
        message.extend_from_slice(PROOF_DOMAIN);
        message.extend_from_slice(&self.nonce);
        message.extend_from_slice(&entitlement_id);
        message.extend_from_slice(&self.public);
        message.push(self.operation as u8);
        message.extend_from_slice(blake3::hash(&token).as_bytes());
        if let Some(((a, b, c), hint)) = self.activation {
            for version in [a, b, c] {
                message.extend_from_slice(&version.to_be_bytes());
            }
            message.push(u8::from(hint.is_some()));
            if let Some(hint) = hint {
                message.extend_from_slice(&hint);
            }
        }
        Ok(message)
    }

    fn verify(&self, entitlement_id: Id, proof: &[u8; 64]) -> Result<(), LicenseError> {
        let key = public_key(&self.public).map_err(|_| LicenseError::DeviceProofFailed)?;
        key.verify_strict(
            &self.message(entitlement_id)?,
            &Signature::from_bytes(proof),
        )
        .map_err(|_| LicenseError::DeviceProofFailed)
    }
}

impl ActivateRequest {
    /// Creates and signs an activation request with a fresh nonce.
    ///
    /// # Errors
    ///
    /// Rejects malformed token text or unavailable secure randomness.
    pub fn new(
        entitlement_token: String,
        entitlement_id: Id,
        device: &dyn DeviceProver,
        device_hint: Option<Id>,
        app_version: AppVersion,
    ) -> Result<Self, LicenseError> {
        let mut request = Self {
            entitlement_token,
            device_pub: device.public(),
            device_hint,
            app_version,
            nonce: random_bytes()?,
            proof: [0; 64],
        };
        request.proof = device.sign(&request.input().message(entitlement_id)?)?;
        Ok(request)
    }

    fn input(&self) -> ProofInput<'_> {
        ProofInput {
            operation: Operation::Activate,
            token: &self.entitlement_token,
            public: self.device_pub,
            nonce: self.nonce,
            activation: Some((self.app_version, self.device_hint)),
        }
    }

    /// Validates request authenticity for a purchase identified from the signed token.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid device proof or malformed token.
    pub fn verify_proof(&self, entitlement_id: Id) -> Result<(), LicenseError> {
        self.input().verify(entitlement_id, &self.proof)
    }
}

impl RenewRequest {
    /// Creates and signs a renewal request with a fresh nonce.
    ///
    /// # Errors
    ///
    /// Rejects malformed token text or unavailable secure randomness.
    pub fn new(
        lease_token: String,
        entitlement_id: Id,
        device: &dyn DeviceProver,
    ) -> Result<Self, LicenseError> {
        let mut request = Self {
            lease_token,
            nonce: random_bytes()?,
            proof: [0; 64],
        };
        request.proof = device.sign(&request.input(device.public()).message(entitlement_id)?)?;
        Ok(request)
    }

    fn input(&self, public: [u8; 32]) -> ProofInput<'_> {
        ProofInput {
            operation: Operation::Renew,
            token: &self.lease_token,
            public,
            nonce: self.nonce,
            activation: None,
        }
    }

    /// Validates request authenticity against the authenticated lease's device.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid device proof or malformed token.
    pub fn verify_proof(
        &self,
        entitlement_id: Id,
        device_pub: [u8; 32],
    ) -> Result<(), LicenseError> {
        self.input(device_pub).verify(entitlement_id, &self.proof)
    }
}

impl DeactivateRequest {
    /// Creates and signs a deactivation using a lease credential.
    ///
    /// # Errors
    ///
    /// Rejects malformed token text or unavailable secure randomness.
    pub fn lease(
        token: String,
        entitlement_id: Id,
        device: &dyn DeviceProver,
    ) -> Result<Self, LicenseError> {
        Self::new(Some(token), None, entitlement_id, device)
    }

    /// Creates and signs a deactivation using a purchase credential.
    ///
    /// # Errors
    ///
    /// Rejects malformed token text or unavailable secure randomness.
    pub fn entitlement(
        token: String,
        entitlement_id: Id,
        device: &dyn DeviceProver,
    ) -> Result<Self, LicenseError> {
        Self::new(None, Some(token), entitlement_id, device)
    }

    fn new(
        lease_token: Option<String>,
        entitlement_token: Option<String>,
        entitlement_id: Id,
        device: &dyn DeviceProver,
    ) -> Result<Self, LicenseError> {
        let mut request = Self {
            lease_token,
            entitlement_token,
            device_pub: device.public(),
            nonce: random_bytes()?,
            proof: [0; 64],
        };
        request.proof = device.sign(&request.input()?.message(entitlement_id)?)?;
        Ok(request)
    }

    fn input(&self) -> Result<ProofInput<'_>, LicenseError> {
        let (operation, token) = match (&self.lease_token, &self.entitlement_token) {
            (Some(token), None) => (Operation::DeactivateLease, token),
            (None, Some(token)) => (Operation::DeactivateEntitlement, token),
            _ => return Err(LicenseError::Malformed),
        };
        Ok(ProofInput {
            operation,
            token,
            public: self.device_pub,
            nonce: self.nonce,
            activation: None,
        })
    }

    /// Validates proof for the exact deactivation route and credential.
    ///
    /// # Errors
    ///
    /// Returns an error for ambiguous inputs, malformed tokens or an invalid proof.
    pub fn verify_proof(&self, entitlement_id: Id) -> Result<(), LicenseError> {
        self.input()?.verify(entitlement_id, &self.proof)
    }
}
