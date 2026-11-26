use std::{fmt, mem};

use ed25519_dalek::{Signer, VerifyingKey};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::{
    Class, Crl, DelegationCert, LicenseError, LicensePayload, PublicKey, SigningAlgorithm,
    SigningProvider, validate_product,
};

const LICENSE: u8 = 1;
const CRL: u8 = 2;
const CERTIFICATE: u8 = 3;
const MASTER: u8 = 0;
const DELEGATE: u8 = 1;
const SIGNATURE_SIZE: usize = 64;
const MAX_PAYLOAD: usize = 768;
const MAX_CERTIFICATE: usize = 256;
const MAX_CRL_ENTRIES: usize = 8_192;
pub(crate) const MAX_CRL_BYTES: usize = MAX_CRL_ENTRIES * 26 + 128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum WireVersion {
    V1 = 1,
    V2 = 2,
}

impl WireVersion {
    fn for_keys(keys: impl IntoIterator<Item = PublicKey>) -> Self {
        if keys
            .into_iter()
            .all(|key| key.algorithm() == SigningAlgorithm::Ed25519)
        {
            Self::V1
        } else {
            Self::V2
        }
    }

    fn algorithm(self, rest: &[u8]) -> Result<(SigningAlgorithm, &[u8]), LicenseError> {
        match self {
            Self::V1 => Ok((SigningAlgorithm::Ed25519, rest)),
            Self::V2 => {
                let (&tag, rest) = rest.split_first().ok_or(LicenseError::Malformed)?;
                Ok((SigningAlgorithm::from_wire_tag(tag)?, rest))
            }
        }
    }

    fn append_algorithm(self, output: &mut Vec<u8>, public: PublicKey) {
        if self == Self::V2 {
            output.push(public.algorithm().wire_tag());
        }
    }

    fn domain(self, kind: u8) -> &'static [u8] {
        match (self, kind) {
            (Self::V1, LICENSE) => b"vouchkit-license-v1\0",
            (Self::V1, CRL) => b"vouchkit-crl-v1\0",
            (Self::V1, CERTIFICATE) => b"vouchkit-delegation-v1\0",
            (Self::V2, LICENSE) => b"vouchkit-license-v2\0",
            (Self::V2, CRL) => b"vouchkit-crl-v2\0",
            (Self::V2, CERTIFICATE) => b"vouchkit-delegation-v2\0",
            // Only fixed envelope kinds reach the signing or verifying calls.
            _ => b"vouchkit-invalid-kind\0",
        }
    }
}

/// Failures reported by an author or delegation signing provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SigningError {
    /// The signing key or provider is unavailable.
    #[error("signing key is unavailable")]
    Unavailable,
    /// The requested private-key representation is not valid for its algorithm.
    #[error("invalid signing key")]
    InvalidKey,
    /// The provider denied the requested signature.
    #[error("signing request was denied")]
    Denied,
    /// The provider could not produce a signature.
    #[error("signing provider failed")]
    ProviderFailed,
    /// The returned signature did not verify with the configured public key.
    #[error("signing provider returned an invalid signature")]
    InvalidSignature,
}

/// Pluggable Ed25519 author and delegation signing, including external key providers.
///
/// The provider must return a stable public key and sign the original message using
/// pure Ed25519. Implementations can keep their key material inside a hardware device
/// or a key service. Signing functions strictly verify the provider's signature.
pub trait Ed25519Signer {
    /// Returns the provider's stable Ed25519 public key.
    fn public(&self) -> [u8; 32];

    /// Signs the entire domain-separated message using pure Ed25519.
    ///
    /// # Errors
    ///
    /// Returns a provider error if the key is unavailable, signing is denied, or signing fails.
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SigningError>;
}

/// An Ed25519 signing key whose storage is cleared when dropped.
pub struct SigningKey(ed25519_dalek::SigningKey);

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.public())
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    /// Imports an Ed25519 seed. The caller owns the input seed and its lifecycle.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }

    /// Returns the Ed25519 public key.
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs a challenge or another domain-separated byte sequence.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(message).to_bytes()
    }
}

impl Ed25519Signer for SigningKey {
    fn public(&self) -> [u8; 32] {
        SigningKey::public(self)
    }

    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SigningError> {
        Ok(self.sign(message))
    }
}

/// License and certificate metadata decoded without authentication.
#[derive(Debug)]
pub struct InspectedLicense {
    /// Author key identifier named by the license header.
    pub key_id: u8,
    /// Claims from the untrusted license payload.
    pub payload: LicensePayload,
    /// Untrusted embedded delegation certificate if present.
    pub delegation: Option<DelegationCert>,
}

/// A structurally valid license authenticated by a configured master key.
pub struct SignedLicense {
    key_id: u8,
    payload: LicensePayload,
    certificate: Option<DelegationCert>,
    bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SignedLicense {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedLicense")
            .field("key_id", &self.key_id)
            .field("payload", &self.payload)
            .field("certificate", &self.certificate)
            .finish_non_exhaustive()
    }
}

impl SignedLicense {
    /// Returns the master key ID for the authenticated signature chain.
    pub fn key_id(&self) -> u8 {
        self.key_id
    }
    /// Returns the authenticated license claims.
    pub fn payload(&self) -> &LicensePayload {
        &self.payload
    }
    /// Returns the authenticated certificate for a delegated license.
    pub fn certificate(&self) -> Option<&DelegationCert> {
        self.certificate.as_ref()
    }
    /// Returns the originally authenticated data.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Applies revocation entries to this license.
    ///
    /// # Errors
    ///
    /// Returns the corresponding revocation error if a matching entry is in force.
    pub fn check_revocation(&self, crl: Option<&Crl>) -> Result<(), LicenseError> {
        let Some(crl) = crl else { return Ok(()) };
        if crl.revoked_licenses.contains(&self.payload.license_id)
            || crl
                .revoked_entitlements
                .contains(&self.payload.entitlement_id)
        {
            return Err(LicenseError::Revoked);
        }
        if let Some(cert) = self.certificate()
            && crl
                .revoked_certs
                .iter()
                .any(|(id, since)| *id == cert.cert_id && self.payload.issued_at >= *since)
        {
            return Err(LicenseError::CertRevoked);
        }
        Ok(())
    }

    /// Checks that the signed activation time has arrived and grace has not ended.
    ///
    /// # Errors
    ///
    /// Returns a time-related license error when use is outside the allowed interval.
    pub fn check_time(&self, now: u64, skew: u64) -> Result<(), LicenseError> {
        let payload = self.payload();
        let start = payload
            .not_before
            .unwrap_or(payload.issued_at)
            .max(payload.issued_at);
        if now.saturating_add(skew) < start {
            return Err(LicenseError::NotYetValid);
        }
        if let Some(expires_at) = payload.expires_at
            && now >= expires_at.saturating_add(u64::from(payload.grace_secs))
        {
            return Err(LicenseError::Expired);
        }
        Ok(())
    }

    pub(crate) fn check_delegation(&self) -> Result<(), LicenseError> {
        if let Some(certificate) = self.certificate() {
            delegation_limits(certificate, self.payload())?;
        } else if self.payload.class == Class::Lease {
            return Err(LicenseError::DelegationViolation);
        }
        Ok(())
    }
}

fn signed_message(domain: &[u8], body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut message = Zeroizing::new(Vec::with_capacity(domain.len() + body.len()));
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    message
}

fn authenticate_signature(
    key: PublicKey,
    algorithm: SigningAlgorithm,
    domain: &[u8],
    body: &[u8],
    signature: &[u8],
) -> Result<(), LicenseError> {
    if key.algorithm() != algorithm {
        return Err(LicenseError::BadSignature);
    }
    key.verify(&signed_message(domain, body), signature)
}

pub(crate) fn public_key(bytes: &[u8; 32]) -> Result<VerifyingKey, LicenseError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| LicenseError::BadSignature)?;
    if key.is_weak() {
        return Err(LicenseError::BadSignature);
    }
    Ok(key)
}

fn encode_payload<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, LicenseError> {
    postcard::to_allocvec(value)
        .map(Zeroizing::new)
        .map_err(|_| LicenseError::Malformed)
}

fn decode_payload<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, LicenseError> {
    let (value, remaining) =
        postcard::take_from_bytes(bytes).map_err(|_| LicenseError::Malformed)?;
    if !remaining.is_empty() {
        return Err(LicenseError::Malformed);
    }
    Ok(value)
}

fn validate_header(bytes: &[u8], kind: u8) -> Result<WireVersion, LicenseError> {
    match bytes {
        [1, actual, ..] if *actual == kind => Ok(WireVersion::V1),
        [2, actual, ..] if *actual == kind => Ok(WireVersion::V2),
        [version, ..] if !matches!(version, 1 | 2) => Err(LicenseError::UnsupportedVersion),
        _ => Err(LicenseError::Malformed),
    }
}

fn split_signature(bytes: &[u8]) -> Result<(&[u8], &[u8]), LicenseError> {
    bytes
        .split_at_checked(
            bytes
                .len()
                .checked_sub(SIGNATURE_SIZE)
                .ok_or(LicenseError::Malformed)?,
        )
        .ok_or(LicenseError::Malformed)
}

fn finish_signing(
    body: Vec<u8>,
    domain: &[u8],
    key: &(impl SigningProvider + ?Sized),
    public: PublicKey,
) -> Result<Vec<u8>, LicenseError> {
    let mut body = Zeroizing::new(body);
    let message = signed_message(domain, &body);
    public.validate().map_err(|_| SigningError::InvalidKey)?;
    let signature = key.try_sign(&message)?;
    public
        .verify(&message, &signature)
        .map_err(|_| SigningError::InvalidSignature)?;
    body.extend_from_slice(&signature);
    Ok(mem::take(&mut *body))
}

fn push_short(output: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), LicenseError> {
    if bytes.len() > max || bytes.is_empty() {
        return Err(LicenseError::Malformed);
    }
    let len = u16::try_from(bytes.len()).map_err(|_| LicenseError::Malformed)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn take_short(bytes: &[u8], max: usize) -> Result<(&[u8], &[u8]), LicenseError> {
    let [high, low, rest @ ..] = bytes else {
        return Err(LicenseError::Malformed);
    };
    let len = usize::from(u16::from_be_bytes([*high, *low]));
    if len == 0 || len > max {
        return Err(LicenseError::Malformed);
    }
    rest.split_at_checked(len).ok_or(LicenseError::Malformed)
}

struct LicenseFrame<'a> {
    version: WireVersion,
    algorithm: SigningAlgorithm,
    key_id: u8,
    certificate: Option<&'a [u8]>,
    payload: &'a [u8],
    body: &'a [u8],
    signature: &'a [u8],
}

fn license_frame(bytes: &[u8]) -> Result<LicenseFrame<'_>, LicenseError> {
    let version = validate_header(bytes, LICENSE)?;
    let (body, signature) = split_signature(bytes)?;
    let [_, _, signer, key_id, rest @ ..] = body else {
        return Err(LicenseError::Malformed);
    };
    let (algorithm, rest) = version.algorithm(rest)?;
    let (certificate, rest) = match *signer {
        MASTER => (None, rest),
        DELEGATE => {
            let (cert, rest) = take_short(rest, MAX_CERTIFICATE)?;
            (Some(cert), rest)
        }
        _ => return Err(LicenseError::Malformed),
    };
    let (payload, remaining) = take_short(rest, MAX_PAYLOAD)?;
    if !remaining.is_empty() {
        return Err(LicenseError::Malformed);
    }
    Ok(LicenseFrame {
        version,
        algorithm,
        key_id: *key_id,
        certificate,
        payload,
        body,
        signature,
    })
}

fn validate_license(payload: &LicensePayload) -> Result<(), LicenseError> {
    validate_product(&payload.product)?;
    if payload.subject.len() > 64
        || payload.subject.chars().any(char::is_control)
        || payload.unlock.len() > 4
        || payload
            .unlock
            .iter()
            .any(|(id, _)| !payload.features.contains(*id))
        || payload.unlock.iter().enumerate().any(|(index, (id, _))| {
            payload
                .unlock
                .iter()
                .take(index)
                .any(|(other, _)| id == other)
        })
        || payload.expires_at.is_some_and(|end| {
            end <= payload.issued_at
                || payload.not_before.is_some_and(|start| end <= start)
                || end.checked_add(u64::from(payload.grace_secs)).is_none()
        })
        || payload.expires_at.is_none() && payload.grace_secs != 0
        || payload.renew_after.is_some_and(|renew| {
            payload.class != Class::Lease
                || renew < payload.issued_at
                || payload.expires_at.is_none_or(|end| renew >= end)
        })
        || payload.class == Class::Entitlement
            && (payload.max_devices == 0 || payload.device_pub.is_some())
    {
        return Err(LicenseError::Malformed);
    }
    if let Some(device) = &payload.device_pub {
        device.validate().map_err(|_| LicenseError::Malformed)?;
    }
    Ok(())
}

fn validate_certificate(cert: &DelegationCert) -> Result<(), LicenseError> {
    validate_product(&cert.product)?;
    if cert.not_before > cert.not_after || cert.max_lease_secs == 0 {
        return Err(LicenseError::Malformed);
    }
    cert.delegate_pub
        .validate()
        .map_err(|_| LicenseError::Malformed)?;
    Ok(())
}

fn delegation_limits(cert: &DelegationCert, payload: &LicensePayload) -> Result<(), LicenseError> {
    let total = payload
        .expires_at
        .and_then(|end| end.checked_add(u64::from(payload.grace_secs)))
        .and_then(|end| end.checked_sub(payload.issued_at));
    if payload.class != Class::Lease
        || payload.device_pub.is_none()
        || payload.product != cert.product
        || !(cert.not_before..=cert.not_after).contains(&payload.issued_at)
        || total.is_none_or(|total| total == 0 || total > cert.max_lease_secs)
        || payload.tier > cert.max_tier
        || !payload.features.is_subset_of(&cert.feature_mask)
    {
        return Err(LicenseError::DelegationViolation);
    }
    Ok(())
}

fn encode_license_payload(
    version: WireVersion,
    payload: &LicensePayload,
) -> Result<Zeroizing<Vec<u8>>, LicenseError> {
    match version {
        WireVersion::V2 => encode_payload(payload),
        WireVersion::V1 => {
            let legacy = payload.clone().map_device(|key| match key {
                PublicKey::Ed25519(bytes) => Ok(bytes),
                PublicKey::P256(_) => Err(LicenseError::Malformed),
            })?;
            encode_payload(&legacy)
        }
    }
}

fn decode_license_payload(
    version: WireVersion,
    payload: &[u8],
) -> Result<LicensePayload, LicenseError> {
    let payload = match version {
        WireVersion::V2 => decode_payload(payload)?,
        WireVersion::V1 => {
            decode_payload::<LicensePayload<[u8; 32]>>(payload)?.map_device(|key| Ok(key.into()))?
        }
    };
    validate_license(&payload)?;
    Ok(payload)
}

fn build_license(
    key_id: u8,
    key: &(impl SigningProvider + ?Sized),
    certificate: Option<(&[u8], PublicKey)>,
    payload: &LicensePayload,
) -> Result<Vec<u8>, LicenseError> {
    let signer = if certificate.is_some() {
        DELEGATE
    } else {
        MASTER
    };
    let public = certificate.map_or_else(|| key.public_key(), |(_, public)| public);
    let mut version =
        WireVersion::for_keys([Some(public), payload.device_pub].into_iter().flatten());
    if certificate.is_some_and(|(bytes, _)| bytes.first() == Some(&(WireVersion::V2 as u8))) {
        version = WireVersion::V2;
    }
    let mut output = Vec::with_capacity(crate::codec::MAX_TOKEN_BYTES);
    output.extend_from_slice(&[version as u8, LICENSE, signer, key_id]);
    version.append_algorithm(&mut output, public);
    if let Some((bytes, _)) = certificate {
        push_short(&mut output, bytes, MAX_CERTIFICATE)?;
    }
    push_short(
        &mut output,
        &encode_license_payload(version, payload)?,
        MAX_PAYLOAD,
    )?;
    finish_signing(output, version.domain(LICENSE), key, public)
}

/// Signs an author-issued standalone license or purchase.
///
/// # Errors
///
/// Rejects invalid claims or a lease class.
pub fn sign_master(
    key_id: u8,
    key: &(impl SigningProvider + ?Sized),
    payload: &LicensePayload,
) -> Result<Vec<u8>, LicenseError> {
    validate_license(payload)?;
    if payload.class == Class::Lease {
        return Err(LicenseError::DelegationViolation);
    }
    build_license(key_id, key, None, payload)
}

/// Signs a device lease within the embedded certificate's recorded limits.
///
/// # Errors
///
/// Rejects invalid claims, a mismatched delegate key or a lease outside the certificate limits.
/// The server is responsible for authenticating the certificate at configuration time.
pub fn sign_lease(
    key_id: u8,
    key: &(impl SigningProvider + ?Sized),
    certificate: &[u8],
    payload: &LicensePayload,
) -> Result<Vec<u8>, LicenseError> {
    let (cert_id, cert) = inspect_certificate(certificate)?;
    if cert_id != key_id || cert.delegate_pub != key.public_key() {
        return Err(LicenseError::BadDelegation);
    }
    validate_license(payload)?;
    delegation_limits(&cert, payload)?;
    build_license(key_id, key, Some((certificate, cert.delegate_pub)), payload)
}

/// Signs a delegation certificate using the author's key.
///
/// # Errors
///
/// Rejects invalid claims and certificates that cannot fit in a lease.
pub fn sign_delegation(
    key_id: u8,
    key: &(impl SigningProvider + ?Sized),
    certificate: &DelegationCert,
) -> Result<Vec<u8>, LicenseError> {
    validate_certificate(certificate)?;
    let public = key.public_key();
    let version = WireVersion::for_keys([public, certificate.delegate_pub]);
    let mut output = vec![version as u8, CERTIFICATE, key_id];
    version.append_algorithm(&mut output, public);
    let payload = match version {
        WireVersion::V2 => encode_payload(certificate)?,
        WireVersion::V1 => {
            let PublicKey::Ed25519(bytes) = certificate.delegate_pub else {
                return Err(LicenseError::Malformed);
            };
            encode_payload(&certificate.clone().with_delegate(bytes))?
        }
    };
    let max_payload = MAX_CERTIFICATE - output.len() - 2 - SIGNATURE_SIZE;
    push_short(&mut output, &payload, max_payload)?;
    finish_signing(output, version.domain(CERTIFICATE), key, public)
}

#[derive(Clone, Copy)]
struct RootFrame<'a> {
    version: WireVersion,
    algorithm: SigningAlgorithm,
    key_id: u8,
    rest: &'a [u8],
    body: &'a [u8],
    signature: &'a [u8],
}

fn root_frame(bytes: &[u8], kind: u8, max: usize) -> Result<RootFrame<'_>, LicenseError> {
    let version = validate_header(bytes, kind)?;
    if bytes.len() > max {
        return Err(LicenseError::Malformed);
    }
    let (body, signature) = split_signature(bytes)?;
    let [_, _, key_id, rest @ ..] = body else {
        return Err(LicenseError::Malformed);
    };
    let (algorithm, rest) = version.algorithm(rest)?;
    Ok(RootFrame {
        version,
        algorithm,
        key_id: *key_id,
        rest,
        body,
        signature,
    })
}

fn certificate_payload(frame: RootFrame<'_>) -> Result<&[u8], LicenseError> {
    let (payload, remaining) = take_short(frame.rest, MAX_CERTIFICATE)?;
    if !remaining.is_empty() {
        return Err(LicenseError::Malformed);
    }
    Ok(payload)
}

fn decode_certificate(
    version: WireVersion,
    payload: &[u8],
) -> Result<DelegationCert, LicenseError> {
    let cert = match version {
        WireVersion::V2 => decode_payload(payload)?,
        WireVersion::V1 => {
            let legacy = decode_payload::<DelegationCert<[u8; 32]>>(payload)?;
            let public = legacy.delegate_pub.into();
            legacy.with_delegate(public)
        }
    };
    validate_certificate(&cert)?;
    Ok(cert)
}

fn inspect_certificate(bytes: &[u8]) -> Result<(u8, DelegationCert), LicenseError> {
    let frame = root_frame(bytes, CERTIFICATE, MAX_CERTIFICATE)?;
    let payload = certificate_payload(frame)?;
    Ok((frame.key_id, decode_certificate(frame.version, payload)?))
}

pub(crate) fn authenticate_certificate(
    bytes: &[u8],
    key_lookup: impl FnOnce(u8) -> Result<PublicKey, LicenseError>,
) -> Result<(u8, DelegationCert), LicenseError> {
    let frame = root_frame(bytes, CERTIFICATE, MAX_CERTIFICATE)?;
    let payload = certificate_payload(frame)?;
    authenticate_signature(
        key_lookup(frame.key_id)?,
        frame.algorithm,
        frame.version.domain(CERTIFICATE),
        frame.body,
        frame.signature,
    )?;
    Ok((frame.key_id, decode_certificate(frame.version, payload)?))
}

fn validate_crl(crl: &Crl) -> Result<(), LicenseError> {
    let entries = crl
        .revoked_licenses
        .len()
        .saturating_add(crl.revoked_entitlements.len())
        .saturating_add(crl.revoked_certs.len());
    if crl.seq == 0 || entries > MAX_CRL_ENTRIES {
        return Err(LicenseError::Malformed);
    }
    Ok(())
}

fn crl_payload(frame: RootFrame<'_>) -> Result<&[u8], LicenseError> {
    let [a, b, c, d, payload @ ..] = frame.rest else {
        return Err(LicenseError::Malformed);
    };
    if usize::try_from(u32::from_be_bytes([*a, *b, *c, *d])).ok() != Some(payload.len()) {
        return Err(LicenseError::Malformed);
    }
    Ok(payload)
}

/// Signs a cumulative, positive-sequence revocation list.
///
/// # Errors
///
/// Rejects an invalid sequence or a list larger than the protocol permits.
pub fn sign_crl(
    key_id: u8,
    key: &(impl SigningProvider + ?Sized),
    crl: &Crl,
) -> Result<Vec<u8>, LicenseError> {
    validate_crl(crl)?;
    let payload = encode_payload(crl)?;
    let len = u32::try_from(payload.len()).map_err(|_| LicenseError::Malformed)?;
    let public = key.public_key();
    let version = WireVersion::for_keys([public]);
    let mut output = vec![version as u8, CRL, key_id];
    version.append_algorithm(&mut output, public);
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(&payload);
    finish_signing(output, version.domain(CRL), key, public)
}

pub(crate) fn authenticate_crl(
    bytes: &[u8],
    key_lookup: impl FnOnce(u8) -> Result<PublicKey, LicenseError>,
) -> Result<Crl, LicenseError> {
    let frame = root_frame(bytes, CRL, MAX_CRL_BYTES)?;
    let payload = crl_payload(frame)?;
    authenticate_signature(
        key_lookup(frame.key_id)?,
        frame.algorithm,
        frame.version.domain(CRL),
        frame.body,
        frame.signature,
    )?;
    let crl = decode_payload(payload)?;
    validate_crl(&crl)?;
    Ok(crl)
}

/// Parses a framed license without verifying its signatures.
///
/// # Errors
///
/// Rejects unsupported or malformed envelopes. The returned claims remain untrusted.
pub fn inspect_license(bytes: &[u8]) -> Result<InspectedLicense, LicenseError> {
    let frame = license_frame(bytes)?;
    let delegation = frame
        .certificate
        .map(inspect_certificate)
        .transpose()?
        .map(|(_, cert)| cert);
    let payload = decode_license_payload(frame.version, frame.payload)?;
    Ok(InspectedLicense {
        key_id: frame.key_id,
        payload,
        delegation,
    })
}

pub(crate) fn authenticate_license(
    bytes: &[u8],
    key_lookup: impl Fn(u8) -> Result<PublicKey, LicenseError>,
) -> Result<SignedLicense, LicenseError> {
    let frame = license_frame(bytes)?;
    let (key, certificate) = if let Some(embedded) = frame.certificate {
        // Preserve UnknownKeyId when the outer key is unknown and reject certificate substitution.
        key_lookup(frame.key_id)?;
        let (key_id, cert) = authenticate_certificate(embedded, key_lookup)
            .map_err(|_| LicenseError::BadDelegation)?;
        if key_id != frame.key_id {
            return Err(LicenseError::BadDelegation);
        }
        if frame.version == WireVersion::V1 && embedded.first() != Some(&(WireVersion::V1 as u8)) {
            return Err(LicenseError::BadDelegation);
        }
        if cert.delegate_pub.algorithm() != frame.algorithm {
            return Err(LicenseError::BadDelegation);
        }
        (cert.delegate_pub, Some(cert))
    } else {
        (key_lookup(frame.key_id)?, None)
    };
    authenticate_signature(
        key,
        frame.algorithm,
        frame.version.domain(LICENSE),
        frame.body,
        frame.signature,
    )?;
    let payload = decode_license_payload(frame.version, frame.payload)?;
    Ok(SignedLicense {
        key_id: frame.key_id,
        payload,
        certificate,
        bytes: Zeroizing::new(bytes.to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FeatureSlots, Verifier, VerifyOptions};

    #[test]
    fn a_valid_delegate_signature_cannot_exceed_certificate_limits() -> Result<(), LicenseError> {
        let lease = include_bytes!("../tests/fixtures/lease.bin");
        let cert = include_bytes!("../tests/fixtures/delegation.bin");
        let master = SigningKey::from_seed(&[17; 32]);
        let delegate = SigningKey::from_seed(&[34; 32]);
        let verifier = Verifier::new(&[(255, master.public())], None);
        let base = inspect_license(lease)?.payload;
        let opts = VerifyOptions::new(&base.product, (1, 0, 0), base.issued_at);
        let mut payloads = vec![base.clone(); 9];

        payloads[0].class = Class::Standalone;
        payloads[0].renew_after = None;
        payloads[1].device_pub = None;
        payloads[2].expires_at = Some(base.issued_at + 901);
        payloads[3].issued_at = base.issued_at - 61;
        payloads[4].issued_at = base.issued_at + 61;
        payloads[5].tier = base.tier + 1;
        payloads[6].features = FeatureSlots::try_from_ranges(&[(2050, 2080)])?;
        payloads[7].expires_at = None;
        payloads[7].renew_after = None;
        payloads[7].grace_secs = 0;
        payloads[8].grace_secs = 301;
        for payload in payloads {
            let bytes = build_license(
                255,
                &delegate,
                Some((cert, delegate.public().into())),
                &payload,
            )?;
            assert_eq!(
                verifier.verify_bytes(&bytes, &opts).unwrap_err(),
                LicenseError::DelegationViolation
            );
        }
        let mut other = base.clone();
        other.product = "different".into();
        let bytes = build_license(
            255,
            &delegate,
            Some((cert, delegate.public().into())),
            &other,
        )?;
        let wrong_product = VerifyOptions::new(&other.product, (1, 0, 0), base.issued_at);
        assert_eq!(
            verifier.verify_bytes(&bytes, &wrong_product).unwrap_err(),
            LicenseError::DelegationViolation
        );

        let mut bad_cert = cert.to_vec();
        *bad_cert.last_mut().ok_or(LicenseError::Malformed)? ^= 1;
        let bytes = build_license(
            255,
            &delegate,
            Some((&bad_cert, delegate.public().into())),
            &base,
        )?;
        assert_eq!(
            verifier.verify_bytes(&bytes, &opts).unwrap_err(),
            LicenseError::BadDelegation
        );
        Ok(())
    }
}
