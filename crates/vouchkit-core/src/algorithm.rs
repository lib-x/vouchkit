use std::fmt;

use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256Key, VerifyingKey as P256Verifier,
    signature::{Signer as _, Verifier as _},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Ed25519Signer, LicenseError, SigningError, SigningKey, random_bytes, wire};

/// A digital signature algorithm with a canonical format supported by vouchkit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// Pure Ed25519 as defined by RFC 8032.
    Ed25519,
    /// ECDSA on secp256r1, with SHA-256 and a low-S fixed-size signature.
    P256,
}

impl SigningAlgorithm {
    pub(crate) const fn wire_tag(self) -> u8 {
        match self {
            Self::Ed25519 => 0,
            Self::P256 => 1,
        }
    }

    pub(crate) fn from_wire_tag(tag: u8) -> Result<Self, LicenseError> {
        match tag {
            0 => Ok(Self::Ed25519),
            1 => Ok(Self::P256),
            _ => Err(LicenseError::UnsupportedAlgorithm),
        }
    }
}

/// An algorithm-tagged public key. Constructors for other formats must canonicalize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PublicKey {
    /// The raw 32-byte Ed25519 public key.
    Ed25519([u8; 32]),
    /// The compressed 33-byte SEC1 representation of a secp256r1 point.
    P256(#[serde(with = "compressed_point")] [u8; 33]),
}

impl PublicKey {
    /// Identifies the algorithm bound to this public key.
    pub const fn algorithm(&self) -> SigningAlgorithm {
        match self {
            Self::Ed25519(_) => SigningAlgorithm::Ed25519,
            Self::P256(_) => SigningAlgorithm::P256,
        }
    }

    /// Returns the canonical public-key bytes for this algorithm.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ed25519(bytes) => bytes,
            Self::P256(bytes) => bytes,
        }
    }

    /// Validates and imports a compressed SEC1 P-256 public key.
    ///
    /// # Errors
    ///
    /// Rejects non-compressed or malformed secp256r1 points.
    pub fn from_p256_sec1(bytes: &[u8]) -> Result<Self, LicenseError> {
        let key = Self::P256(bytes.try_into().map_err(|_| LicenseError::Malformed)?);
        key.validate().map_err(|_| LicenseError::Malformed)?;
        Ok(key)
    }

    /// Checks that this key has a usable canonical representation.
    ///
    /// # Errors
    ///
    /// Rejects malformed SEC1 points and weak or malformed Ed25519 keys.
    pub fn validate(&self) -> Result<(), LicenseError> {
        match self {
            Self::Ed25519(bytes) => wire::public_key(bytes).map(|_| ()),
            Self::P256(bytes) => p256_verifier(bytes).map(|_| ()),
        }
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), LicenseError> {
        match self {
            Self::Ed25519(bytes) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| LicenseError::Malformed)?;
                wire::public_key(bytes)?
                    .verify_strict(message, &signature)
                    .map_err(|_| LicenseError::BadSignature)
            }
            Self::P256(bytes) => {
                let signature =
                    P256Signature::from_slice(signature).map_err(|_| LicenseError::BadSignature)?;
                if signature != signature.normalize_s() {
                    return Err(LicenseError::BadSignature);
                }
                p256_verifier(bytes)?
                    .verify(message, &signature)
                    .map_err(|_| LicenseError::BadSignature)
            }
        }
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(value: [u8; 32]) -> Self {
        Self::Ed25519(value)
    }
}

fn p256_verifier(bytes: &[u8; 33]) -> Result<P256Verifier, LicenseError> {
    if !matches!(bytes.first(), Some(2 | 3)) {
        return Err(LicenseError::BadSignature);
    }
    P256Verifier::from_sec1_bytes(bytes).map_err(|_| LicenseError::BadSignature)
}

/// A provider of algorithm-bound author, delegate or hardware signing operations.
///
/// The provider must return a stable key and sign the full message. For ECDSA P-256
/// return the canonical 64-byte concatenation of big-endian `r` and low-`s`.
pub trait SigningProvider {
    /// The algorithm and canonical public key corresponding to this provider.
    fn public_key(&self) -> PublicKey;

    /// Signs a domain-separated protocol message.
    ///
    /// # Errors
    ///
    /// Returns a typed failure if signing is unavailable or refused.
    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SigningError>;
}

impl<T: Ed25519Signer + ?Sized> SigningProvider for T {
    fn public_key(&self) -> PublicKey {
        Ed25519Signer::public(self).into()
    }

    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SigningError> {
        Ed25519Signer::try_sign(self, message)
    }
}

impl SigningProvider for Box<dyn SigningProvider + Send + Sync> {
    fn public_key(&self) -> PublicKey {
        self.as_ref().public_key()
    }

    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SigningError> {
        self.as_ref().try_sign(message)
    }
}

/// A software Ed25519 or P-256 signer with zeroizing private-key storage.
pub struct SoftwareSigningKey {
    inner: SoftwareKey,
}

enum SoftwareKey {
    Ed25519(SigningKey),
    P256(P256Key, [u8; 33]),
}

impl fmt::Debug for SoftwareSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareSigningKey")
            .field("algorithm", &self.public_key().algorithm())
            .finish_non_exhaustive()
    }
}

impl SoftwareSigningKey {
    /// Imports an Ed25519 seed or a 32-byte big-endian secp256r1 private scalar.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the P-256 scalar falls outside the valid range.
    pub fn from_seed(algorithm: SigningAlgorithm, seed: &[u8; 32]) -> Result<Self, SigningError> {
        match algorithm {
            SigningAlgorithm::Ed25519 => Ok(SigningKey::from_seed(seed).into()),
            SigningAlgorithm::P256 => {
                let key = P256Key::from_slice(seed).map_err(|_| SigningError::InvalidKey)?;
                let point = key.verifying_key().to_sec1_point(true);
                let public = point
                    .as_bytes()
                    .try_into()
                    .map_err(|_| SigningError::InvalidKey)?;
                Ok(Self {
                    inner: SoftwareKey::P256(key, public),
                })
            }
        }
    }
}

impl From<SigningKey> for SoftwareSigningKey {
    fn from(key: SigningKey) -> Self {
        Self {
            inner: SoftwareKey::Ed25519(key),
        }
    }
}

impl SigningProvider for SoftwareSigningKey {
    fn public_key(&self) -> PublicKey {
        match &self.inner {
            SoftwareKey::Ed25519(key) => key.public().into(),
            SoftwareKey::P256(_, public) => PublicKey::P256(*public),
        }
    }

    fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SigningError> {
        match &self.inner {
            SoftwareKey::Ed25519(key) => Ok(key.sign(message)),
            SoftwareKey::P256(key, _) => {
                let signature: P256Signature = key
                    .try_sign(message)
                    .map_err(|_| SigningError::ProviderFailed)?;
                Ok(signature.normalize_s().to_bytes().into())
            }
        }
    }
}

/// Generates a valid raw Ed25519 seed or a 32-byte secp256r1 private scalar.
///
/// # Errors
///
/// Returns an error if the operating system random source is unavailable.
/// The caller is responsible for protecting and clearing the returned secret.
pub fn generate_signing_seed(algorithm: SigningAlgorithm) -> Result<[u8; 32], LicenseError> {
    for _ in 0..16 {
        let seed = Zeroizing::new(random_bytes()?);
        let valid = match algorithm {
            SigningAlgorithm::Ed25519 => true,
            SigningAlgorithm::P256 => P256Key::from_slice(seed.as_ref()).is_ok(),
        };
        if valid {
            return Ok(*seed);
        }
    }
    Err(LicenseError::Randomness)
}

/// Converts an HSM's ASN.1 DER ECDSA P-256 signature to canonical protocol bytes.
///
/// # Errors
///
/// Rejects invalid DER or a signature with invalid scalar components.
pub fn normalize_p256_der_signature(der: &[u8]) -> Result<[u8; 64], SigningError> {
    let signature = P256Signature::from_der(der).map_err(|_| SigningError::InvalidSignature)?;
    Ok(signature.normalize_s().to_bytes().into())
}

mod compressed_point {
    use serde::{
        Deserializer, Serializer,
        de::{Error, SeqAccess, Visitor},
        ser::SerializeTuple,
    };
    use std::fmt;

    pub(super) fn serialize<S: Serializer>(
        key: &[u8; 33],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(key.len())?;
        for byte in key {
            tuple.serialize_element(byte)?;
        }
        tuple.end()
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 33], D::Error> {
        struct PointVisitor;

        impl<'de> Visitor<'de> for PointVisitor {
            type Value = [u8; 33];

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 33-byte compressed SEC1 point")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut key = [0; 33];
                for (index, byte) in key.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| A::Error::invalid_length(index, &self))?;
                }
                Ok(key)
            }
        }
        de.deserialize_tuple(33, PointVisitor)
    }
}
