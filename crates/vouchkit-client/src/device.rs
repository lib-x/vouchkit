use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;

use thiserror::Error;
use vouchkit_core::{
    DeviceKeyError, DeviceProver, LicenseError, PublicKey, SigningAlgorithm, SigningError,
    SigningKey, SigningProvider, SoftwareSigningKey, generate_signing_seed,
};
use zeroize::Zeroizing;

use crate::state::{directory, open_private, private_temp, sync_directory};

const SECRET_BYTES: usize = 32;
const P256_PREFIX: &[u8] = b"VOUCHKIT-DEVICE-P256-2\0";
const MAX_DEVICE_KEY_BYTES: usize = P256_PREFIX.len() + SECRET_BYTES;

/// A device prover suitable for activation and renewal.
///
/// Implement [DeviceProver] around a platform key handle to use a
/// non-exportable Ed25519 or P-256 key. The signer can return a typed device error
/// when authentication, hardware access, or signing fails.
/// For a P-256 provider that returns an ASN.1 DER signature, use
/// [vouchkit_core::normalize_p256_der_signature] to obtain the protocol bytes.
pub trait DeviceKeyStore: DeviceProver + Send + Sync {}

impl<T: DeviceProver + Send + Sync + ?Sized> DeviceKeyStore for T {}

/// An Ed25519 or P-256 device key held by this application process.
pub struct DeviceKey(SoftwareSigningKey);

impl DeviceKey {
    /// Wraps an Ed25519 seed held by the caller.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_seed(seed).into())
    }

    /// Wraps a caller-held Ed25519 seed or P-256 scalar.
    ///
    /// # Errors
    ///
    /// Rejects key material that violates the selected algorithm's requirements.
    pub fn from_seed_with_algorithm(
        algorithm: SigningAlgorithm,
        seed: &[u8; 32],
    ) -> Result<Self, SigningError> {
        SoftwareSigningKey::from_seed(algorithm, seed).map(Self)
    }

    /// Creates an ephemeral Ed25519 device key.
    ///
    /// # Errors
    ///
    /// Returns an error if the system random source fails.
    pub fn generate() -> Result<Self, LicenseError> {
        let seed = Zeroizing::new(generate_signing_seed(SigningAlgorithm::Ed25519)?);
        Ok(Self::from_seed(&seed))
    }

    /// Creates an ephemeral device key for the selected algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if the random source or key construction fails.
    pub fn generate_with_algorithm(
        algorithm: SigningAlgorithm,
    ) -> Result<Self, DeviceStorageError> {
        let seed = Zeroizing::new(generate_signing_seed(algorithm)?);
        Ok(Self::from_seed_with_algorithm(algorithm, &seed)?)
    }

    /// Returns the signing algorithm used by this device key.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.0.public_key().algorithm()
    }

    /// Loads an Ed25519 or P-256 key from a private file.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failure, invalid key data, or unsafe file
    /// permissions on Unix.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, DeviceStorageError> {
        let file = open_private(path.as_ref())?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(MAX_DEVICE_KEY_BYTES + 1));
        file.take((MAX_DEVICE_KEY_BYTES + 1) as u64)
            .read_to_end(&mut encoded)?;
        decode_key(&encoded)
    }

    /// Loads or atomically creates the device's private key file.
    ///
    /// An existing key may use either supported algorithm. New keys use
    /// Ed25519. On Unix the file is created and checked with mode 0600.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable randomness, insecure permissions,
    /// an invalid key file, or an I/O failure.
    pub fn open_or_create_file(path: impl AsRef<Path>) -> Result<Self, DeviceStorageError> {
        Self::ensure_file(path.as_ref(), None)
    }

    /// Loads or atomically creates the private key file with the selected algorithm.
    ///
    /// # Examples
    ///
    /// ```
    /// use vouchkit_client::DeviceKey;
    /// use vouchkit_core::SigningAlgorithm;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let app_data = tempfile::tempdir()?;
    /// let path = app_data.path().join("device.key");
    /// let key = DeviceKey::open_or_create_file_with_algorithm(path, SigningAlgorithm::P256)?;
    /// assert_eq!(key.algorithm(), SigningAlgorithm::P256);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Also returns an error if the file already holds a key of a different
    /// algorithm. The stored key is left intact.
    pub fn open_or_create_file_with_algorithm(
        path: impl AsRef<Path>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, DeviceStorageError> {
        Self::ensure_file(path.as_ref(), Some(algorithm))
    }

    fn ensure_file(
        path: &Path,
        expected: Option<SigningAlgorithm>,
    ) -> Result<Self, DeviceStorageError> {
        match Self::load_file(path) {
            Ok(key) => return require_algorithm(key, expected),
            Err(DeviceStorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let (key, encoded) = provision_key(expected)?;
        let parent = directory(path);
        let mut temp = private_temp(parent)?;
        temp.write_all(&encoded)?;
        temp.as_file().sync_all()?;
        match temp.persist_noclobber(path) {
            Ok(_) => {
                sync_directory(parent)?;
                Ok(key)
            }
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                require_algorithm(Self::load_file(path)?, expected)
            }
            Err(error) => Err(error.error.into()),
        }
    }

    /// Loads or provisions a key in the platform credential store.
    ///
    /// Cooperating processes must provide the same application-owned lock
    /// path for a service and account. The private key lives in the OS
    /// credential store and is loaded into memory for signing. An existing
    /// key may use either algorithm. New keys use Ed25519.
    ///
    /// # Errors
    ///
    /// Returns an error if the provisioning lock, random source, or OS
    /// credential store is unavailable, or if the stored key is invalid.
    #[cfg(all(
        feature = "keyring",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    pub fn open_or_create_keyring(
        service: &str,
        account: &str,
        lock_path: impl AsRef<Path>,
    ) -> Result<Self, DeviceStorageError> {
        Self::ensure_keyring(service, account, lock_path.as_ref(), None)
    }

    /// Loads or provisions a key of the selected algorithm in the platform credential store.
    ///
    /// # Errors
    ///
    /// Returns an error if provisioning fails or the stored key uses a
    /// different algorithm. The stored key is left intact.
    #[cfg(all(
        feature = "keyring",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    pub fn open_or_create_keyring_with_algorithm(
        service: &str,
        account: &str,
        lock_path: impl AsRef<Path>,
        algorithm: SigningAlgorithm,
    ) -> Result<Self, DeviceStorageError> {
        Self::ensure_keyring(service, account, lock_path.as_ref(), Some(algorithm))
    }

    #[cfg(all(
        feature = "keyring",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    fn ensure_keyring(
        service: &str,
        account: &str,
        lock_path: &Path,
        expected: Option<SigningAlgorithm>,
    ) -> Result<Self, DeviceStorageError> {
        let _lock = crate::state::lock_file(lock_path)?;
        let entry = keyring::Entry::new(service, account)?;
        match entry.get_secret() {
            Ok(secret) => {
                let secret = Zeroizing::new(secret);
                require_algorithm(decode_key(&secret)?, expected)
            }
            Err(keyring::Error::NoEntry) => {
                let (key, encoded) = provision_key(expected)?;
                entry.set_secret(&encoded)?;
                Ok(key)
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl DeviceProver for DeviceKey {
    fn public(&self) -> PublicKey {
        self.0.public_key()
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], DeviceKeyError> {
        self.0
            .try_sign(msg)
            .map_err(|_| DeviceKeyError::SigningFailed)
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKey").finish_non_exhaustive()
    }
}

fn decode_key(encoded: &[u8]) -> Result<DeviceKey, DeviceStorageError> {
    let (algorithm, seed) = if encoded.len() == SECRET_BYTES {
        (SigningAlgorithm::Ed25519, encoded)
    } else {
        let seed = encoded
            .strip_prefix(P256_PREFIX)
            .ok_or(DeviceStorageError::Invalid)?;
        (SigningAlgorithm::P256, seed)
    };
    let seed = seed.try_into().map_err(|_| DeviceStorageError::Invalid)?;
    DeviceKey::from_seed_with_algorithm(algorithm, seed).map_err(|_| DeviceStorageError::Invalid)
}

fn provision_key(
    requested: Option<SigningAlgorithm>,
) -> Result<(DeviceKey, Zeroizing<Vec<u8>>), DeviceStorageError> {
    let algorithm = requested.unwrap_or(SigningAlgorithm::Ed25519);
    let prefix = if algorithm == SigningAlgorithm::Ed25519 {
        &[][..]
    } else if algorithm == SigningAlgorithm::P256 {
        P256_PREFIX
    } else {
        return Err(DeviceStorageError::UnsupportedAlgorithm);
    };
    let seed = Zeroizing::new(generate_signing_seed(algorithm)?);
    let key = DeviceKey::from_seed_with_algorithm(algorithm, &seed)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(prefix.len() + seed.len()));
    encoded.extend_from_slice(prefix);
    encoded.extend_from_slice(seed.as_ref());
    Ok((key, encoded))
}

fn require_algorithm(
    key: DeviceKey,
    expected: Option<SigningAlgorithm>,
) -> Result<DeviceKey, DeviceStorageError> {
    if let Some(expected) = expected {
        let actual = key.algorithm();
        if actual != expected {
            return Err(DeviceStorageError::AlgorithmMismatch { expected, actual });
        }
    }
    Ok(key)
}

/// Errors loading or provisioning a device key.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeviceStorageError {
    /// The private file or provisioning lock could not be accessed.
    #[error("device key I/O failed")]
    Io(#[from] io::Error),
    /// The private key data has invalid framing or key material.
    #[error("invalid device key data")]
    Invalid,
    /// Key generation failed.
    #[error("device key generation failed")]
    Randomness(#[from] LicenseError),
    /// The requested key material is invalid for the signing algorithm.
    #[error("device key construction failed")]
    Signing(#[from] SigningError),
    /// The client has no storage format for this algorithm.
    #[error("unsupported device key algorithm")]
    UnsupportedAlgorithm,
    /// The stored key disagrees with the explicitly requested algorithm.
    #[error("device key algorithm mismatch (expected {expected:?}, stored {actual:?})")]
    AlgorithmMismatch {
        /// Algorithm requested by the caller.
        expected: SigningAlgorithm,
        /// Algorithm present in the stored key.
        actual: SigningAlgorithm,
    },
    /// The platform credential store reported an error.
    #[cfg(all(
        feature = "keyring",
        any(target_os = "linux", target_os = "macos", target_os = "windows")
    ))]
    #[error("device credential storage failed")]
    Keyring(#[from] keyring::Error),
}

#[cfg(test)]
mod tests {
    use vouchkit_core::{DeviceProver, PublicKey, SigningAlgorithm};

    use super::{DeviceKey, DeviceStorageError, P256_PREFIX, decode_key};

    #[test]
    fn reuses_the_same_file_key() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device.key");
        let first = DeviceKey::open_or_create_file(&path)?;
        let second = DeviceKey::open_or_create_file(&path)?;
        assert_eq!(first.algorithm(), SigningAlgorithm::Ed25519);
        assert_eq!(first.public(), second.public());
        assert_eq!(first.sign(b"fixture")?, second.sign(b"fixture")?);
        assert_eq!(std::fs::metadata(path)?.len(), 32);
        Ok(())
    }

    #[test]
    fn reuses_p256_key_and_does_not_replace_it_on_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device.key");
        let first = DeviceKey::open_or_create_file_with_algorithm(&path, SigningAlgorithm::P256)?;
        assert!(matches!(first.public(), PublicKey::P256(_)));
        assert_eq!(first.algorithm(), SigningAlgorithm::P256);
        let encoded = zeroize::Zeroizing::new(std::fs::read(&path)?);
        assert!(encoded.starts_with(b"VOUCHKIT-DEVICE-P256-2\0"));
        assert_eq!(encoded.len(), P256_PREFIX.len() + 32);
        assert!(matches!(
            DeviceKey::open_or_create_file_with_algorithm(&path, SigningAlgorithm::Ed25519),
            Err(DeviceStorageError::AlgorithmMismatch {
                expected: SigningAlgorithm::Ed25519,
                actual: SigningAlgorithm::P256,
            }),
        ));
        let second = DeviceKey::open_or_create_file(&path)?;
        assert_eq!(first.public(), second.public());
        assert_eq!(first.sign(b"fixture")?, second.sign(b"fixture")?);
        Ok(())
    }

    #[test]
    fn rejects_invalid_p256_scalars_and_extended_file_encodings() {
        let mut encoded = P256_PREFIX.to_vec();
        encoded.extend_from_slice(&[0; 32]);
        assert!(matches!(
            decode_key(&encoded),
            Err(DeviceStorageError::Invalid)
        ));

        if let Some(last) = encoded.last_mut() {
            *last = 1;
        }
        assert!(decode_key(&encoded).is_ok());
        encoded.push(0);
        assert!(matches!(
            decode_key(&encoded),
            Err(DeviceStorageError::Invalid)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_keys_and_symlinks() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device.key");
        let link = dir.path().join("link");
        DeviceKey::open_or_create_file(&path)?;
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
        symlink(&path, &link)?;
        assert!(DeviceKey::load_file(link).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
        assert!(DeviceKey::load_file(path).is_err());
        Ok(())
    }
}
