use std::fmt;
use std::io::{self, Read, Write};
use std::path::Path;

use thiserror::Error;
use vouchkit_core::{DeviceKeyError, DeviceProver, LicenseError, SigningKey, random_bytes};
use zeroize::Zeroizing;

use crate::state::{directory, open_private, private_temp, sync_directory};

/// A device prover suitable for activation and renewal.
///
/// Implement [DeviceProver] around a platform key handle to use a
/// non-exportable Ed25519 key. The signer can return a typed device error
/// when authentication, hardware access, or signing fails.
pub trait DeviceKeyStore: DeviceProver + Send + Sync {}

impl<T: DeviceProver + Send + Sync + ?Sized> DeviceKeyStore for T {}

/// An Ed25519 device key held by this application process.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    /// Wraps a seed held by the caller.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_seed(seed))
    }

    /// Creates an ephemeral device key.
    ///
    /// # Errors
    ///
    /// Returns an error if the system random source fails.
    pub fn generate() -> Result<Self, LicenseError> {
        let seed = Zeroizing::new(random_bytes()?);
        Ok(Self::from_seed(&seed))
    }

    /// Loads a 32-byte seed from a private file.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failure, an unexpected file size, or unsafe
    /// file permissions on Unix.
    pub fn load_file(path: impl AsRef<Path>) -> Result<Self, DeviceStorageError> {
        let mut file = open_private(path.as_ref())?;
        let mut seed = Zeroizing::new([0; 32]);
        file.read_exact(seed.as_mut())
            .map_err(|error| match error.kind() {
                io::ErrorKind::UnexpectedEof => DeviceStorageError::Invalid,
                _ => error.into(),
            })?;
        let mut tail = Zeroizing::new([0]);
        if file.read(tail.as_mut())? != 0 {
            return Err(DeviceStorageError::Invalid);
        }
        Ok(Self::from_seed(&seed))
    }

    /// Loads or atomically creates the device's private key file.
    ///
    /// Keep the file in an application-owned directory. On Unix the file is
    /// created with mode 0600 and existing files require that mode.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable randomness, insecure permissions,
    /// an invalid key file, or an I/O failure.
    pub fn open_or_create_file(path: impl AsRef<Path>) -> Result<Self, DeviceStorageError> {
        let path = path.as_ref();
        match Self::load_file(path) {
            Ok(key) => return Ok(key),
            Err(DeviceStorageError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let seed = Zeroizing::new(random_bytes()?);
        let parent = directory(path);
        let mut temp = private_temp(parent)?;
        temp.write_all(seed.as_ref())?;
        temp.as_file().sync_all()?;
        match temp.persist_noclobber(path) {
            Ok(_) => {
                sync_directory(parent)?;
                Ok(Self::from_seed(&seed))
            }
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
                Self::load_file(path)
            }
            Err(error) => Err(error.error.into()),
        }
    }

    /// Loads or provisions a key in the platform credential store.
    ///
    /// Cooperating processes must provide the same application-owned lock
    /// path for a service and account. The private key lives in the OS
    /// credential store and is loaded into memory for signing.
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
        let _lock = crate::state::lock_file(lock_path.as_ref())?;
        let entry = keyring::Entry::new(service, account)?;
        match entry.get_secret() {
            Ok(secret) => {
                let secret = Zeroizing::new(secret);
                let seed = secret
                    .as_slice()
                    .try_into()
                    .map_err(|_| DeviceStorageError::Invalid)?;
                Ok(Self::from_seed(seed))
            }
            Err(keyring::Error::NoEntry) => {
                let seed = Zeroizing::new(random_bytes()?);
                entry.set_secret(seed.as_ref())?;
                Ok(Self::from_seed(&seed))
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl DeviceProver for DeviceKey {
    fn public(&self) -> [u8; 32] {
        self.0.public()
    }

    fn sign(&self, msg: &[u8]) -> Result<[u8; 64], DeviceKeyError> {
        Ok(self.0.sign(msg))
    }
}

impl fmt::Debug for DeviceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKey").finish_non_exhaustive()
    }
}

/// Errors loading or provisioning a device key.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DeviceStorageError {
    /// The private file or provisioning lock could not be accessed.
    #[error("device key I/O failed")]
    Io(#[from] io::Error),
    /// The private key data has an unexpected size.
    #[error("invalid device key data")]
    Invalid,
    /// Key generation failed.
    #[error("device key generation failed")]
    Randomness(#[from] LicenseError),
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
    use super::{DeviceKey, DeviceProver};

    #[test]
    fn reuses_the_same_file_key() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("device.key");
        let first = DeviceKey::open_or_create_file(&path)?;
        let second = DeviceKey::open_or_create_file(&path)?;
        assert_eq!(first.public(), second.public());
        assert_eq!(first.sign(b"fixture")?, second.sign(b"fixture")?);
        assert_eq!(std::fs::metadata(path)?.len(), 32);
        Ok(())
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
