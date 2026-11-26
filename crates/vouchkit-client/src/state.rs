use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use vouchkit_core::protocol::MAX_CRL_BYTES;
use vouchkit_core::{LicenseError, MAX_TOKEN_TEXT, StateStore};
use zeroize::{Zeroize, Zeroizing};

const STATE_VERSION: u8 = 1;
const MAX_STATE_FILE: usize = MAX_CRL_BYTES + 2 * MAX_TOKEN_TEXT + 64;

/// An in-memory cache for one product, device and publisher key ring.
#[derive(Default, Serialize, Deserialize)]
pub struct MemoryStateStore {
    max_crl_seq: Option<u64>,
    last_seen_time: Option<u64>,
    lease: Option<Vec<u8>>,
    entitlement: Option<Vec<u8>>,
    crl: Option<Vec<u8>>,
}

impl MemoryStateStore {
    /// Starts with an empty lease, CRL and clock watermark.
    pub fn new() -> Self {
        Self::default()
    }

    fn valid_size(&self) -> bool {
        self.lease
            .as_ref()
            .is_none_or(|lease| lease.len() <= MAX_TOKEN_TEXT)
            && self
                .entitlement
                .as_ref()
                .is_none_or(|token| token.len() <= MAX_TOKEN_TEXT)
            && self
                .crl
                .as_ref()
                .is_none_or(|crl| crl.len() <= MAX_CRL_BYTES)
    }
}

impl fmt::Debug for MemoryStateStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryStateStore")
            .field("max_crl_seq", &self.max_crl_seq)
            .field("last_seen_time", &self.last_seen_time)
            .field("has_lease", &self.lease.is_some())
            .field("has_entitlement", &self.entitlement.is_some())
            .field("has_crl", &self.crl.is_some())
            .finish()
    }
}

impl Drop for MemoryStateStore {
    fn drop(&mut self) {
        self.lease.zeroize();
        self.entitlement.zeroize();
    }
}

impl StateStore for MemoryStateStore {
    fn get_max_crl_seq(&self) -> Option<u64> {
        self.max_crl_seq
    }

    fn set_max_crl_seq(&mut self, seq: u64) {
        self.max_crl_seq = Some(seq.max(self.max_crl_seq.unwrap_or_default()));
    }

    fn get_last_seen_time(&self) -> Option<u64> {
        self.last_seen_time
    }

    fn set_last_seen_time(&mut self, time: u64) {
        self.last_seen_time = Some(time.max(self.last_seen_time.unwrap_or_default()));
    }

    fn get_lease(&self) -> Option<Vec<u8>> {
        self.lease.clone()
    }

    fn set_lease(&mut self, token: &[u8]) {
        self.lease.zeroize();
        self.lease = (!token.is_empty()).then(|| token.to_owned());
    }

    fn get_entitlement(&self) -> Option<Vec<u8>> {
        self.entitlement.clone()
    }

    fn set_entitlement(&mut self, token: &[u8]) {
        self.entitlement.zeroize();
        self.entitlement = (!token.is_empty()).then(|| token.to_owned());
    }

    fn get_crl(&self) -> Option<Vec<u8>> {
        self.crl.clone()
    }

    fn set_crl(&mut self, crl: &[u8]) {
        self.crl = Some(crl.to_owned());
    }
}

/// A private, atomically updated state file with an exclusive writer lock.
#[derive(Debug)]
pub struct FileStateStore {
    path: PathBuf,
    state: MemoryStateStore,
    _lock: File,
    dirty: bool,
}

impl FileStateStore {
    /// Opens state under an exclusive lock, or starts fresh if the file is absent.
    ///
    /// Use an application-owned directory. The sibling lock file remains on
    /// disk after close so all processes use the same lock inode.
    ///
    /// # Errors
    ///
    /// Returns an error for I/O failure, another open writer or invalid state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StateFileError> {
        let path = path.as_ref().to_owned();
        let mut lock_name = path.file_name().ok_or(StateFileError::Invalid)?.to_owned();
        lock_name.push(".lock");
        let lock = lock_file(&directory(&path).join(lock_name)).map_err(StateFileError::Lock)?;

        let state = match open_private(&path) {
            Ok(file) => {
                let mut bytes = Zeroizing::new(Vec::new());
                file.take((MAX_STATE_FILE + 1) as u64)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > MAX_STATE_FILE {
                    return Err(StateFileError::Invalid);
                }
                let Some((&STATE_VERSION, data)) = bytes.split_first() else {
                    return Err(StateFileError::Invalid);
                };
                let (state, tail): (MemoryStateStore, _) =
                    postcard::take_from_bytes(data).map_err(|_| StateFileError::Invalid)?;
                if !tail.is_empty() || !state.valid_size() {
                    return Err(StateFileError::Invalid);
                }
                state
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => MemoryStateStore::new(),
            Err(error) => return Err(error.into()),
        };

        Ok(Self {
            path,
            state,
            _lock: lock,
            dirty: false,
        })
    }

    /// Commits staged changes with a durable atomic replacement.
    ///
    /// # Errors
    ///
    /// Returns an error if the state exceeds its format limits or the
    /// replacement could not be committed.
    pub fn save(&mut self) -> Result<(), StateFileError> {
        if !self.dirty {
            return Ok(());
        }
        if !self.state.valid_size() {
            return Err(StateFileError::Invalid);
        }
        let bytes = Zeroizing::new(
            postcard::to_allocvec(&self.state).map_err(|_| StateFileError::Invalid)?,
        );
        let parent = directory(&self.path);
        let mut temp = private_temp(parent)?;
        temp.write_all(&[STATE_VERSION])?;
        temp.write_all(&bytes)?;
        temp.as_file().sync_all()?;
        temp.persist(&self.path).map_err(|error| error.error)?;
        sync_directory(parent)?;
        self.dirty = false;
        Ok(())
    }
}

impl StateStore for FileStateStore {
    fn get_max_crl_seq(&self) -> Option<u64> {
        self.state.get_max_crl_seq()
    }

    fn set_max_crl_seq(&mut self, seq: u64) {
        self.state.set_max_crl_seq(seq);
        self.dirty = true;
    }

    fn get_last_seen_time(&self) -> Option<u64> {
        self.state.get_last_seen_time()
    }

    fn set_last_seen_time(&mut self, time: u64) {
        self.state.set_last_seen_time(time);
        self.dirty = true;
    }

    fn get_lease(&self) -> Option<Vec<u8>> {
        self.state.get_lease()
    }

    fn set_lease(&mut self, token: &[u8]) {
        self.state.set_lease(token);
        self.dirty = true;
    }

    fn get_entitlement(&self) -> Option<Vec<u8>> {
        self.state.get_entitlement()
    }

    fn set_entitlement(&mut self, token: &[u8]) {
        self.state.set_entitlement(token);
        self.dirty = true;
    }

    fn get_crl(&self) -> Option<Vec<u8>> {
        self.state.get_crl()
    }

    fn set_crl(&mut self, crl: &[u8]) {
        self.state.set_crl(crl);
        self.dirty = true;
    }

    fn flush(&mut self) -> Result<(), LicenseError> {
        self.save().map_err(|_| LicenseError::StateStorage)
    }
}

/// Errors opening or persisting the application-owned state file.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StateFileError {
    /// Another process holds the state lock or the lock is unavailable.
    #[error("could not acquire the license state lock")]
    Lock(#[source] io::Error),
    /// The private file could not be read or written.
    #[error("license state file I/O failed")]
    Io(#[from] io::Error),
    /// File framing, version or size is invalid.
    #[error("invalid license state file")]
    Invalid,
}

pub(crate) fn directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

pub(crate) fn private_temp(path: &Path) -> io::Result<NamedTempFile> {
    let temp = NamedTempFile::new_in(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(temp)
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

fn require_private(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "expected a private file with mode 0600 and one hard link",
            ));
        }
    }
    Ok(())
}

pub(crate) fn open_private(path: &Path) -> io::Result<File> {
    let file = private_options().open(path)?;
    require_private(&file)?;
    Ok(file)
}

pub(crate) fn lock_file(path: &Path) -> io::Result<File> {
    let lock = private_options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    require_private(&lock)?;
    FileExt::try_lock_exclusive(&lock)?;
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::{FileStateStore, StateFileError, StateStore};

    #[test]
    fn file_store_locks_and_persists_watermarks_together() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("license.state");
        {
            let mut store = FileStateStore::open(&path)?;
            store.set_lease(b"fixture");
            store.set_entitlement(b"fixture entitlement");
            store.set_max_crl_seq(20);
            store.set_crl(b"fixture crl");
            store.set_last_seen_time(1_500);
            store.set_max_crl_seq(10);
            store.set_last_seen_time(900);
            store.flush()?;
            assert!(matches!(
                FileStateStore::open(&path),
                Err(StateFileError::Lock(_))
            ));
        }
        let store = FileStateStore::open(&path)?;
        assert_eq!(store.get_lease().as_deref(), Some(&b"fixture"[..]));
        assert_eq!(
            store.get_entitlement().as_deref(),
            Some(&b"fixture entitlement"[..])
        );
        assert_eq!(store.get_crl().as_deref(), Some(&b"fixture crl"[..]));
        assert_eq!(store.get_max_crl_seq(), Some(20));
        assert_eq!(store.get_last_seen_time(), Some(1_500));
        Ok(())
    }
}
