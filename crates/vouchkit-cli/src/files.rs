use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

pub(crate) enum Destination {
    New,
    Replace,
}

pub(crate) fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn normalized_target(path: &Path) -> Result<PathBuf> {
    let name = path.file_name().context("output path must name a file")?;
    Ok(parent(path)
        .canonicalize()
        .with_context(|| format!("resolving the directory for {}", path.display()))?
        .join(name))
}

pub(crate) fn read(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = open_regular(path)?;
    read_bounded(&mut file, limit).with_context(|| format!("reading {}", path.display()))
}

pub(crate) fn read_secret(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = open_regular(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = file.metadata()?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} is accessible by other users (use chmod 600)",
                path.display()
            );
        }
    }
    read_bounded(&mut file, limit).with_context(|| format!("reading {}", path.display()))
}

fn open_regular(path: &Path) -> Result<File> {
    if !fs::metadata(path)
        .with_context(|| format!("opening {}", path.display()))?
        .is_file()
    {
        bail!("{} must be a regular file", path.display());
    }
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("{} must be a regular file", path.display());
    }
    Ok(file)
}

fn read_bounded(input: &mut File, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let len = usize::try_from(input.metadata()?.len())?;
    if len > limit {
        bail!("file exceeds the {limit}-byte limit");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(len.saturating_add(1)));
    input
        .take(u64::try_from(limit)? + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("file exceeds the {limit}-byte limit");
    }
    Ok(bytes)
}

pub(crate) struct PendingFile(NamedTempFile);

impl PendingFile {
    pub(crate) fn new(path: &Path, bytes: &[u8]) -> Result<Self> {
        let mut temporary = NamedTempFile::new_in(parent(path))
            .with_context(|| format!("staging {}", path.display()))?;
        temporary
            .write_all(bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(Self(temporary))
    }

    pub(crate) fn persist(self, path: &Path, mode: Destination) -> Result<()> {
        let published = match mode {
            Destination::New => self.0.persist_noclobber(path),
            Destination::Replace => self.0.persist(path),
        };
        let _file = published
            .map_err(|error| error.error)
            .with_context(|| format!("publishing {}", path.display()))?;
        sync_parent(path)
    }
}

pub(crate) fn require_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("checking {}", path.display())),
        Ok(_) => bail!("{} already exists", path.display()),
    }
}

pub(crate) fn write(path: &Path, bytes: &[u8], mode: Destination) -> Result<()> {
    PendingFile::new(path, bytes)?.persist(path, mode)
}

pub(crate) fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(parent(path))
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("syncing the directory for {}", path.display()))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
