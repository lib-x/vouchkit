use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::{File, OpenOptions, symlink_metadata};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use vouchkit_core::FeatureSlots;

use crate::files;

const MAX_LINE: usize = 8192;

pub(crate) fn sibling(path: &Path, suffix: &str) -> Result<PathBuf> {
    let mut name = OsString::from(path.file_name().context("output path must name a file")?);
    name.push(suffix);
    Ok(path.with_file_name(name))
}

pub(crate) fn lock_path(path: &Path) -> Result<File> {
    let lock_path = sibling(path, ".lock")?;
    let file = open(&lock_path, Mode::Lock)?;
    FileExt::lock_exclusive(&file).with_context(|| format!("locking {}", lock_path.display()))?;
    Ok(file)
}

pub(crate) struct Ledger {
    path: PathBuf,
    _lock: File,
}

impl Ledger {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        Ok(Self {
            path: path.to_path_buf(),
            _lock: lock_path(path)?,
        })
    }

    pub(crate) fn crl_path(&self) -> Result<PathBuf> {
        sibling(&self.path, ".crl")
    }

    pub(crate) fn reject_reserved_output(&self, path: &Path) -> Result<()> {
        let output = files::normalized_target(path)?;
        for reserved in [
            &self.path,
            &self.crl_path()?,
            &sibling(&self.path, ".lock")?,
        ] {
            ensure!(
                output != files::normalized_target(reserved)?,
                "output overlaps the issuance ledger or revocation state"
            );
        }
        Ok(())
    }

    pub(crate) fn append(&self, record: &Record) -> Result<()> {
        let mut line = serde_json::to_vec(record)?;
        ensure!(line.len() < MAX_LINE, "ledger record is too large");
        line.push(b'\n');

        let mut file = open(&self.path, Mode::Append)?;
        let complete_len = trim_incomplete_record(&mut file)?;
        if let Err(error) = file.write_all(&line).and_then(|()| file.sync_all()) {
            file.set_len(complete_len)
                .and_then(|()| file.sync_all())
                .map_err(|repair| {
                    anyhow::anyhow!(
                        "appending ledger failed: {error}; restoring ledger failed: {repair}"
                    )
                })?;
            return Err(error).context("appending issued record to ledger");
        }
        files::sync_parent(&self.path)
    }

    pub(crate) fn for_each(&self, mut visit: impl FnMut(Record) -> Result<()>) -> Result<()> {
        let Some(file) = open_existing(&self.path)? else {
            return Ok(());
        };
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        let mut number = 0u64;
        loop {
            line.clear();
            (reader.by_ref().take(u64::try_from(MAX_LINE)? + 1)).read_until(b'\n', &mut line)?;
            if line.is_empty() {
                return Ok(());
            }
            number += 1;
            ensure!(
                line.len() <= MAX_LINE,
                "ledger line {number} exceeds the size limit"
            );
            if line.last() != Some(&b'\n') {
                // Issuance is published only after the terminated record has been synced.
                return Ok(());
            }
            let record = serde_json::from_slice(&line)
                .with_context(|| format!("invalid ledger record at line {number}"))?;
            visit(record)?;
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Record {
    License {
        license_id: String,
        entitlement_id: String,
        class: String,
        product: String,
        subject: String,
        tier: u8,
        features: FeatureSlots,
        issued_at: u64,
        expires_at: Option<u64>,
    },
    Delegation {
        cert_id: String,
        product: String,
        max_tier: u8,
        feature_mask: FeatureSlots,
        issued_at: u64,
        expires_at: u64,
    },
}

enum Mode {
    Lock,
    Append,
}

fn open(path: &Path, mode: Mode) -> Result<File> {
    match symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file(),
            "{} is not a regular file",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("checking {}", path.display())),
    }
    let mut opts = OpenOptions::new();
    opts.read(true).create(true);
    match mode {
        Mode::Lock => opts.write(true),
        Mode::Append => opts.append(true),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        opts.mode(0o600);
    }
    let file = opts
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "{} is not a regular file",
        path.display()
    );
    Ok(file)
}

fn open_existing(path: &Path) -> Result<Option<File>> {
    match symlink_metadata(path) {
        Ok(metadata) => ensure!(
            metadata.is_file(),
            "{} is not a regular file",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("checking {}", path.display())),
    }
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    ensure!(
        file.metadata()?.is_file(),
        "{} is not a regular file",
        path.display()
    );
    Ok(Some(file))
}

fn trim_incomplete_record(file: &mut File) -> Result<u64> {
    let total = file.metadata()?.len();
    if total == 0 {
        return Ok(0);
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0];
    file.read_exact(&mut last)?;
    if &last == b"\n" {
        return Ok(total);
    }
    let tail_len = total.min(u64::try_from(MAX_LINE)?);
    let start = total - tail_len;
    file.seek(SeekFrom::Start(start))?;
    let mut tail = vec![0; usize::try_from(tail_len)?];
    file.read_exact(&mut tail)?;
    let complete_len = match tail.iter().rposition(|byte| *byte == b'\n') {
        Some(index) => start + u64::try_from(index)? + 1,
        None if start == 0 => 0,
        None => bail!("ledger ends in an oversized incomplete record"),
    };
    file.set_len(complete_len)
        .context("discarding incomplete final ledger record")?;
    Ok(complete_len)
}

#[cfg(test)]
mod tests {
    use super::{Ledger, Record};
    use anyhow::Result;
    use std::fs;

    #[test]
    fn repairs_an_incomplete_final_record_before_appending() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("issued.jsonl");
        let ledger = Ledger::acquire(&path)?;
        let mut visited = 0;
        let record = Record::Delegation {
            cert_id: "a".into(),
            product: "app".into(),
            max_tier: 1,
            feature_mask: 0u32.into(),
            issued_at: 1,
            expires_at: 2,
        };
        ledger.append(&record)?;
        let mut partial = fs::read(&path)?;
        partial.extend(b"{\"kind\":");
        fs::write(&path, partial)?;
        ledger.for_each(|_| {
            visited += 1;
            Ok(())
        })?;
        assert_eq!(visited, 1, "an uncommitted record must not be visible");

        ledger.append(&record)?;
        ledger.for_each(|_| {
            visited += 1;
            Ok(())
        })?;
        assert_eq!(visited, 3, "two complete records must remain");
        Ok(())
    }
}
