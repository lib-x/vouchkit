use std::{
    env,
    fs::{self, File},
    io::Read,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
};

use serde::Deserialize;
use vouchkit_core::{SigningKey, protocol::parse_master_public_key};
use zeroize::Zeroizing;

use crate::ServerError;

pub(crate) const DAY_SECS: u64 = 86_400;
pub(crate) const MAX_CRL_BYTES: usize = 256 * 1_024;
const DELEGATE_HEADER: &[u8] = b"VOUCHKIT-DELEGATE-1\n";

/// Settings for a standalone, delegated activation service.
#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub(crate) listen: SocketAddr,
    pub(crate) database: PathBuf,
    pub(crate) master_public_keys: Vec<PathBuf>,
    pub(crate) delegate_key: Option<PathBuf>,
    pub(crate) delegate_key_env: Option<String>,
    pub(crate) delegation_cert: PathBuf,
    pub(crate) crl: Option<PathBuf>,
    pub(crate) lease_secs: u64,
    pub(crate) grace_secs: u32,
    pub(crate) requests_per_ip_per_minute: u32,
    pub(crate) requests_per_entitlement_per_minute: u32,
    pub(crate) requests_per_minute: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            database: "activations.sqlite3".into(),
            master_public_keys: Vec::new(),
            delegate_key: None,
            delegate_key_env: None,
            delegation_cert: "cert.bin".into(),
            crl: None,
            lease_secs: 14 * DAY_SECS,
            grace_secs: (7 * DAY_SECS) as u32,
            requests_per_ip_per_minute: 120,
            requests_per_entitlement_per_minute: 60,
            requests_per_minute: 2_400,
        }
    }
}

impl ServerConfig {
    /// Reads TOML configuration and resolves paths against the file's location.
    ///
    /// # Errors
    ///
    /// Returns an error on invalid configuration or unreadable input.
    pub fn load(path: &Path) -> Result<Self, ServerError> {
        let data = read_limited(path, 32 * 1_024)?;
        let text = std::str::from_utf8(&data)
            .map_err(|_| ServerError::Config("configuration must be UTF-8"))?;
        let mut config: Self =
            toml::from_str(text).map_err(|_| ServerError::Config("invalid server TOML"))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        config.database = base.join(config.database);
        config.delegation_cert = base.join(config.delegation_cert);
        config.delegate_key = config.delegate_key.map(|p| base.join(p));
        config.crl = config.crl.map(|p| base.join(p));
        for path in &mut config.master_public_keys {
            *path = base.join(&*path);
        }
        Ok(config)
    }

    /// Returns the interface and port to which the reference service should bind.
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    /// Returns the configured source of signed CRL updates, if any.
    pub fn crl_path(&self) -> Option<&Path> {
        self.crl.as_deref()
    }

    pub(crate) fn read_master_keys(&self) -> Result<Vec<(u8, [u8; 32])>, ServerError> {
        if self.master_public_keys.is_empty() || self.master_public_keys.len() > 256 {
            return Err(ServerError::Config(
                "configure one to 256 master public keys",
            ));
        }
        let mut seen = [false; 256];
        self.master_public_keys
            .iter()
            .map(|path| {
                let data = Zeroizing::new(read_limited(path, 128)?);
                let text = std::str::from_utf8(&data).map_err(|_| {
                    ServerError::Config("master public key must use the vouch public key format")
                })?;
                let (id, key) = parse_master_public_key(text)?;
                if std::mem::replace(&mut seen[usize::from(id)], true) {
                    return Err(ServerError::Config("duplicate master key ID"));
                }
                Ok((id, key))
            })
            .collect()
    }

    pub(crate) fn read_delegate(&self) -> Result<SigningKey, ServerError> {
        let bytes = match (&self.delegate_key, &self.delegate_key_env) {
            (Some(path), None) => Zeroizing::new(read_limited(path, 128)?),
            (None, Some(name)) => {
                let value = env::var(name).map_err(|_| {
                    ServerError::Config("delegate key environment variable is missing or invalid")
                })?;
                Zeroizing::new(value.into_bytes())
            }
            _ => {
                return Err(ServerError::Config(
                    "configure exactly one of delegate_key or delegate_key_env",
                ));
            }
        };
        let encoded = bytes
            .strip_prefix(DELEGATE_HEADER)
            .ok_or(ServerError::Config("invalid delegate key file header"))?;
        let encoded = encoded.strip_suffix(b"\n").unwrap_or(encoded);
        let mut seed = Zeroizing::new([0; 32]);
        hex::decode_to_slice(encoded, seed.as_mut())
            .map_err(|_| ServerError::Config("invalid delegate key seed"))?;
        Ok(SigningKey::from_seed(&seed))
    }
}

pub(crate) fn read_limited(path: &Path, limit: usize) -> Result<Vec<u8>, ServerError> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(ServerError::Config(
            "configuration file exceeds its size limit",
        ));
    }
    Ok(bytes)
}

pub(crate) fn is_missing(path: &Path) -> Result<bool, ServerError> {
    match fs::metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_resolves_paths_relative_to_its_location() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "database = \"db.sqlite\"\nmaster_public_keys = [\"master.pub\"]\n",
        )?;
        let config = ServerConfig::load(&path)?;
        assert_eq!(config.database, dir.path().join("db.sqlite"));
        assert_eq!(config.master_public_keys, [dir.path().join("master.pub")]);
        Ok(())
    }
}
