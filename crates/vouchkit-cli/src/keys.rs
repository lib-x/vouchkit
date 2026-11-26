use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::{fs, path::Path};
use vouchkit_core::protocol::{
    encode_master_key, encode_signing_public_key, parse_master_key, parse_signing_public_key,
};
use vouchkit_core::{
    DeviceKeyError, DeviceProver, PublicKey, SigningAlgorithm, SigningProvider, SoftwareSigningKey,
    generate_signing_seed, random_bytes,
};
use zeroize::{Zeroize, Zeroizing};

use crate::files::{self, Destination, PendingFile};

const MASTER_ENCRYPTED: &[u8] = b"VOUCHKIT-MASTER-1\0";
const MASTER_PLAINTEXT: &[u8] = b"VOUCHKIT-MASTER-PLAINTEXT-1\0";
const MASTER_ENCRYPTED_P256: &[u8] = b"VOUCHKIT-MASTER-P256-2\0";
const MASTER_PLAINTEXT_P256: &[u8] = b"VOUCHKIT-MASTER-PLAINTEXT-P256-2\0";
const DELEGATE: &[u8] = b"VOUCHKIT-DELEGATE-1\n";
const DELEGATE_P256: &[u8] = b"VOUCHKIT-DELEGATE-P256-2\n";
const DEVICE_P256: &[u8] = b"VOUCHKIT-DEVICE-P256-2\0";
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;
const MAX_KEY_BYTES: usize = 1024;
const MAX_PASS_BYTES: usize = 4096;

pub(crate) struct MasterKey {
    pub(crate) id: u8,
    pub(crate) seed: Zeroizing<[u8; 32]>,
    pub(crate) signing: SoftwareSigningKey,
    algorithm: SigningAlgorithm,
}

impl MasterKey {
    fn from_seed(id: u8, algorithm: SigningAlgorithm, seed: Zeroizing<[u8; 32]>) -> Result<Self> {
        let signing =
            SoftwareSigningKey::from_seed(algorithm, &seed).context("invalid master key seed")?;
        Ok(Self {
            id,
            seed,
            signing,
            algorithm,
        })
    }

    pub(crate) fn read(path: &Path, passphrase_file: Option<&Path>) -> Result<Self> {
        let bytes = files::read_secret(path, MAX_KEY_BYTES)?;
        if let Some((algorithm, plaintext)) =
            algorithm_and_body(&bytes, MASTER_PLAINTEXT, MASTER_PLAINTEXT_P256)
        {
            let (&id, seed) = plaintext
                .split_first()
                .context("invalid plaintext master key")?;
            ensure!(
                passphrase_file.is_none(),
                "a plaintext master key does not use a passphrase"
            );
            return Self::from_seed(
                id,
                algorithm,
                Zeroizing::new(seed.try_into().context("invalid plaintext master key")?),
            );
        }

        let parsed = EncryptedMaster::parse(&bytes)?;
        let password = passphrase(passphrase_file, "Master key passphrase: ")?;
        let cipher = cipher(&password, parsed.kdf, parsed.salt)?;
        let seed = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(parsed.nonce),
                    Payload {
                        msg: parsed.ciphertext,
                        aad: parsed.header,
                    },
                )
                .map_err(|_| anyhow!("wrong master key passphrase or damaged key file"))?,
        );
        Self::from_seed(
            parsed.id,
            parsed.algorithm,
            Zeroizing::new(
                seed.as_slice()
                    .try_into()
                    .context("invalid master key seed")?,
            ),
        )
    }
}

pub(crate) fn keygen_master(
    dir: &Path,
    id: u8,
    algorithm: SigningAlgorithm,
    insecure_plaintext: bool,
    passphrase_file: Option<&Path>,
) -> Result<()> {
    fs::create_dir_all(dir).context("creating master key directory")?;
    let private_name = if insecure_plaintext {
        "master.key"
    } else {
        "master.key.enc"
    };
    let private_path = dir.join(private_name);
    let mut lock_name = dir.to_path_buf();
    lock_name.push(".vouch-keygen");
    let _lock = crate::ledger::lock_path(&lock_name)?;
    let paths = [
        private_path,
        dir.join("master.pub"),
        dir.join("public_keys.rs"),
    ];
    for path in &paths {
        files::require_absent(path)?;
    }
    let master = MasterKey::from_seed(
        id,
        algorithm,
        Zeroizing::new(generate_signing_seed(algorithm)?),
    )?;
    let public = master.signing.public_key();
    let private = if insecure_plaintext {
        ensure!(
            passphrase_file.is_none(),
            "--passphrase-file conflicts with --insecure-plaintext"
        );
        let header = marker(algorithm, MASTER_PLAINTEXT, MASTER_PLAINTEXT_P256)?;
        let mut file = Zeroizing::new(Vec::with_capacity(header.len() + 33));
        file.extend_from_slice(header);
        file.push(id);
        file.extend_from_slice(master.seed.as_slice());
        file
    } else {
        let password = passphrase(passphrase_file, "New master key passphrase: ")?;
        if passphrase_file.is_none() {
            let confirmation = passphrase(None, "Confirm master key passphrase: ")?;
            ensure!(
                *password == *confirmation,
                "master key passphrases do not match"
            );
        }
        Zeroizing::new(encrypt_master(&master, &password)?)
    };
    let public_text = format!("{}\n", encode_master_key(id, public));
    let rust = match public {
        PublicKey::Ed25519(bytes) => {
            format!("pub const PUBLIC_KEYS: &[(u8, [u8; 32])] = &[({id}, {bytes:?})];\n")
        }
        PublicKey::P256(bytes) => format!(
            "pub const PUBLIC_KEYS: &[(u8, vouchkit_core::PublicKey)] = &[({id}, vouchkit_core::PublicKey::P256({bytes:?}))];\n"
        ),
        _ => bail!("unsupported signing algorithm"),
    };
    let references = [private.as_slice(), public_text.as_bytes(), rust.as_bytes()];
    let pending: Vec<_> = paths
        .iter()
        .zip(references)
        .map(|(path, bytes)| PendingFile::new(path, bytes))
        .collect::<Result<_>>()?;
    for (output, path) in pending.into_iter().zip(&paths) {
        output.persist(path, Destination::New)?;
    }
    Ok(())
}

pub(crate) fn keygen_delegate(dir: &Path, algorithm: SigningAlgorithm) -> Result<()> {
    fs::create_dir_all(dir).context("creating delegate key directory")?;
    let _lock = crate::ledger::lock_path(&dir.join(".vouch-keygen"))?;
    let paths = [dir.join("delegate.key"), dir.join("delegate.pub")];
    for path in &paths {
        files::require_absent(path)?;
    }
    let seed = Zeroizing::new(generate_signing_seed(algorithm)?);
    let header = marker(algorithm, DELEGATE, DELEGATE_P256)?;
    let mut private = Zeroizing::new(Vec::with_capacity(header.len() + 65));
    private.extend_from_slice(header);
    let mut encoded = Zeroizing::new([0; 64]);
    hex::encode_to_slice(seed.as_slice(), encoded.as_mut_slice())
        .context("encoding delegate key")?;
    private.extend_from_slice(encoded.as_slice());
    encoded.zeroize();
    private.push(b'\n');
    let signer = SoftwareSigningKey::from_seed(algorithm, &seed)?;
    let public = format!("{}\n", encode_signing_public_key(signer.public_key()));
    let pending_private = PendingFile::new(&paths[0], &private)?;
    let pending_public = PendingFile::new(&paths[1], public.as_bytes())?;
    pending_private.persist(&paths[0], Destination::New)?;
    pending_public.persist(&paths[1], Destination::New)
}

pub(crate) fn read_master_public(path: &Path) -> Result<(u8, PublicKey)> {
    let bytes = files::read(path, MAX_KEY_BYTES)?;
    parse_master_key(std::str::from_utf8(&bytes)?)
        .context("expected a master public key with key ID and public key")
}

pub(crate) fn read_delegate_public(path: &Path) -> Result<PublicKey> {
    let bytes = files::read(path, MAX_KEY_BYTES)?;
    parse_public(std::str::from_utf8(&bytes)?)
}

pub(crate) fn parse_public(input: &str) -> Result<PublicKey> {
    parse_signing_public_key(input).context("expected an Ed25519 or P-256 public key")
}

pub(crate) struct DeviceKey(SoftwareSigningKey);

impl DeviceKey {
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let bytes = files::read_secret(path, DEVICE_P256.len() + 32)?;
        let (algorithm, seed) = if bytes.len() == 32 {
            (SigningAlgorithm::Ed25519, bytes.as_slice())
        } else {
            (
                SigningAlgorithm::P256,
                bytes
                    .strip_prefix(DEVICE_P256)
                    .context("unknown device key format")?,
            )
        };
        let seed: &[u8; 32] = seed.try_into().context("invalid device key file length")?;
        Ok(Self(
            SoftwareSigningKey::from_seed(algorithm, seed).context("invalid device key seed")?,
        ))
    }
}

impl DeviceProver for DeviceKey {
    fn public(&self) -> PublicKey {
        self.0.public_key()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DeviceKeyError> {
        self.0
            .try_sign(message)
            .map_err(|_| DeviceKeyError::SigningFailed)
    }
}

fn algorithm_and_body<'a>(
    bytes: &'a [u8],
    ed25519: &[u8],
    p256: &[u8],
) -> Option<(SigningAlgorithm, &'a [u8])> {
    bytes
        .strip_prefix(ed25519)
        .map(|rest| (SigningAlgorithm::Ed25519, rest))
        .or_else(|| {
            bytes
                .strip_prefix(p256)
                .map(|rest| (SigningAlgorithm::P256, rest))
        })
}

fn marker(
    algorithm: SigningAlgorithm,
    ed25519: &'static [u8],
    p256: &'static [u8],
) -> Result<&'static [u8]> {
    match algorithm {
        SigningAlgorithm::Ed25519 => Ok(ed25519),
        SigningAlgorithm::P256 => Ok(p256),
        _ => bail!("unsupported signing algorithm"),
    }
}

fn passphrase(path: Option<&Path>, prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut password = if let Some(path) = path {
        files::read_secret(path, MAX_PASS_BYTES)?
    } else {
        Zeroizing::new(
            rpassword::prompt_password(prompt)
                .context("reading master key passphrase")?
                .into_bytes(),
        )
    };
    if path.is_some() && password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    ensure!(
        !password.is_empty(),
        "master key passphrase must not be empty"
    );
    ensure!(
        password.len() <= MAX_PASS_BYTES,
        "master key passphrase is too long"
    );
    Ok(password)
}

#[derive(Clone, Copy)]
struct Kdf {
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
}

impl Kdf {
    fn params(self) -> Result<Params> {
        ensure!(
            (19 * 1024..=128 * 1024).contains(&self.memory_kib)
                && (2..=6).contains(&self.iterations)
                && (1..=4).contains(&self.lanes),
            "unsupported master key derivation parameters"
        );
        Params::new(self.memory_kib, self.iterations, self.lanes, Some(32))
            .map_err(|_| anyhow!("invalid master key derivation parameters"))
    }
}

fn cipher(password: &[u8], kdf: Kdf, salt: &[u8; 16]) -> Result<XChaCha20Poly1305> {
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, kdf.params()?)
        .hash_password_into(password, salt, key.as_mut_slice())
        .map_err(|_| anyhow!("master key derivation failed"))?;
    Ok(XChaCha20Poly1305::new((&*key).into()))
}

fn encrypt_master(master: &MasterKey, password: &[u8]) -> Result<Vec<u8>> {
    let kdf = Kdf {
        memory_kib: MEMORY_KIB,
        iterations: ITERATIONS,
        lanes: LANES,
    };
    let salt = random_bytes()?;
    let nonce: [u8; 24] = random_bytes()?;
    let mut header = Vec::from(marker(
        master.algorithm,
        MASTER_ENCRYPTED,
        MASTER_ENCRYPTED_P256,
    )?);
    header.push(master.id);
    header.extend(kdf.memory_kib.to_be_bytes());
    header.extend(kdf.iterations.to_be_bytes());
    header.extend(kdf.lanes.to_be_bytes());
    header.extend(salt);
    header.extend(nonce);
    let ciphertext = cipher(password, kdf, &salt)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: master.seed.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| anyhow!("encrypting master key failed"))?;
    header.extend(ciphertext);
    Ok(header)
}

struct EncryptedMaster<'a> {
    id: u8,
    algorithm: SigningAlgorithm,
    kdf: Kdf,
    salt: &'a [u8; 16],
    nonce: &'a [u8; 24],
    header: &'a [u8],
    ciphertext: &'a [u8; 48],
}

impl<'a> EncryptedMaster<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let (algorithm, tail) = algorithm_and_body(bytes, MASTER_ENCRYPTED, MASTER_ENCRYPTED_P256)
            .context("unknown master key format")?;
        let (&id, tail) = tail
            .split_first()
            .context("truncated encrypted master key")?;
        let (memory_kib, tail) = part(tail)?;
        let (iterations, tail) = part(tail)?;
        let (lanes, tail) = part(tail)?;
        let (salt, tail) = part(tail)?;
        let (nonce, ciphertext) = part(tail)?;
        let ciphertext = ciphertext
            .try_into()
            .context("invalid encrypted master key length")?;
        let header = bytes
            .get(..bytes.len() - 48)
            .context("truncated encrypted master key")?;
        let kdf = Kdf {
            memory_kib: u32::from_be_bytes(*memory_kib),
            iterations: u32::from_be_bytes(*iterations),
            lanes: u32::from_be_bytes(*lanes),
        };
        kdf.params()?;
        Ok(Self {
            id,
            algorithm,
            kdf,
            salt,
            nonce,
            header,
            ciphertext,
        })
    }
}

fn part<const N: usize>(input: &[u8]) -> Result<(&[u8; N], &[u8])> {
    input
        .split_first_chunk()
        .context("truncated encrypted master key")
}

#[cfg(test)]
mod tests {
    use super::{
        EncryptedMaster, ITERATIONS, LANES, MASTER_ENCRYPTED, MASTER_PLAINTEXT,
        MASTER_PLAINTEXT_P256, MEMORY_KIB, MasterKey,
    };
    use crate::files::{self, Destination};
    use anyhow::Result;
    use vouchkit_core::{SigningAlgorithm, SigningKey, SigningProvider};

    fn header(memory: u32, iterations: u32, lanes: u32) -> Vec<u8> {
        let mut bytes = Vec::from(MASTER_ENCRYPTED);
        bytes.push(9);
        bytes.extend(memory.to_be_bytes());
        bytes.extend(iterations.to_be_bytes());
        bytes.extend(lanes.to_be_bytes());
        bytes.extend([0; 16 + 24 + 48]);
        bytes
    }

    #[test]
    fn validates_header_length_and_kdf_limits_before_decryption() -> Result<()> {
        let standard = header(MEMORY_KIB, ITERATIONS, LANES);
        let parsed = EncryptedMaster::parse(&standard)?;
        assert_eq!(parsed.id, 9);
        assert_eq!(parsed.algorithm, SigningAlgorithm::Ed25519);
        assert_eq!(
            parsed.header.len() + parsed.ciphertext.len(),
            standard.len()
        );
        assert!(EncryptedMaster::parse(&standard[..standard.len() - 1]).is_err());
        assert!(EncryptedMaster::parse(&header(u32::MAX, ITERATIONS, LANES)).is_err());
        assert!(EncryptedMaster::parse(&header(MEMORY_KIB, 1, LANES)).is_err());
        assert!(EncryptedMaster::parse(&header(MEMORY_KIB, ITERATIONS, 0)).is_err());
        Ok(())
    }
    #[test]
    fn accepts_legacy_master_bytes_and_checks_p256_scalars() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let legacy = directory.path().join("legacy.key");
        let invalid = directory.path().join("invalid.key");
        let mut legacy_bytes = Vec::from(MASTER_PLAINTEXT);
        legacy_bytes.push(7);
        legacy_bytes.extend([11; 32]);
        files::write(&legacy, &legacy_bytes, Destination::New)?;

        let master = MasterKey::read(&legacy, None)?;
        assert_eq!(master.id, 7);
        assert_eq!(
            master.signing.public_key(),
            SigningKey::from_seed(&[11; 32]).public().into()
        );

        let mut invalid_bytes = Vec::from(MASTER_PLAINTEXT_P256);
        invalid_bytes.push(8);
        invalid_bytes.extend([0; 32]);
        files::write(&invalid, &invalid_bytes, Destination::New)?;
        assert!(MasterKey::read(&invalid, None).is_err());
        Ok(())
    }
}
