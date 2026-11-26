use anyhow::{Context, Result, ensure};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use vouchkit_core::protocol::{
    encode_signing_public_key, parse_master_key, parse_signing_public_key,
};
use vouchkit_core::{
    Class, PublicKey, SigningAlgorithm, SigningKey, SigningProvider, SoftwareSigningKey, Verifier,
    VerifyOptions, asset_open, decode_token, encode_license_file, inspect_license, sign_lease,
};

struct Workdir(tempfile::TempDir);

impl Workdir {
    fn new() -> Result<Self> {
        Ok(Self(tempfile::tempdir()?))
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_vouch"));
        command.current_dir(self.0.path());
        command
    }

    fn vouch(&self, args: &[&str]) -> Result<String> {
        output(self.command().args(args).output()?)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.path().join(name)
    }

    fn keygen(&self) -> Result<()> {
        self.vouch(&[
            "keygen",
            "--kind",
            "master",
            "--key-id",
            "9",
            "--insecure-plaintext",
        ])?;
        Ok(())
    }

    fn verify(&self, file: &str, extra: &[&str]) -> Result<String> {
        let mut args = vec![
            "verify",
            file,
            "--pubkey",
            "master.pub",
            "--product",
            "demo",
        ];
        args.extend(extra);
        self.vouch(&args)
    }

    fn verifier(&self) -> Result<Verifier> {
        let public = fs::read_to_string(self.path("master.pub"))?;
        let key = parse_master_key(&public)?;
        Ok(Verifier::with_public_keys(&[key], None))
    }

    fn inspect(&self, file: &str) -> Result<serde_json::Value> {
        Ok(serde_json::from_str(&self.vouch(&["inspect", file])?)?)
    }

    fn private_file(&self, name: &str, data: &[u8]) -> Result<()> {
        write_private(&self.path(name), data)
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    options.open(path)?.write_all(data)?;
    Ok(())
}

fn output(output: Output) -> Result<String> {
    let stderr = String::from_utf8_lossy(&output.stderr);
    ensure!(output.status.success(), "{stderr}");
    Ok(String::from_utf8(output.stdout)?)
}

fn field<'a>(document: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    document
        .get(field)
        .and_then(serde_json::Value::as_str)
        .context("missing string field")
}

#[test]
fn encrypted_master_validates_a_passphrase_and_signs_an_offline_license() -> Result<()> {
    let directory = Workdir::new()?;
    let passphrase = b"correct fixture passphrase";
    directory.private_file("correct", passphrase)?;
    directory.private_file("wrong", b"wrong passphrase")?;
    directory.vouch(&[
        "keygen",
        "--kind",
        "master",
        "--key-id",
        "5",
        "--passphrase-file",
        "correct",
    ])?;
    let encrypted = fs::read(directory.path("master.key.enc"))?;
    assert!(encrypted.starts_with(b"VOUCHKIT-MASTER-1\0"));
    assert!(!directory.path("master.key").exists());
    assert!(
        !encrypted
            .windows(passphrase.len())
            .any(|part| part == passphrase)
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(directory.path("master.key.enc"))?
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the encrypted key still needs owner-only access"
        );
    }

    let issue = [
        "issue",
        "--key",
        "master.key.enc",
        "--class",
        "standalone",
        "--product",
        "demo",
        "--subject",
        "fixture user",
        "--tier",
        "2",
        "--format",
        "file",
        "--out",
        "license.vk",
    ];
    let failure = directory
        .command()
        .args(issue)
        .args(["--passphrase-file", "wrong"])
        .output()?;
    assert!(!failure.status.success());
    assert!(String::from_utf8_lossy(&failure.stderr).contains("wrong master key passphrase"));
    assert!(!directory.path("license.vk").exists());
    assert!(!directory.path("issued.jsonl").exists());

    output(
        directory
            .command()
            .args(issue)
            .args(["--passphrase-file", "correct"])
            .output()?,
    )?;
    assert_eq!(directory.verify("license.vk", &[])?.trim(), "Active");

    let mut raw = decode_token(&fs::read_to_string(directory.path("license.vk"))?)?;
    let end = raw.last_mut().context("token has no signature bytes")?;
    *end ^= 1;
    fs::write(directory.path("forged.vk"), encode_license_file(&raw))?;
    let inspected = directory.inspect("forged.vk")?;
    assert_eq!(inspected["signature_verified"], false);
    let error = directory
        .verify("forged.vk", &[])
        .expect_err("mutated signature must fail");
    assert!(error.to_string().contains("bad signature"));
    Ok(())
}

#[test]
fn scoped_slots_device_binding_resource_sealing_and_profiles_work_together() -> Result<()> {
    let directory = Workdir::new()?;
    directory.keygen()?;
    let seed = [17; 32];
    directory.private_file("device", &seed)?;
    directory.private_file("other-device", &[18; 32])?;
    let device = SigningKey::from_seed(&seed);
    let public = encode_signing_public_key(device.public().into());
    let issue = [
        "issue",
        "--key",
        "master.key",
        "--class",
        "standalone",
        "--product",
        "demo",
        "--subject",
        "bound user",
        "--tier",
        "2",
        "--features",
        "0x08",
        "--feature-slots",
        "64,100-110",
        "--max-version",
        "2.x.x",
        "--device-pub",
        &public,
        "--tags",
        "--unlock",
        "3,64",
        "--out",
        "license.vk",
    ];
    directory.vouch(&issue)?;
    assert!(directory.verify("license.vk", &[]).is_err());
    assert!(
        directory
            .verify("license.vk", &["--device-key", "other-device"])
            .is_err()
    );
    assert!(
        directory
            .verify(
                "license.vk",
                &["--device-key", "device", "--app-version", "3.0.0"]
            )
            .is_err()
    );
    assert_eq!(
        directory
            .verify(
                "license.vk",
                &["--device-key", "device", "--app-version", "2.7.1"]
            )?
            .trim(),
        "Active"
    );

    let metadata = directory.inspect("license.vk")?;
    assert_eq!(
        metadata["feature_slots"],
        serde_json::json!([[3, 3], [64, 64], [100, 110]])
    );
    assert_eq!(metadata["unlock_features"], serde_json::json!([3, 64]));
    assert!(
        metadata.get("unlock").is_none(),
        "inspect should omit resource key bytes"
    );

    directory.vouch(&[
        "profile",
        "--key",
        "master.key",
        "--slots",
        "1,4,7",
        "--out",
        "profile.rs",
    ])?;
    let generated = fs::read_to_string(directory.path("profile.rs"))?;
    assert!(generated.contains("TAG_PROFILE"));
    assert_eq!(generated.matches("TagSlot").count(), 3);

    let clear = b"test resource";
    fs::write(directory.path("resource.txt"), clear)?;
    directory.vouch(&[
        "seal-asset",
        "--key",
        "master.key",
        "--product",
        "demo",
        "--feature",
        "64",
        "--in",
        "resource.txt",
        "--out",
        "resource.vk",
    ])?;
    let mut options = VerifyOptions::new(
        "demo",
        (2, 0, 0),
        metadata["issued_at"].as_u64().context("issuance time")?,
    );
    let device = TestDevice(device);
    options.device = Some(&device);
    let token = fs::read_to_string(directory.path("license.vk"))?;
    let authorization = directory.verifier()?.verify(&token, &options)?;
    let licensed = authorization
        .license()
        .context("should unlock a resource")?;
    let key = licensed.unlock_key(64).context("expected feature key")?;
    assert_eq!(
        asset_open(key, &fs::read(directory.path("resource.vk"))?)?,
        clear
    );

    let ledger = directory.vouch(&["ledger", "list"])?;
    assert!(
        !ledger.contains("unlock") && !ledger.contains("secret") && !ledger.contains("device_pub")
    );
    Ok(())
}

struct TestDevice(SigningKey);

impl vouchkit_core::DeviceProver for TestDevice {
    fn public(&self) -> PublicKey {
        self.0.public().into()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], vouchkit_core::DeviceKeyError> {
        Ok(self.0.sign(message))
    }
}

#[test]
fn concurrent_crl_updates_have_distinct_sequences_and_remain_cumulative() -> Result<()> {
    let directory = Workdir::new()?;
    directory.keygen()?;
    directory.vouch(&["keygen", "--kind", "delegate"])?;
    directory.vouch(&[
        "delegate",
        "--key",
        "master.key",
        "--delegate-pub",
        "delegate.pub",
        "--product",
        "demo",
        "--max-tier",
        "2",
        "--feature-slots",
        "64",
        "--out",
        "cert.bin",
    ])?;
    directory.vouch(&[
        "issue",
        "--key",
        "master.key",
        "--class",
        "entitlement",
        "--product",
        "demo",
        "--subject",
        "buyer",
        "--tier",
        "2",
        "--feature-slots",
        "64",
        "--out",
        "entitlement.vk",
    ])?;
    assert_eq!(
        directory.verify("entitlement.vk", &[])?.trim(),
        "NeedsActivation"
    );
    let license = directory.inspect("entitlement.vk")?;
    let entitlement_id = field(&license, "entitlement_id")?;
    let raw = decode_token(&fs::read_to_string(directory.path("entitlement.vk"))?)?;
    let data = inspect_license(&raw)?;
    let mut lease = data.payload.clone();
    lease.class = Class::Lease;
    lease.max_devices = 0;
    lease.license_id = [0x7c; 16];
    lease.expires_at = Some(lease.issued_at + 3600);
    lease.renew_after = Some(lease.issued_at + 1800);
    lease.device_pub = Some(SigningKey::from_seed(&[11; 32]).public().into());
    let seed = fs::read_to_string(directory.path("delegate.key"))?;
    let seed: [u8; 32] = hex::decode(
        seed.strip_prefix("VOUCHKIT-DELEGATE-1\n")
            .context("DK format")?
            .trim(),
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("invalid delegate seed"))?;
    let cert = fs::read(directory.path("cert.bin"))?;
    let signed = sign_lease(9, &SigningKey::from_seed(&seed), &cert, &lease)?;
    fs::write(directory.path("lease.vk"), encode_license_file(&signed))?;

    let revoke = || {
        let mut command = directory.command();
        command.args(["revoke", "--key", "master.key"]);
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        command
    };
    let one = revoke()
        .args(["--lease", "lease.vk", "--out", "lease-crl.bin"])
        .spawn()?;
    let two = revoke()
        .args(["--entitlement", entitlement_id, "--out", "purchase-crl.bin"])
        .spawn()?;
    output(one.wait_with_output()?)?;
    output(two.wait_with_output()?)?;
    let verifier = directory.verifier()?;
    let left = verifier.verify_crl(&fs::read(directory.path("lease-crl.bin"))?)?;
    let right = verifier.verify_crl(&fs::read(directory.path("purchase-crl.bin"))?)?;
    assert_eq!(left.seq.min(right.seq), 1);
    assert_eq!(left.seq.max(right.seq), 2);
    let canonical = verifier.verify_crl(&fs::read(directory.path("issued.jsonl.crl"))?)?;
    assert_eq!(canonical.seq, 2);
    assert_eq!(canonical.revoked_licenses, [lease.license_id]);
    assert_eq!(canonical.revoked_entitlements, [lease.entitlement_id]);
    assert!(
        directory
            .verify("entitlement.vk", &["--crl", "issued.jsonl.crl"])
            .is_err()
    );
    Ok(())
}

#[test]
fn p256_master_header_and_device_algorithm_are_authenticated() -> Result<()> {
    let directory = Workdir::new()?;
    directory.private_file("passphrase", b"fixture passphrase")?;
    directory.vouch(&[
        "keygen",
        "--kind",
        "master",
        "--key-id",
        "12",
        "--algorithm",
        "p256",
        "--passphrase-file",
        "passphrase",
    ])?;

    let master_pub = fs::read_to_string(directory.path("master.pub"))?;
    assert!(master_pub.starts_with("12:p256:"));
    assert!(matches!(
        parse_master_key(&master_pub)?,
        (12, PublicKey::P256(_))
    ));
    let generated = fs::read_to_string(directory.path("public_keys.rs"))?;
    assert!(generated.contains("vouchkit_core::PublicKey::P256"));

    let device_seed = [5; 32];
    let device = SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &device_seed)?;
    let device_pub = encode_signing_public_key(device.public_key());
    let mut device_file = b"VOUCHKIT-DEVICE-P256-2\0".to_vec();
    device_file.extend_from_slice(&device_seed);
    directory.private_file("device.key", &device_file)?;
    directory.private_file("ed25519-device.key", &device_seed)?;

    let issue = |master, out| {
        [
            "issue",
            "--key",
            master,
            "--passphrase-file",
            "passphrase",
            "--class",
            "standalone",
            "--product",
            "demo",
            "--subject",
            "P-256 customer",
            "--tier",
            "1",
            "--device-pub",
            &device_pub,
            "--format",
            "file",
            "--out",
            out,
        ]
    };
    directory.vouch(&issue("master.key.enc", "license.vk"))?;
    assert_eq!(
        directory
            .verify("license.vk", &["--device-key", "device.key"])?
            .trim(),
        "Active",
    );
    let license = fs::read_to_string(directory.path("license.vk"))?;
    let mut signed = decode_token(&license)?;
    assert_eq!(
        signed.first(),
        Some(&2),
        "P-256 uses the algorithm-tagged envelope"
    );
    assert!(license.contains("VK2-"));
    *signed.last_mut().context("expected signature bytes")? ^= 1;
    fs::write(directory.path("tampered.vk"), encode_license_file(&signed))?;
    let error = directory
        .verify("tampered.vk", &["--device-key", "device.key"])
        .expect_err("changing the P-256 signature must invalidate the license");
    assert!(error.to_string().contains("bad signature"));

    let inspected = directory.inspect("license.vk")?;
    assert_eq!(inspected["device_pub"].as_str(), Some(device_pub.as_str()));
    let wrong_device = directory.verify("license.vk", &["--device-key", "ed25519-device.key"]);
    assert!(
        wrong_device.is_err(),
        "the same seed cannot be used as an Ed25519 key"
    );

    let encrypted = fs::read(directory.path("master.key.enc"))?;
    let ciphertext = encrypted
        .strip_prefix(b"VOUCHKIT-MASTER-P256-2\0")
        .context("missing P-256 marker")?;
    let mut downgraded = b"VOUCHKIT-MASTER-1\0".to_vec();
    downgraded.extend_from_slice(ciphertext);
    directory.private_file("downgraded.key", &downgraded)?;
    let error = directory
        .vouch(&issue("downgraded.key", "forged.vk"))
        .expect_err("changing only the algorithm marker must not decrypt the master key");
    assert!(
        error
            .to_string()
            .contains("wrong master key passphrase or damaged key file")
    );
    assert!(!directory.path("forged.vk").exists());
    Ok(())
}

#[test]
fn p256_delegate_with_legacy_author_can_issue_and_revoke_leases() -> Result<()> {
    let directory = Workdir::new()?;
    directory.keygen()?;
    let author = fs::read(directory.path("master.key"))?;
    assert!(author.starts_with(b"VOUCHKIT-MASTER-PLAINTEXT-1\0"));
    let author_pub = fs::read_to_string(directory.path("master.pub"))?;
    assert!(!author_pub.contains("p256:"));
    directory.vouch(&["keygen", "--kind", "delegate", "--algorithm", "p256"])?;
    let encoded = fs::read_to_string(directory.path("delegate.key"))?;
    let scalar: [u8; 32] = hex::decode(
        encoded
            .strip_prefix("VOUCHKIT-DELEGATE-P256-2\n")
            .context("missing P-256 delegate marker")?
            .trim(),
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("invalid P-256 private key length"))?;
    let delegate = SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &scalar)?;
    let public = fs::read_to_string(directory.path("delegate.pub"))?;
    assert_eq!(parse_signing_public_key(&public)?, delegate.public_key());

    directory.vouch(&[
        "delegate",
        "--key",
        "master.key",
        "--delegate-pub",
        "delegate.pub",
        "--product",
        "demo",
        "--max-tier",
        "2",
        "--feature-slots",
        "64",
        "--out",
        "cert.bin",
    ])?;
    directory.vouch(&[
        "issue",
        "--key",
        "master.key",
        "--class",
        "entitlement",
        "--product",
        "demo",
        "--subject",
        "P-256 lease",
        "--tier",
        "2",
        "--feature-slots",
        "64",
        "--out",
        "purchase.vk",
    ])?;
    assert_eq!(
        directory.verify("purchase.vk", &[])?.trim(),
        "NeedsActivation"
    );

    let purchase = fs::read_to_string(directory.path("purchase.vk"))?;
    let mut lease = inspect_license(&decode_token(&purchase)?)?.payload;
    lease.class = Class::Lease;
    lease.license_id = [19; 16];
    lease.max_devices = 0;
    lease.expires_at = Some(lease.issued_at + 3_600);
    lease.renew_after = Some(lease.issued_at + 1_800);
    let device_seed = [12; 32];
    let device = SigningKey::from_seed(&device_seed);
    lease.device_pub = Some(device.public().into());
    directory.private_file("device.key", &device_seed)?;
    let certificate = fs::read(directory.path("cert.bin"))?;
    let lease_bytes = sign_lease(9, &delegate, &certificate, &lease)?;
    fs::write(
        directory.path("lease.vk"),
        encode_license_file(&lease_bytes),
    )?;
    assert_eq!(
        directory
            .verify("lease.vk", &["--device-key", "device.key"])?
            .trim(),
        "Active",
    );
    let inspected = directory.inspect("lease.vk")?;
    assert_eq!(
        inspected["delegation"]["delegate_pub"].as_str(),
        Some(public.trim())
    );

    directory.vouch(&[
        "revoke",
        "--key",
        "master.key",
        "--lease",
        "lease.vk",
        "--out",
        "crl.bin",
    ])?;
    let old_crl = directory
        .verifier()?
        .verify_crl(&fs::read(directory.path("crl.bin"))?)?;
    assert_eq!(old_crl.seq, 1);
    assert_eq!(old_crl.revoked_licenses, [lease.license_id]);

    directory.vouch(&[
        "keygen",
        "--kind",
        "master",
        "--algorithm",
        "p256",
        "--key-id",
        "10",
        "--insecure-plaintext",
        "--out-dir",
        "p256",
    ])?;
    let author = fs::read(directory.path("p256/master.key"))?;
    assert!(author.starts_with(b"VOUCHKIT-MASTER-PLAINTEXT-P256-2\0"));
    let entitlement_id = hex::encode(lease.entitlement_id);
    directory.vouch(&[
        "revoke",
        "--key",
        "p256/master.key",
        "--pubkey",
        "master.pub",
        "--entitlement",
        &entitlement_id,
        "--out",
        "crl.bin",
    ])?;
    let p256_pub = fs::read_to_string(directory.path("p256/master.pub"))?;
    let trusted = [parse_master_key(&author_pub)?, parse_master_key(&p256_pub)?];
    let verifier = Verifier::with_public_keys(&trusted, None);
    let new_crl = verifier.verify_crl(&fs::read(directory.path("crl.bin"))?)?;
    assert_eq!(new_crl.seq, 2);
    assert_eq!(new_crl.revoked_licenses, [lease.license_id]);
    assert_eq!(new_crl.revoked_entitlements, [lease.entitlement_id]);
    let rejected = directory
        .verify(
            "purchase.vk",
            &["--pubkey", "p256/master.pub", "--crl", "crl.bin"],
        )
        .expect_err("a P-256 CRL must revoke a verified Ed25519 entitlement");
    assert!(rejected.to_string().contains("revoked"));
    Ok(())
}
