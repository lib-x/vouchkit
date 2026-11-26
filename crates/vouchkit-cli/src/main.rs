//! The offline vouchkit authoring command.

mod args;
mod files;
mod keys;
mod ledger;
mod revoke;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use vouchkit_core::protocol::{MAX_CRL_BYTES, encode_signing_public_key};
use vouchkit_core::{
    Class, DelegationCert, DeviceProver, LicensePayload, MAX_TOKEN_TEXT, PublicKey, Verifier,
    VerifyOptions, VerifyOutcome, asset_seal, decode_token, derive_feature_key, derive_tag_slot,
    derive_tags, encode_license_file, encode_token, inspect_license, random_bytes, sign_delegation,
    sign_master, validate_product,
};
use zeroize::Zeroizing;

use crate::args::{Cli, Command, IssueClass, KeyKind, LedgerCommand, OutputFormat};
use crate::files::{Destination, PendingFile};
use crate::keys::{DeviceKey, MasterKey};
use crate::ledger::{Ledger, Record};

const MAX_ASSET_INPUT: usize = 64 * 1024 * 1024;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let passphrase = cli.passphrase_file.as_deref();
    match cli.command {
        Command::Keygen(args) => match args.kind {
            KeyKind::Master => keys::keygen_master(
                &args.out_dir,
                args.key_id
                    .context("--key-id is required for a master key")?,
                args.algorithm.into(),
                args.insecure_plaintext,
                passphrase,
            ),
            KeyKind::Delegate => {
                ensure!(
                    args.key_id.is_none() && !args.insecure_plaintext && passphrase.is_none(),
                    "--key-id, --insecure-plaintext and --passphrase-file apply to master keys"
                );
                keys::keygen_delegate(&args.out_dir, args.algorithm.into())
            }
        },
        Command::Delegate(args) => delegate(args, passphrase),
        Command::Issue(args) => issue(args, passphrase),
        Command::Profile(args) => profile(args, passphrase),
        Command::SealAsset(args) => seal(args, passphrase),
        Command::Inspect { input } => inspect(&input),
        Command::Verify(args) => verify(args),
        Command::Revoke(args) => revoke::revoke(args, passphrase),
        Command::Ledger {
            action: LedgerCommand::List { ledger },
        } => {
            let ledger = Ledger::acquire(&ledger)?;
            let mut stdout = io::stdout().lock();
            ledger.for_each(|record| {
                serde_json::to_writer(&mut stdout, &record)?;
                stdout.write_all(b"\n")?;
                Ok(())
            })
        }
    }
}

fn delegate(args: args::Delegate, passphrase: Option<&Path>) -> Result<()> {
    let master = MasterKey::read(&args.key, passphrase)?;
    let now = now()?;
    let valid_for = args
        .valid_days
        .checked_mul(86_400)
        .context("delegation duration too large")?;
    ensure!(valid_for != 0, "delegation validity must be positive");
    let cert = DelegationCert {
        cert_id: random_bytes()?,
        delegate_pub: keys::read_delegate_public(&args.delegate_pub)?,
        product: args.product,
        not_before: now,
        not_after: now
            .checked_add(valid_for)
            .context("delegation expiration too large")?,
        max_lease_secs: args.max_lease,
        max_tier: args.max_tier,
        feature_mask: args::slots(args.feature_mask, &args.feature_slots)?,
    };
    let certificate = sign_delegation(master.id, &master.signing, &cert)?;
    let record = Record::Delegation {
        cert_id: hex::encode(cert.cert_id),
        product: cert.product,
        max_tier: cert.max_tier,
        feature_mask: cert.feature_mask,
        issued_at: cert.not_before,
        expires_at: cert.not_after,
    };
    publish_issuance(&args.ledger, Some(&args.out), &certificate, &record)
}

fn issue(args: args::Issue, passphrase: Option<&Path>) -> Result<()> {
    let master = MasterKey::read(&args.key, passphrase)?;
    let issued_at = now()?;
    let entitlement_id = random_bytes()?;
    let expires_at = args
        .expires
        .map(|duration| {
            issued_at
                .checked_add(duration)
                .context("license expiration too large")
        })
        .transpose()?;
    let (class, max_devices) = match args.class {
        IssueClass::Standalone => {
            ensure!(
                args.max_devices.is_none(),
                "--max-devices applies to entitlements"
            );
            (Class::Standalone, 0)
        }
        IssueClass::Entitlement => {
            ensure!(
                args.device_pub.is_none(),
                "--device-pub applies to standalone licenses"
            );
            ensure!(
                args.grace_secs == 0,
                "--grace-secs applies to standalone licenses"
            );
            (Class::Entitlement, args.max_devices.unwrap_or(1))
        }
    };
    let device_pub = args
        .device_pub
        .as_deref()
        .map(keys::parse_public)
        .transpose()?;
    validate_product(&args.product)?;
    let features = args::slots(args.features, &args.feature_slots)?;
    let tags = args
        .tags
        .then(|| derive_tags(&master.seed, &entitlement_id, &args.product));
    let mut unlock_ids = args.unlock;
    unlock_ids.sort_unstable();
    ensure!(
        unlock_ids.len() <= 4,
        "a license can carry at most four resource keys"
    );
    ensure!(
        unlock_ids.windows(2).all(|ids| ids.first() != ids.last()),
        "duplicate resource key ID"
    );
    ensure!(
        unlock_ids.iter().all(|id| features.contains(*id)),
        "each resource key ID must be included in the granted feature slots"
    );
    let unlock = unlock_ids
        .into_iter()
        .map(|id| (id, derive_feature_key(&master.seed, &args.product, id)))
        .collect();
    let payload = LicensePayload {
        class,
        license_id: random_bytes()?,
        entitlement_id,
        product: args.product,
        subject: args.subject,
        tier: args.tier,
        features,
        issued_at,
        not_before: args.not_before,
        expires_at,
        renew_after: None,
        grace_secs: args.grace_secs,
        max_app_version: args.max_version,
        max_devices,
        device_pub,
        device_hint: None,
        tags,
        unlock,
    };
    let signed = Zeroizing::new(sign_master(master.id, &master.signing, &payload)?);
    let mut output = Zeroizing::new(match args.format {
        OutputFormat::Token => encode_token(&signed),
        OutputFormat::File => encode_license_file(&signed),
    });
    if !output.ends_with('\n') {
        output.push('\n');
    }
    let record = Record::License {
        license_id: hex::encode(payload.license_id),
        entitlement_id: hex::encode(entitlement_id),
        class: args.class.label().to_owned(),
        product: payload.product.clone(),
        subject: payload.subject.clone(),
        tier: payload.tier,
        features: payload.features.clone(),
        issued_at,
        expires_at,
    };
    publish_issuance(
        &args.ledger,
        args.out.as_deref(),
        output.as_bytes(),
        &record,
    )
}

fn publish_issuance(
    ledger_path: &Path,
    out: Option<&Path>,
    bytes: &[u8],
    record: &Record,
) -> Result<()> {
    let ledger = Ledger::acquire(ledger_path)?;
    let staged = out
        .map(|path| {
            ledger.reject_reserved_output(path)?;
            files::require_absent(path)?;
            PendingFile::new(path, bytes).map(|file| (file, path))
        })
        .transpose()?;
    ledger.append(record)?;
    match staged {
        Some((file, path)) => file.persist(path, Destination::New),
        None => {
            let mut output = io::stdout().lock();
            output.write_all(bytes)?;
            output.flush()?;
            Ok(())
        }
    }
}

fn profile(args: args::Profile, passphrase: Option<&Path>) -> Result<()> {
    let mut slots = args.slots;
    slots.sort_unstable();
    ensure!(
        (2..=8).contains(&slots.len()) && slots.windows(2).all(|ids| ids.first() != ids.last()),
        "select two or more distinct tag slots"
    );
    let master = MasterKey::read(&args.key, passphrase)?;
    let mut source = Zeroizing::new(String::from(
        "pub static TAG_PROFILE: vouchkit_core::TagProfile = vouchkit_core::TagProfile::new(&[\n",
    ));
    for index in slots {
        use std::fmt::Write;

        let key = Zeroizing::new(derive_tag_slot(&master.seed, index)?);
        writeln!(
            &mut *source,
            "    vouchkit_core::TagSlot {{ index: {index}, key: {:?} }},",
            *key
        )?;
    }
    source.push_str("]);\n");
    files::write(&args.out, source.as_bytes(), Destination::New)
}

fn seal(args: args::SealAsset, passphrase: Option<&Path>) -> Result<()> {
    validate_product(&args.product)?;
    let master = MasterKey::read(&args.key, passphrase)?;
    let resource = files::read(&args.input, MAX_ASSET_INPUT)?;
    let key = Zeroizing::new(derive_feature_key(
        &master.seed,
        &args.product,
        args.feature,
    ));
    let sealed = asset_seal(&key, &resource)?;
    files::write(&args.out, &sealed, Destination::New)
}

fn inspect(input: &OsStr) -> Result<()> {
    let token = read_token(input)?;
    let bytes = Zeroizing::new(decode_token(&token)?);
    let inspected = inspect_license(&bytes)?;
    let payload = &inspected.payload;
    let delegation = inspected.delegation.map(|cert| {
        serde_json::json!({
            "cert_id": hex::encode(cert.cert_id),
            "delegate_pub": encode_signing_public_key(cert.delegate_pub),
            "product": cert.product,
            "not_before": cert.not_before,
            "not_after": cert.not_after,
            "max_lease_secs": cert.max_lease_secs,
            "max_tier": cert.max_tier,
            "feature_slots": cert.feature_mask.ranges(),
        })
    });
    let metadata = serde_json::json!({
        "signature_verified": false,
        "key_id": inspected.key_id,
        "class": payload.class,
        "license_id": hex::encode(payload.license_id),
        "entitlement_id": hex::encode(payload.entitlement_id),
        "product": payload.product,
        "subject": payload.subject,
        "tier": payload.tier,
        "feature_slots": payload.features.ranges(),
        "issued_at": payload.issued_at,
        "not_before": payload.not_before,
        "expires_at": payload.expires_at,
        "renew_after": payload.renew_after,
        "grace_secs": payload.grace_secs,
        "max_app_version": payload.max_app_version,
        "max_devices": payload.max_devices,
        "device_pub": payload.device_pub.map(|key| match key {
            PublicKey::Ed25519(bytes) => hex::encode(bytes),
            _ => encode_signing_public_key(key),
        }),
        "device_hint": payload.device_hint.map(hex::encode),
        "tags": payload.tags.map(|tags| tags.map(hex::encode)),
        "unlock_features": payload.unlock.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        "delegation": delegation,
    });
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &metadata)?;
    writeln!(stdout)?;
    Ok(())
}

fn verify(args: args::Verify) -> Result<()> {
    let trusted = read_public_keys(&args.pubkey)?;
    let verifier = Verifier::with_public_keys(&trusted, None);
    let token = read_token(&args.input)?;
    let device = args
        .device_key
        .as_deref()
        .map(DeviceKey::read)
        .transpose()?;
    let crl = args
        .crl
        .as_deref()
        .map(|file| -> Result<_> {
            let bytes = files::read(file, MAX_CRL_BYTES)?;
            Ok(verifier.verify_crl(&bytes)?)
        })
        .transpose()?;
    let mut options = VerifyOptions::new(&args.product, args.app_version, now()?);
    options.device = device.as_ref().map(|key| key as &dyn DeviceProver);
    options.crl = crl.as_ref();
    let outcome = verifier.verify(&token, &options)?;
    let mut stdout = io::stdout().lock();
    match outcome {
        VerifyOutcome::Active(_) => writeln!(stdout, "Active")?,
        VerifyOutcome::RenewSoon(_) => writeln!(stdout, "RenewSoon")?,
        VerifyOutcome::Grace(_, remaining) => {
            writeln!(stdout, "Grace ({remaining} seconds remaining)")?
        }
        VerifyOutcome::NeedsActivation(_) => writeln!(stdout, "NeedsActivation")?,
    }
    Ok(())
}

fn read_public_keys(paths: &[std::path::PathBuf]) -> Result<Vec<(u8, PublicKey)>> {
    let mut public_keys = Vec::new();
    for path in paths {
        add_public_key(&mut public_keys, keys::read_master_public(path)?)?;
    }
    Ok(public_keys)
}

fn add_public_key(keys: &mut Vec<(u8, PublicKey)>, entry: (u8, PublicKey)) -> Result<()> {
    if let Some(existing) = keys.iter().find(|(id, _)| *id == entry.0) {
        ensure!(*existing == entry, "duplicate master key ID {}", entry.0);
    } else {
        keys.push(entry);
    }
    Ok(())
}

fn read_token(input: &OsStr) -> Result<Zeroizing<String>> {
    if let Some(input) = input.to_str()
        && decode_token(input).map(Zeroizing::new).is_ok()
    {
        return Ok(Zeroizing::new(input.to_owned()));
    }
    let path = Path::new(input);
    match path.try_exists() {
        Ok(true) => {
            let bytes = files::read(path, MAX_TOKEN_TEXT)?;
            let token = std::str::from_utf8(&bytes).context("license file must be UTF-8")?;
            Ok(Zeroizing::new(token.to_owned()))
        }
        Ok(false) => bail!("invalid license token or missing license file"),
        Err(error) => Err(error).context("checking license file"),
    }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("clock is before the Unix epoch")?
        .as_secs())
}
