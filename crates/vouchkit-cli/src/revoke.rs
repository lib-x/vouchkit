use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use vouchkit_core::protocol::MAX_CRL_BYTES;
use vouchkit_core::{Class, Crl, Id, SigningProvider, Verifier, decode_token, sign_crl};
use zeroize::Zeroizing;

use crate::args::Revoke;
use crate::files::{self, Destination, PendingFile};
use crate::keys::MasterKey;
use crate::ledger::{Ledger, Record};

pub(crate) fn revoke(args: Revoke, passphrase: Option<&Path>) -> Result<()> {
    ensure!(
        !args.license.is_empty()
            || !args.lease.is_empty()
            || !args.entitlement.is_empty()
            || !args.cert.is_empty(),
        "specify at least one license, lease, entitlement or certificate to revoke"
    );
    let master = MasterKey::read(&args.key, passphrase)?;
    let mut public_keys = super::read_public_keys(&args.pubkey)?;
    super::add_public_key(&mut public_keys, (master.id, master.signing.public_key()))?;
    let verifier = Verifier::with_public_keys(&public_keys, None);
    let mut leases = Vec::new();
    for input in &args.lease {
        let token = super::read_token(input)?;
        let bytes = Zeroizing::new(decode_token(&token)?);
        let signed = verifier.authenticate(&bytes)?;
        let payload = signed.payload();
        ensure!(
            payload.class == Class::Lease,
            "--lease requires a signed lease"
        );
        let certificate = signed.certificate().context("lease has no delegation")?;
        leases.push(LeaseTarget {
            id: payload.license_id,
            entitlement: hex::encode(payload.entitlement_id),
            certificate: hex::encode(certificate.cert_id),
            product: payload.product.clone(),
        });
    }
    let ledger = Ledger::acquire(&args.ledger)?;
    let state_path = ledger.crl_path()?;
    IssuedTargets::read(&ledger, &args, &leases)?.ensure_known()?;

    let published = read_existing(&args.out, &verifier)?;
    let persisted = read_existing(&state_path, &verifier)?;
    let mut payload = merge_history(published, persisted)?;
    let now = super::now()?;
    ensure!(
        payload.issued_at <= now,
        "clock precedes the last CRL issuance"
    );
    payload.seq = payload
        .seq
        .checked_add(1)
        .context("CRL sequence exhausted")?;
    payload.issued_at = now;

    payload.revoked_licenses = merge(
        payload.revoked_licenses,
        args.license
            .into_iter()
            .chain(leases.into_iter().map(|lease| lease.id)),
    );
    payload.revoked_entitlements = merge(payload.revoked_entitlements, args.entitlement);
    if let Some(since) = args.since {
        payload.revoked_certs = merge_certificates(payload.revoked_certs, args.cert, since);
    }

    let signed = sign_crl(master.id, &master.signing, &payload)?;
    let state = PendingFile::new(&state_path, &signed)?;
    let in_place = files::normalized_target(&args.out)? == files::normalized_target(&state_path)?;
    let exported = if in_place {
        None
    } else {
        ledger.reject_reserved_output(&args.out)?;
        Some(PendingFile::new(&args.out, &signed)?)
    };
    state.persist(&state_path, Destination::Replace)?;
    if let Some(exported) = exported {
        exported.persist(&args.out, Destination::Replace)?;
    }
    Ok(())
}

struct IssuedTargets {
    licenses: BTreeSet<String>,
    entitlements: BTreeSet<String>,
    certs: BTreeSet<String>,
    lease_entitlements: BTreeSet<(String, String)>,
    lease_certs: BTreeSet<(String, String)>,
}

struct LeaseTarget {
    id: Id,
    entitlement: String,
    certificate: String,
    product: String,
}

impl IssuedTargets {
    fn read(ledger: &Ledger, args: &Revoke, leases: &[LeaseTarget]) -> Result<Self> {
        let mut unknown = Self {
            licenses: args.license.iter().map(hex::encode).collect(),
            entitlements: args.entitlement.iter().map(hex::encode).collect(),
            certs: args.cert.iter().map(hex::encode).collect(),
            lease_entitlements: leases
                .iter()
                .map(|lease| (lease.entitlement.clone(), lease.product.clone()))
                .collect(),
            lease_certs: leases
                .iter()
                .map(|lease| (lease.certificate.clone(), lease.product.clone()))
                .collect(),
        };
        ledger.for_each(|record| {
            match record {
                Record::License {
                    license_id,
                    entitlement_id,
                    class,
                    product,
                    ..
                } => {
                    unknown.licenses.remove(&license_id);
                    unknown.entitlements.remove(&entitlement_id);
                    if class == "entitlement" {
                        unknown
                            .lease_entitlements
                            .remove(&(entitlement_id, product));
                    }
                }
                Record::Delegation {
                    cert_id, product, ..
                } => {
                    unknown.certs.remove(&cert_id);
                    unknown.lease_certs.remove(&(cert_id, product));
                }
            }
            Ok(())
        })?;
        Ok(unknown)
    }

    fn ensure_known(&self) -> Result<()> {
        for (name, remaining) in [
            ("license", &self.licenses),
            ("entitlement", &self.entitlements),
            ("delegation certificate", &self.certs),
        ] {
            if let Some(first) = remaining.first() {
                bail!("unknown {name} ID {first} in issuance ledger");
            }
        }
        if let Some((id, _)) = self.lease_entitlements.first() {
            bail!("unknown lease entitlement ID {id} in issuance ledger");
        }
        if let Some((id, _)) = self.lease_certs.first() {
            bail!("unknown lease certificate ID {id} in issuance ledger");
        }
        Ok(())
    }
}

type ExistingCrl = (Crl, Zeroizing<Vec<u8>>);

fn read_existing(path: &Path, verifier: &Verifier) -> Result<Option<ExistingCrl>> {
    match path.symlink_metadata() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("examining {}", path.display())),
        Ok(metadata) => ensure!(
            metadata.is_file(),
            "{} is not a regular file",
            path.display()
        ),
    }
    let bytes = files::read(path, MAX_CRL_BYTES)?;
    let crl = verifier
        .verify_crl(&bytes)
        .with_context(|| format!("authenticating existing revocation list {}", path.display()))?;
    Ok(Some((crl, bytes)))
}

fn merge_history(published: Option<ExistingCrl>, persisted: Option<ExistingCrl>) -> Result<Crl> {
    match (published, persisted) {
        (Some((mut published, published_bytes)), Some((persisted, persisted_bytes))) => {
            if published.seq == persisted.seq {
                ensure!(
                    published_bytes == persisted_bytes,
                    "conflicting signed CRLs with the same sequence"
                );
                return Ok(published);
            }
            published.seq = published.seq.max(persisted.seq);
            published.issued_at = published.issued_at.max(persisted.issued_at);
            published.revoked_licenses =
                merge(published.revoked_licenses, persisted.revoked_licenses);
            published.revoked_entitlements = merge(
                published.revoked_entitlements,
                persisted.revoked_entitlements,
            );
            published.revoked_certs = earliest_certificates(
                published
                    .revoked_certs
                    .into_iter()
                    .chain(persisted.revoked_certs),
            );
            Ok(published)
        }
        (published, persisted) => Ok(published
            .or(persisted)
            .map_or_else(Crl::default, |(crl, _)| crl)),
    }
}

fn merge(old: Vec<Id>, added: impl IntoIterator<Item = Id>) -> Vec<Id> {
    old.into_iter()
        .chain(added)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn merge_certificates(old: Vec<(Id, u64)>, added: Vec<Id>, since: u64) -> Vec<(Id, u64)> {
    earliest_certificates(
        old.into_iter()
            .chain(added.into_iter().map(|id| (id, since))),
    )
}

fn earliest_certificates(entries: impl IntoIterator<Item = (Id, u64)>) -> Vec<(Id, u64)> {
    let mut earliest = BTreeMap::new();
    for (id, since) in entries {
        earliest
            .entry(id)
            .and_modify(|previous: &mut u64| *previous = (*previous).min(since))
            .or_insert(since);
    }
    earliest.into_iter().collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn merging_certificate_revocations_preserves_the_earliest_cutoff() {
        let a = [1; 16];
        let b = [2; 16];
        let c = [3; 16];
        let merged = super::merge_certificates(vec![(a, 4), (b, 7)], vec![a, b, c], 6);
        assert_eq!(merged, [(a, 4), (b, 6), (c, 6)]);
    }
}
