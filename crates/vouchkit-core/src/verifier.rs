use zeroize::Zeroizing;

use crate::{
    Class, Crl, DelegationCert, EntitlementInfo, LicenseError, PublicKey, SignedLicense,
    SigningAlgorithm, StateStore, TagProfile, VerifiedLicense, VerifyOptions, VerifyOutcome,
    check_clock_with_skew, decode_token, random_bytes,
    wire::{authenticate_certificate, authenticate_crl, authenticate_license},
};

const DEVICE_DOMAIN: &[u8] = b"vouchkit-device-v1\0";
const DEVICE_DOMAIN_V2: &[u8] = b"vouchkit-device-v2\0";
const SELF_TEST_KEY: (u8, [u8; 32]) = (
    255,
    [
        208, 74, 178, 50, 116, 43, 180, 171, 58, 19, 104, 189, 70, 21, 228, 230, 208, 34, 74, 183,
        26, 1, 107, 175, 133, 32, 163, 50, 201, 119, 135, 55,
    ],
);
const SELF_TEST_GOOD: &[u8] = include_bytes!("self-test.bin");
const SELF_TEST_P256_KEY: PublicKey = PublicKey::P256(*include_bytes!("self-test-p256.pub"));
const SELF_TEST_P256_GOOD: &[u8] = include_bytes!("self-test-p256.bin");

/// Verifies author signatures, delegated leases and optional build tags.
#[derive(Debug, Clone)]
pub struct Verifier {
    master_keys: Vec<(u8, PublicKey)>,
    tag_profile: Option<&'static TagProfile>,
}

impl Verifier {
    /// Configures the author's trusted key IDs and optional build tag profile.
    ///
    /// Duplicate key IDs fail closed when an input names the ambiguous ID.
    pub fn new(master_keys: &[(u8, [u8; 32])], tag_profile: Option<&'static TagProfile>) -> Self {
        let keys: Vec<_> = master_keys
            .iter()
            .map(|&(id, key)| (id, key.into()))
            .collect();
        Self::from_keys(keys, tag_profile)
    }

    /// Configures algorithm-tagged trust anchors and an optional build tag profile.
    ///
    /// Each identifier must have a single trusted key across all algorithms.
    pub fn with_public_keys(
        master_keys: &[(u8, PublicKey)],
        tag_profile: Option<&'static TagProfile>,
    ) -> Self {
        Self::from_keys(master_keys.to_vec(), tag_profile)
    }

    fn from_keys(
        mut master_keys: Vec<(u8, PublicKey)>,
        tag_profile: Option<&'static TagProfile>,
    ) -> Self {
        master_keys.sort_unstable();
        Self {
            master_keys,
            tag_profile,
        }
    }

    fn key(&self, id: u8) -> Result<PublicKey, LicenseError> {
        let start = self.master_keys.partition_point(|(key_id, _)| *key_id < id);
        let end = self
            .master_keys
            .partition_point(|(key_id, _)| *key_id <= id);
        match self.master_keys.get(start..end) {
            Some([(_, key)]) => Ok(*key),
            _ => Err(LicenseError::UnknownKeyId),
        }
    }

    /// Returns a stable fingerprint of the configured master key table.
    pub fn pubkeys_fingerprint(&self) -> [u8; 32] {
        let legacy = self
            .master_keys
            .iter()
            .all(|(_, key)| key.algorithm() == SigningAlgorithm::Ed25519);
        let context = if legacy {
            "vouchkit-pubkeys-v1"
        } else {
            "vouchkit-pubkeys-v2"
        };
        let mut hasher = blake3::Hasher::new_derive_key(context);
        for (id, key) in &self.master_keys {
            hasher.update(&[*id]);
            if !legacy {
                hasher.update(&[key.algorithm().wire_tag()]);
            }
            hasher.update(key.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    /// Authenticates raw license claims and their delegation without granting access.
    ///
    /// # Errors
    ///
    /// Rejects invalid framing, signatures, claims or delegation constraints.
    pub fn authenticate(&self, bytes: &[u8]) -> Result<SignedLicense, LicenseError> {
        let signed = authenticate_license(bytes, |id| self.key(id))?;
        signed.check_delegation()?;
        Ok(signed)
    }

    /// Reconstructs and authenticates a standalone delegation certificate.
    ///
    /// # Errors
    ///
    /// Returns an error if the certificate cannot be decoded or authenticated.
    pub fn verify_delegation(&self, bytes: &[u8]) -> Result<(u8, DelegationCert), LicenseError> {
        authenticate_certificate(bytes, |id| self.key(id))
    }

    /// Checks signature and format of a CRL without updating replay protection.
    ///
    /// # Errors
    ///
    /// Returns an error if the CRL cannot be decoded or authenticated.
    pub fn verify_crl(&self, bytes: &[u8]) -> Result<Crl, LicenseError> {
        authenticate_crl(bytes, |id| self.key(id))
    }

    /// Authenticates and stores a CRL, enforcing the store's sequence watermark.
    ///
    /// # Errors
    ///
    /// Rejects malformed, older or conflicting same-sequence lists and storage failures.
    pub fn load_crl(&self, bytes: &[u8], store: &mut dyn StateStore) -> Result<Crl, LicenseError> {
        let crl = self.verify_crl(bytes)?;
        if let Some(previous) = store.get_max_crl_seq() {
            if crl.seq < previous {
                return Err(LicenseError::CrlRollback);
            }
            if crl.seq == previous
                && let Some(stored) = store.get_crl()
                && self.verify_crl(&stored)? != crl
            {
                return Err(LicenseError::CrlRollback);
            }
        }
        store.set_max_crl_seq(crl.seq);
        store.set_crl(bytes);
        store.flush()?;
        Ok(crl)
    }

    /// Verifies a text token or armored file using the required local conditions.
    ///
    /// # Errors
    ///
    /// Returns the first failed format, authorization or device proof check.
    pub fn verify(
        &self,
        token: &str,
        opts: &VerifyOptions<'_>,
    ) -> Result<VerifyOutcome, LicenseError> {
        let bytes = Zeroizing::new(decode_token(token)?);
        self.verify_bytes(&bytes, opts)
    }

    /// Verifies a binary envelope, including local conditions and device proof.
    ///
    /// # Errors
    ///
    /// Returns the first failed format, authorization or device proof check.
    pub fn verify_bytes(
        &self,
        bytes: &[u8],
        opts: &VerifyOptions<'_>,
    ) -> Result<VerifyOutcome, LicenseError> {
        let signed = authenticate_license(bytes, |id| self.key(id))?;
        let payload = signed.payload();
        if payload.product != opts.product {
            return Err(LicenseError::WrongProduct);
        }
        signed.check_delegation()?;
        signed.check_revocation(opts.crl)?;
        signed.check_time(opts.now, opts.clock_skew_secs)?;
        if payload
            .max_app_version
            .is_some_and(|max| opts.app_version > max)
        {
            return Err(LicenseError::VersionNotCovered);
        }
        if let Some(expected) = payload.device_pub {
            let device = opts.device.ok_or(LicenseError::DeviceProofFailed)?;
            if device.public() != expected {
                return Err(LicenseError::DeviceProofFailed);
            }
            let nonce: [u8; 16] = random_bytes()?;
            let legacy = expected.algorithm() == SigningAlgorithm::Ed25519;
            let domain = if legacy {
                DEVICE_DOMAIN
            } else {
                DEVICE_DOMAIN_V2
            };
            let mut challenge = Vec::with_capacity(domain.len() + 66);
            challenge.extend_from_slice(domain);
            challenge.extend_from_slice(&payload.license_id);
            challenge.extend_from_slice(&nonce);
            if !legacy {
                challenge.push(expected.algorithm().wire_tag());
                challenge.extend_from_slice(expected.as_bytes());
            }
            expected
                .verify(&challenge, &device.sign(&challenge)?)
                .map_err(|_| LicenseError::DeviceProofFailed)?;
        }
        self.check_tags(&signed)?;
        if payload.class == Class::Entitlement {
            if payload.expires_at.is_some_and(|end| opts.now >= end) {
                return Err(LicenseError::Expired);
            }
            return Ok(VerifyOutcome::NeedsActivation(EntitlementInfo {
                entitlement_id: payload.entitlement_id,
                product: payload.product.clone(),
                max_devices: payload.max_devices,
            }));
        }

        let grace_remaining = payload
            .expires_at
            .filter(|&expires_at| opts.now >= expires_at)
            .map(|expires_at| {
                expires_at
                    .saturating_add(u64::from(payload.grace_secs))
                    .saturating_sub(opts.now)
            });
        let renew = payload
            .renew_after
            .is_some_and(|renew_after| opts.now >= renew_after);
        let verified = VerifiedLicense {
            signed: Box::new(signed),
        };
        Ok(match grace_remaining {
            Some(remaining) => VerifyOutcome::Grace(verified, remaining),
            None if renew => VerifyOutcome::RenewSoon(verified),
            None => VerifyOutcome::Active(verified),
        })
    }

    /// Verifies a token against clock and CRL state maintained by the host.
    ///
    /// # Errors
    ///
    /// Rejects clock rollback, missing current CRLs and ordinary verification failures.
    /// Install a newer signed CRL with [Self::load_crl] before supplying it here,
    /// so the new sequence watermark survives a restart.
    pub fn verify_with_store(
        &self,
        token: &str,
        opts: &VerifyOptions<'_>,
        store: &mut dyn StateStore,
    ) -> Result<VerifyOutcome, LicenseError> {
        let cached = store
            .get_crl()
            .map(|bytes| self.verify_crl(&bytes))
            .transpose()?;
        if let (Some(stored), Some(supplied)) = (cached.as_ref(), opts.crl)
            && (supplied.seq > stored.seq || (supplied.seq == stored.seq && supplied != stored))
        {
            return Err(LicenseError::CrlUnavailable);
        }
        let crl = cached.as_ref().or(opts.crl);
        if let Some(max) = store.get_max_crl_seq()
            && crl.is_none_or(|crl| crl.seq != max)
        {
            return Err(LicenseError::CrlUnavailable);
        }
        let opts = VerifyOptions {
            now: check_clock_with_skew(opts.now, store, opts.clock_skew_secs)?,
            crl,
            ..*opts
        };
        self.verify(token, &opts)
    }

    fn check_tags(&self, signed: &SignedLicense) -> Result<(), LicenseError> {
        if let Some(profile) = self.tag_profile {
            let payload = signed.payload();
            profile.check(
                &payload.entitlement_id,
                &payload.product,
                payload.tags.as_ref(),
            )?;
        }
        Ok(())
    }

    pub(crate) fn recheck(&self, license: &VerifiedLicense, now: u64) -> Result<(), LicenseError> {
        let original = license.signed.payload();
        let signed = self.authenticate(license.signed.bytes())?;
        if signed.payload() != original || signed.payload().class == Class::Entitlement {
            return Err(LicenseError::Tampered);
        }
        signed.check_time(now, 300)?;
        self.check_tags(&signed)
    }

    /// Runs the known-good and known-invalid public verification vectors.
    ///
    /// # Errors
    ///
    /// Returns [LicenseError::Tampered] if either fixture produces an unexpected result.
    pub fn self_test(&self) -> Result<(), LicenseError> {
        Self::run_self_test(|verifier, bytes, options| verifier.verify_bytes(bytes, options))
    }

    fn run_self_test(
        verify: impl Fn(&Verifier, &[u8], &VerifyOptions<'_>) -> Result<VerifyOutcome, LicenseError>,
    ) -> Result<(), LicenseError> {
        let verifier = Self::with_public_keys(
            &[
                (SELF_TEST_KEY.0, SELF_TEST_KEY.1.into()),
                (254, SELF_TEST_P256_KEY),
            ],
            None,
        );
        let opts = VerifyOptions::new("vouchkit-self-test", (1, 0, 0), 1_700_000_001);
        for good in [SELF_TEST_GOOD, SELF_TEST_P256_GOOD] {
            let mut damaged = good.to_vec();
            *damaged.last_mut().ok_or(LicenseError::Tampered)? ^= 1;
            if !matches!(verify(&verifier, good, &opts), Ok(VerifyOutcome::Active(_)))
                || !matches!(
                    verify(&verifier, &damaged, &opts),
                    Err(LicenseError::BadSignature)
                )
            {
                return Err(LicenseError::Tampered);
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "test-util"))]
mod tests {
    use super::*;

    #[test]
    fn self_test_detects_a_verifier_accepting_a_bad_signature() {
        let result = Verifier::run_self_test(|verifier, _, opts| {
            verifier.verify_bytes(SELF_TEST_GOOD, opts)
        });
        assert_eq!(result, Err(LicenseError::Tampered));
    }
}
