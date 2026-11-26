use proptest::prelude::*;
use vouchkit_core::{
    Crl, DeviceKeyError, DeviceProver, FeatureSlots, LicenseError, LicenseState, PublicKey,
    SigningKey, StateStore, TagProfile, TagSlot, Verifier, VerifyOptions, VerifyOutcome,
    asset_open, asset_seal, check_clock_with_skew, decode_token, derive_feature_key,
    derive_tag_slot, derive_tags, embed_pubkeys, encode_license_file, encode_token,
    inspect_license,
    protocol::{ActivateRequest, DeactivateRequest, RenewRequest},
    sign_crl, sign_delegation, sign_lease, sign_master,
};

const NOW: u64 = 1_700_000_000;
const ROOT_ID: u8 = 255;
const FIXED_PRODUCT: &str = "vouchkit-self-test";
const ROOT_PUBLIC: [u8; 32] = [
    208, 74, 178, 50, 116, 43, 180, 171, 58, 19, 104, 189, 70, 21, 228, 230, 208, 34, 74, 183, 26,
    1, 107, 175, 133, 32, 163, 50, 201, 119, 135, 55,
];
const STANDALONE: &[u8] = include_bytes!("fixtures/standalone.bin");
const ENTITLEMENT: &[u8] = include_bytes!("fixtures/entitlement.bin");
const LEASE: &[u8] = include_bytes!("fixtures/lease.bin");
const CERT: &[u8] = include_bytes!("fixtures/delegation.bin");
const CRL: &[u8] = include_bytes!("fixtures/crl.bin");
const BAD: &[u8] = include_bytes!("fixtures/bad_signature.bin");

struct Device {
    key: SigningKey,
    deny: bool,
}

impl Device {
    fn fixed() -> Self {
        Self {
            key: SigningKey::from_seed(&[51; 32]),
            deny: false,
        }
    }
}

impl DeviceProver for Device {
    fn public(&self) -> PublicKey {
        self.key.public().into()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DeviceKeyError> {
        if self.deny {
            Err(DeviceKeyError::Denied)
        } else {
            Ok(self.key.sign(message))
        }
    }
}

fn fixture_verifier() -> Verifier {
    Verifier::new(&[(ROOT_ID, ROOT_PUBLIC)], None)
}

fn fixture_opts(now: u64) -> VerifyOptions<'static> {
    VerifyOptions::new(FIXED_PRODUCT, (1, 2, 3), now)
}

#[test]
fn independent_fixed_vectors_verify_and_reproduce() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = fixture_verifier();
    let device = Device::fixed();
    let mut opts = fixture_opts(NOW + 1);
    opts.device = Some(&device);
    assert!(matches!(
        verifier.verify_bytes(STANDALONE, &opts)?,
        VerifyOutcome::Active(_)
    ));
    assert!(matches!(
        verifier.verify_bytes(ENTITLEMENT, &opts)?,
        VerifyOutcome::NeedsActivation(_)
    ));
    assert!(matches!(
        verifier.verify_bytes(LEASE, &opts)?,
        VerifyOutcome::Active(_)
    ));
    assert_eq!(
        verifier.verify_bytes(BAD, &opts).unwrap_err(),
        LicenseError::BadSignature
    );
    let master = SigningKey::from_seed(&[17; 32]);
    let delegate = SigningKey::from_seed(&[34; 32]);
    assert_eq!(master.public(), ROOT_PUBLIC);
    let (id, cert) = verifier.verify_delegation(CERT)?;
    assert_eq!(id, ROOT_ID);
    assert_eq!(sign_delegation(id, &master, &cert)?, CERT);
    assert_eq!(sign_crl(id, &master, &verifier.verify_crl(CRL)?)?, CRL);
    assert_eq!(
        sign_master(id, &master, &inspect_license(STANDALONE)?.payload)?,
        STANDALONE
    );
    assert_eq!(
        sign_master(id, &master, &inspect_license(ENTITLEMENT)?.payload)?,
        ENTITLEMENT
    );
    assert_eq!(
        sign_lease(id, &delegate, CERT, &inspect_license(LEASE)?.payload)?,
        LEASE
    );
    assert_eq!(
        verifier.pubkeys_fingerprint(),
        Verifier::new(&embed_pubkeys![(ROOT_ID, ROOT_PUBLIC)], None).pubkeys_fingerprint()
    );
    verifier.self_test()?;
    Ok(())
}

#[test]
fn every_changed_envelope_byte_fails_and_text_aliases_are_equivalent() -> Result<(), LicenseError> {
    let verifier = fixture_verifier();
    let device = Device::fixed();
    let mut opts = fixture_opts(NOW + 1);
    opts.device = Some(&device);
    for original in [STANDALONE, ENTITLEMENT, LEASE] {
        for offset in 0..original.len() {
            let mut changed = original.to_vec();
            changed[offset] ^= 1;
            assert!(
                verifier.verify_bytes(&changed, &opts).is_err(),
                "accepted mutation at {offset}"
            );
        }
        let token = encode_token(original);
        let aliases = token
            .to_lowercase()
            .replace('0', "O")
            .replace('1', "l")
            .replacen("vkl", "vk1", 1);
        assert_eq!(decode_token(&format!(" \t{aliases}\r\n"))?, original);
        assert_eq!(decode_token(&encode_license_file(original))?, original);
        let mut group_chars = token
            .strip_prefix("VK1-")
            .ok_or(LicenseError::Malformed)?
            .replace('-', "");
        let final_symbol = group_chars.pop().ok_or(LicenseError::Malformed)?;
        group_chars.push(if final_symbol == '0' { '8' } else { '0' });
        assert!(
            verifier
                .verify(&format!("VK1-{group_chars}"), &opts)
                .is_err()
        );
    }
    for offset in 0..CRL.len() {
        let mut changed = CRL.to_vec();
        changed[offset] ^= 1;
        assert!(
            verifier.verify_crl(&changed).is_err(),
            "accepted CRL mutation at {offset}"
        );
    }
    for offset in 0..CERT.len() {
        let mut changed = CERT.to_vec();
        changed[offset] ^= 1;
        assert!(
            verifier.verify_delegation(&changed).is_err(),
            "accepted certificate mutation at {offset}"
        );
    }
    assert_eq!(decode_token("VK1-ZZ").unwrap_err(), LicenseError::Malformed);
    assert_eq!(
        decode_token(&format!("VK1-{}", "0".repeat(8_000))).unwrap_err(),
        LicenseError::Malformed
    );
    Ok(())
}

#[test]
fn verifier_reports_specific_failures_and_exact_time_boundaries() -> Result<(), LicenseError> {
    let verifier = fixture_verifier();
    let mut wrong = VerifyOptions::new("different", (1, 0, 0), NOW + 1);
    assert_eq!(
        verifier.verify_bytes(STANDALONE, &wrong).unwrap_err(),
        LicenseError::WrongProduct
    );
    wrong.product = FIXED_PRODUCT;
    wrong.app_version = (2, 8, 0);
    assert_eq!(
        verifier.verify_bytes(STANDALONE, &wrong).unwrap_err(),
        LicenseError::VersionNotCovered
    );
    wrong.app_version = (2, 7, 0);
    wrong.now = NOW - 301;
    assert_eq!(
        verifier.verify_bytes(STANDALONE, &wrong).unwrap_err(),
        LicenseError::NotYetValid
    );
    wrong.now += 1;
    assert!(verifier.verify_bytes(STANDALONE, &wrong).is_ok());
    assert_eq!(
        Verifier::new(&[], None)
            .verify_bytes(STANDALONE, &wrong)
            .unwrap_err(),
        LicenseError::UnknownKeyId
    );
    assert_eq!(
        Verifier::new(&[(ROOT_ID, ROOT_PUBLIC), (ROOT_ID, ROOT_PUBLIC)], None)
            .verify_bytes(STANDALONE, &wrong)
            .unwrap_err(),
        LicenseError::UnknownKeyId
    );
    assert_eq!(
        verifier.verify_bytes(&[99], &wrong).unwrap_err(),
        LicenseError::UnsupportedVersion
    );
    assert_eq!(
        verifier.verify_bytes(&[1, 7], &wrong).unwrap_err(),
        LicenseError::Malformed
    );

    let mut opts = fixture_opts(NOW);
    assert_eq!(
        verifier.verify_bytes(LEASE, &opts).unwrap_err(),
        LicenseError::DeviceProofFailed
    );
    let denied = Device {
        deny: true,
        ..Device::fixed()
    };
    opts.device = Some(&denied);
    assert_eq!(
        verifier.verify_bytes(LEASE, &opts).unwrap_err(),
        LicenseError::DeviceKey(DeviceKeyError::Denied)
    );
    let device = Device::fixed();
    opts.device = Some(&device);
    let cases = [
        (NOW + 299, LicenseState::Active),
        (NOW + 300, LicenseState::RenewSoon { since: NOW + 300 }),
        (NOW + 599, LicenseState::RenewSoon { since: NOW + 300 }),
        (NOW + 600, LicenseState::Grace { remaining_secs: 60 }),
        (NOW + 659, LicenseState::Grace { remaining_secs: 1 }),
    ];
    for (now, expected) in cases {
        opts.now = now;
        assert_eq!(verifier.verify_bytes(LEASE, &opts)?.state(), expected);
    }
    opts.now = NOW + 660;
    assert_eq!(
        verifier.verify_bytes(LEASE, &opts).unwrap_err(),
        LicenseError::Expired
    );
    Ok(())
}

#[test]
fn feature_intervals_are_canonical_and_require_subset_authority() -> Result<(), LicenseError> {
    let set = FeatureSlots::try_from_ranges(&[
        (155, 160),
        (3, 3),
        (100, 154),
        (3, 5),
        (u16::MAX, u16::MAX),
    ])?;
    assert_eq!(set.ranges(), &[(3, 5), (100, 160), (u16::MAX, u16::MAX)]);
    assert!(set.contains(151));
    assert!(!set.contains(161));
    assert!(FeatureSlots::try_from_ranges(&[(152, 155)])?.is_subset_of(&set));
    assert!(!FeatureSlots::try_from_ranges(&[(4, 101)])?.is_subset_of(&set));
    assert_eq!(
        FeatureSlots::try_from_ranges(&[(4, 2)]),
        Err(LicenseError::Malformed)
    );
    let too_many: Vec<_> = (0..17).map(|i| (i * 2, i * 2)).collect();
    assert_eq!(
        FeatureSlots::try_from_ranges(&too_many),
        Err(LicenseError::Malformed)
    );
    assert_eq!(FeatureSlots::from(0x5555_5555).ranges().len(), 16);
    Ok(())
}

#[test]
fn build_tags_and_assets_follow_the_verified_purchase() -> Result<(), LicenseError> {
    let master = SigningKey::from_seed(&[17; 32]);
    let mut payload = inspect_license(STANDALONE)?.payload;
    payload.tags = Some(derive_tags(
        &[17; 32],
        &payload.entitlement_id,
        &payload.product,
    ));
    let good_key = derive_feature_key(&[17; 32], &payload.product, 1050);
    payload.unlock = vec![(1050, good_key)];
    let bytes = sign_master(ROOT_ID, &master, &payload)?;
    let slots_a = [0, 1].map(|index| TagSlot {
        index,
        key: derive_tag_slot(&[17; 32], index).unwrap(),
    });
    let slots_b = [4, 7].map(|index| TagSlot {
        index,
        key: derive_tag_slot(&[17; 32], index).unwrap(),
    });
    let a: &'static TagProfile = Box::leak(Box::new(TagProfile::new(Box::leak(Box::new(slots_a)))));
    let b: &'static TagProfile = Box::leak(Box::new(TagProfile::new(Box::leak(Box::new(slots_b)))));
    let opts = fixture_opts(NOW);
    let asset = asset_seal(&good_key, b"licensed resource")?;
    for profile in [a, b] {
        let verifier = Verifier::new(&[(ROOT_ID, ROOT_PUBLIC)], Some(profile));
        let outcome = verifier.verify_bytes(&bytes, &opts)?;
        let license = outcome.license().ok_or(LicenseError::Malformed)?;
        assert_eq!(license.unlock_key(100), None);
        assert_eq!(
            asset_open(
                license.unlock_key(1050).ok_or(LicenseError::Malformed)?,
                &asset
            )?,
            b"licensed resource"
        );
        license.recheck(&verifier, NOW)?;
        license.recheck_with(&verifier, &opts)?;
    }
    let verifier = Verifier::new(&[(ROOT_ID, ROOT_PUBLIC)], Some(a));
    assert_eq!(
        verifier.verify_bytes(STANDALONE, &opts).unwrap_err(),
        LicenseError::TagMismatch
    );
    payload.tags.as_mut().expect("assigned build tags")[0][0] ^= 1;
    let bad_tags = sign_master(ROOT_ID, &master, &payload)?;
    assert_eq!(
        verifier.verify_bytes(&bad_tags, &opts).unwrap_err(),
        LicenseError::TagMismatch
    );
    assert!(
        Verifier::new(&[(ROOT_ID, ROOT_PUBLIC)], Some(b))
            .verify_bytes(&bad_tags, &opts)
            .is_ok()
    );
    assert_eq!(
        asset_open(&[0; 32], &asset),
        Err(LicenseError::BadSignature)
    );
    Ok(())
}

#[derive(Default)]
struct Store {
    seq: Option<u64>,
    crl: Option<Vec<u8>>,
    last: Option<u64>,
    fail_flush: bool,
}

impl StateStore for Store {
    fn get_max_crl_seq(&self) -> Option<u64> {
        self.seq
    }
    fn set_max_crl_seq(&mut self, seq: u64) {
        self.seq = Some(seq);
    }
    fn get_last_seen_time(&self) -> Option<u64> {
        self.last
    }
    fn set_last_seen_time(&mut self, now: u64) {
        self.last = Some(now);
    }
    fn get_lease(&self) -> Option<Vec<u8>> {
        None
    }
    fn set_lease(&mut self, _: &[u8]) {}
    fn get_crl(&self) -> Option<Vec<u8>> {
        self.crl.clone()
    }
    fn set_crl(&mut self, bytes: &[u8]) {
        self.crl = Some(bytes.to_vec());
    }
    fn flush(&mut self) -> Result<(), LicenseError> {
        if self.fail_flush {
            Err(LicenseError::StateStorage)
        } else {
            Ok(())
        }
    }
}

#[test]
fn revocation_watermark_clock_and_cert_since_fail_closed() -> Result<(), LicenseError> {
    let verifier = fixture_verifier();
    let master = SigningKey::from_seed(&[17; 32]);
    let mut store = Store::default();
    let first = verifier.load_crl(CRL, &mut store)?;
    assert_eq!(store.seq, Some(1));
    assert_eq!(verifier.load_crl(CRL, &mut store)?, first);
    let mut next = first.clone();
    next.revoked_entitlements.clear();
    assert_eq!(
        verifier.load_crl(&sign_crl(ROOT_ID, &master, &next)?, &mut store),
        Err(LicenseError::CrlRollback)
    );
    next.seq += 1;
    assert_eq!(
        verifier.load_crl(&sign_crl(ROOT_ID, &master, &next)?, &mut store)?,
        next
    );
    assert_eq!(
        verifier.load_crl(CRL, &mut store),
        Err(LicenseError::CrlRollback)
    );
    let conflicting = Crl {
        seq: 3,
        revoked_entitlements: first.revoked_entitlements.clone(),
        ..Crl::default()
    };
    let mut newer_crl = fixture_opts(NOW);
    newer_crl.crl = Some(&conflicting);
    assert_eq!(
        verifier
            .verify_with_store(&encode_token(STANDALONE), &newer_crl, &mut store)
            .unwrap_err(),
        LicenseError::CrlUnavailable
    );
    let signed = verifier.authenticate(LEASE)?;
    assert_eq!(
        signed.check_revocation(Some(&first)),
        Err(LicenseError::Revoked)
    );
    assert!(signed.check_revocation(Some(&next)).is_ok());
    next.revoked_certs[0].1 = NOW;
    assert_eq!(
        signed.check_revocation(Some(&next)),
        Err(LicenseError::CertRevoked)
    );
    next.revoked_certs.clear();
    next.revoked_licenses.push(signed.payload().license_id);
    assert_eq!(
        signed.check_revocation(Some(&next)),
        Err(LicenseError::Revoked)
    );
    assert_eq!(check_clock_with_skew(NOW + 10, &mut store, 300)?, NOW + 10);
    assert_eq!(check_clock_with_skew(NOW, &mut store, 300)?, NOW + 10);
    assert_eq!(
        check_clock_with_skew(NOW - 291, &mut store, 300),
        Err(LicenseError::ClockRollback)
    );
    store.crl = None;
    assert_eq!(
        verifier
            .verify_with_store(&encode_token(STANDALONE), &fixture_opts(NOW), &mut store)
            .unwrap_err(),
        LicenseError::CrlUnavailable
    );
    store.fail_flush = true;
    for _ in 0..2 {
        assert_eq!(
            check_clock_with_skew(NOW + 11, &mut store, 300),
            Err(LicenseError::StateStorage)
        );
    }
    store.fail_flush = false;
    assert_eq!(check_clock_with_skew(NOW + 11, &mut store, 300)?, NOW + 11);
    Ok(())
}

#[test]
fn activation_proofs_bind_operation_and_request_fields() -> Result<(), LicenseError> {
    let device = Device::fixed();
    let id = inspect_license(ENTITLEMENT)?.payload.entitlement_id;
    let token = encode_token(ENTITLEMENT);
    let mut activation =
        ActivateRequest::new(token.clone(), id, &device, Some([7; 16]), (1, 2, 3))?;
    activation.verify_proof(id)?;
    activation.app_version.2 += 1;
    assert_eq!(
        activation.verify_proof(id),
        Err(LicenseError::DeviceProofFailed)
    );
    activation.app_version.2 -= 1;
    activation.device_hint = None;
    assert_eq!(
        activation.verify_proof(id),
        Err(LicenseError::DeviceProofFailed)
    );
    let mut deactivation = DeactivateRequest::entitlement(token, id, &device)?;
    deactivation.verify_proof(id)?;
    deactivation.nonce = activation.nonce;
    deactivation.proof = activation.proof;
    assert_eq!(
        deactivation.verify_proof(id),
        Err(LicenseError::DeviceProofFailed)
    );
    let mut renewal = RenewRequest::new(encode_token(LEASE), id, &device)?;
    renewal.verify_proof(id, device.public())?;
    renewal.lease_token = encode_token(STANDALONE);
    assert_eq!(
        renewal.verify_proof(id, device.public()),
        Err(LicenseError::DeviceProofFailed)
    );
    Ok(())
}

#[test]
fn signer_rejects_excessive_fields() -> Result<(), LicenseError> {
    let master = SigningKey::from_seed(&[17; 32]);
    let mut payload = inspect_license(STANDALONE)?.payload;
    payload.subject = "é".repeat(33);
    assert_eq!(
        sign_master(ROOT_ID, &master, &payload),
        Err(LicenseError::Malformed)
    );
    payload.subject.clear();
    payload.product = "p".repeat(33);
    assert_eq!(
        sign_master(ROOT_ID, &master, &payload),
        Err(LicenseError::Malformed)
    );
    payload.product = "非 ASCII".into();
    assert_eq!(
        sign_master(ROOT_ID, &master, &payload),
        Err(LicenseError::Malformed)
    );
    let list = Crl {
        seq: 1,
        revoked_licenses: vec![[0; 16]; 8193],
        ..Crl::default()
    };
    assert_eq!(
        sign_crl(ROOT_ID, &master, &list),
        Err(LicenseError::Malformed)
    );
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn random_payloads_sign_and_roundtrip(
        product in "[a-z0-9-]{1,32}", subject in "[A-Za-z0-9 ]{0,64}",
        mask in any::<u32>(), id in any::<[u8; 16]>(), tier in any::<u8>(),
    ) {
        let master = SigningKey::from_seed(&[17; 32]);
        let mut payload = inspect_license(STANDALONE).unwrap().payload;
        payload.product = product.clone();
        payload.subject = subject;
        payload.license_id = id;
        payload.tier = tier;
        payload.features = mask.into();
        let bytes = sign_master(ROOT_ID, &master, &payload).unwrap();
        let text = encode_token(&bytes);
        prop_assert_eq!(decode_token(&text).unwrap(), bytes);
        let outcome = fixture_verifier().verify(&text, &VerifyOptions::new(&product, (1, 0, 0), NOW)).unwrap();
        prop_assert_eq!(outcome.license().unwrap().payload(), &payload);
    }
}

#[test]
fn author_provider_can_use_an_external_key_handle() -> Result<(), LicenseError> {
    use vouchkit_core::{Ed25519Signer, SigningError, SigningProvider};

    enum Provider {
        Available(SigningKey),
        Denied,
        WrongKey(SigningKey),
    }

    impl Ed25519Signer for Provider {
        fn public(&self) -> [u8; 32] {
            ROOT_PUBLIC
        }

        fn try_sign(&self, message: &[u8]) -> Result<[u8; 64], SigningError> {
            match self {
                Self::Available(key) | Self::WrongKey(key) => Ok(key.sign(message)),
                Self::Denied => Err(SigningError::Denied),
            }
        }
    }

    let claims = inspect_license(STANDALONE)?.payload;
    let external: Box<dyn SigningProvider + Send + Sync> =
        Box::new(Provider::Available(SigningKey::from_seed(&[17; 32])));
    assert_eq!(sign_master(ROOT_ID, &external, &claims)?, STANDALONE);
    let external = Provider::WrongKey(SigningKey::from_seed(&[123; 32]));
    assert_eq!(
        sign_master(ROOT_ID, &external, &claims),
        Err(LicenseError::Signing(SigningError::InvalidSignature))
    );
    assert_eq!(
        sign_master(ROOT_ID, &Provider::Denied, &claims),
        Err(LicenseError::Signing(SigningError::Denied))
    );
    Ok(())
}
