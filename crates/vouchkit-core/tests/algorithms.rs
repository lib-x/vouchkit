use vouchkit_core::{
    Class, Crl, DelegationCert, DeviceKeyError, DeviceProver, LicenseError, PublicKey,
    SigningAlgorithm, SigningError, SigningKey, SigningProvider, SoftwareSigningKey, Verifier,
    VerifyOptions, VerifyOutcome, decode_token, encode_token, inspect_license,
    normalize_p256_der_signature,
    protocol::{
        ActivateRequest, RenewRequest, encode_master_key, encode_signing_public_key,
        parse_master_key, parse_signing_public_key,
    },
    sign_crl, sign_delegation, sign_lease, sign_master,
};

const NOW: u64 = 1_700_000_000;
const PRODUCT: &str = "vouchkit-self-test";
const RAW_P256: &[u8] = include_bytes!("../src/self-test-p256.bin");
const KEY_P256: [u8; 33] = *include_bytes!("../src/self-test-p256.pub");
const RAW_ED: &[u8] = include_bytes!("fixtures/standalone.bin");

struct Device(SoftwareSigningKey);

impl DeviceProver for Device {
    fn public(&self) -> PublicKey {
        self.0.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DeviceKeyError> {
        self.0
            .try_sign(message)
            .map_err(|_| DeviceKeyError::SigningFailed)
    }
}

#[test]
fn independent_p256_vector_verifies_alongside_v1_ed25519_vector() -> Result<(), LicenseError> {
    let key = SigningKey::from_seed(&[17; 32]).public();
    let p256 = PublicKey::from_p256_sec1(&KEY_P256)?;
    let verifier = Verifier::with_public_keys(&[(254, p256), (255, key.into())], None);
    let opts = VerifyOptions::new(PRODUCT, (1, 0, 0), NOW + 1);
    let p256_token = encode_token(RAW_P256);
    assert!(p256_token.starts_with("VK2-"));
    assert!(encode_token(RAW_ED).starts_with("VK1-"));
    assert!(matches!(
        verifier.verify(&p256_token, &opts)?,
        VerifyOutcome::Active(_)
    ));
    assert!(matches!(
        verifier.verify_bytes(RAW_ED, &opts)?,
        VerifyOutcome::Active(_)
    ));
    assert_eq!(
        decode_token(&p256_token.replacen("VK2-", "VK1-", 1)),
        Err(LicenseError::Malformed)
    );
    assert_eq!(
        parse_master_key(&encode_master_key(254, p256))?,
        (254, p256)
    );
    assert_eq!(
        parse_signing_public_key(&encode_signing_public_key(key.into()))?,
        key.into()
    );
    assert!(verifier.self_test().is_ok());

    let mut unknown = RAW_P256.to_vec();
    unknown[4] = 128;
    assert_eq!(
        verifier.verify_bytes(&unknown, &opts).unwrap_err(),
        LicenseError::UnsupportedAlgorithm
    );
    unknown[4] = 0;
    assert_eq!(
        verifier.verify_bytes(&unknown, &opts).unwrap_err(),
        LicenseError::BadSignature
    );
    let mismatched_trust = Verifier::new(&[(254, key)], None);
    assert_eq!(
        mismatched_trust.verify_bytes(RAW_P256, &opts).unwrap_err(),
        LicenseError::BadSignature
    );
    Ok(())
}

#[test]
fn p256_root_issues_and_revokes_leases_with_either_delegate_and_device_suite()
-> Result<(), LicenseError> {
    let authority = SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &[68; 32])?;
    let verifier = Verifier::with_public_keys(&[(25, authority.public_key())], None);
    let entitlement = inspect_license(include_bytes!("fixtures/entitlement.bin"))?.payload;
    let entitlement_token = encode_token(&sign_master(25, &authority, &entitlement)?);
    let cert_template = DelegationCert {
        cert_id: [15; 16],
        delegate_pub: authority.public_key(),
        product: PRODUCT.into(),
        not_before: NOW,
        not_after: NOW + 300,
        max_lease_secs: 800,
        max_tier: 5,
        feature_mask: entitlement.features.clone(),
    };
    for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::P256] {
        let delegate = SoftwareSigningKey::from_seed(algorithm, &[34; 32])?;
        let mut cert = cert_template.clone();
        cert.delegate_pub = delegate.public_key();
        let certificate = sign_delegation(25, &authority, &cert)?;
        assert_eq!(
            verifier.verify_delegation(&certificate)?,
            (25, cert.clone())
        );
        for device_algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::P256] {
            let device = Device(SoftwareSigningKey::from_seed(device_algorithm, &[45; 32])?);
            let proof = ActivateRequest::new(
                entitlement_token.clone(),
                entitlement.entitlement_id,
                &device,
                None,
                (1, 0, 0),
            )?;
            proof.verify_proof(entitlement.entitlement_id)?;
            let mut lease = inspect_license(include_bytes!("fixtures/lease.bin"))?.payload;
            lease.class = Class::Lease;
            lease.device_pub = Some(device.public());
            let signed = sign_lease(25, &delegate, &certificate, &lease)?;
            let mut opts = VerifyOptions::new(PRODUCT, (1, 0, 0), NOW);
            opts.device = Some(&device);
            assert!(matches!(
                verifier.verify_bytes(&signed, &opts)?,
                VerifyOutcome::Active(_)
            ));
            let proof = RenewRequest::new(encode_token(&signed), lease.entitlement_id, &device)?;
            proof.verify_proof(lease.entitlement_id, device.public())?;
            let crl = Crl {
                seq: 1,
                issued_at: NOW,
                revoked_certs: vec![(cert.cert_id, NOW)],
                ..Crl::default()
            };
            let crl = verifier.verify_crl(&sign_crl(25, &authority, &crl)?)?;
            opts.crl = Some(&crl);
            assert_eq!(
                verifier.verify_bytes(&signed, &opts).unwrap_err(),
                LicenseError::CertRevoked
            );
        }
    }
    Ok(())
}

#[test]
fn p256_rejects_malleable_high_s_and_invalid_key_material() -> Result<(), LicenseError> {
    use p256::ecdsa::Signature;

    // Both signatures are mathematically valid. The protocol admits only the low-S encoding.
    let offset = RAW_P256.len() - 64;
    let sig = Signature::from_slice(&RAW_P256[offset..]).unwrap();
    let high = Signature::from_scalars(sig.r().to_bytes(), (-sig.s()).to_bytes()).unwrap();
    let mut malleable = RAW_P256.to_vec();
    malleable[offset..].copy_from_slice(&high.to_bytes());
    let public = PublicKey::from_p256_sec1(&KEY_P256)?;
    let verifier = Verifier::with_public_keys(&[(254, public)], None);
    assert_eq!(
        verifier.authenticate(&malleable).unwrap_err(),
        LicenseError::BadSignature
    );
    assert_eq!(
        normalize_p256_der_signature(high.to_der().as_bytes())?,
        <[u8; 64]>::from(sig.to_bytes())
    );
    assert_eq!(
        normalize_p256_der_signature(b"bad"),
        Err(SigningError::InvalidSignature)
    );
    assert_eq!(
        SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &[0; 32]).unwrap_err(),
        SigningError::InvalidKey
    );
    assert_eq!(
        PublicKey::from_p256_sec1(&[0; 33]),
        Err(LicenseError::Malformed)
    );
    Ok(())
}
