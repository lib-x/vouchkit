use std::{
    fs,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use tokio::net::TcpListener;
use vouchkit_core::{
    Class, Crl, DelegationCert, DeviceKeyError, DeviceProver, LicensePayload, PublicKey,
    SigningAlgorithm, SigningProvider, SoftwareSigningKey, Verifier, VerifyOptions, encode_token,
    protocol::{
        ActivateRequest, ApiError, DeactivateRequest, ErrorCode, LeaseResponse, RenewRequest,
        encode_signing_public_key,
    },
    sign_crl, sign_delegation, sign_master,
};
use vouchkit_server::{ActivationServer, ActivationStore, MemoryActivationStore, ServerConfig};

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

#[tokio::test]
async fn online_authorization_with_mixed_algorithms_and_no_database_file() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = |name| dir.path().join(name);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let id = [19; 16];
    let key_id = 7;
    let product = "memory-test";
    let app_version = (1, 0, 0);
    let delegate_seed = [53; 32];
    let master = SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &[31; 32])?;
    let delegate = SoftwareSigningKey::from_seed(SigningAlgorithm::P256, &delegate_seed)?;
    let a = Device(SoftwareSigningKey::from_seed(
        SigningAlgorithm::P256,
        &[5; 32],
    )?);
    let b = Device(SoftwareSigningKey::from_seed(
        SigningAlgorithm::Ed25519,
        &[6; 32],
    )?);
    let delegation = DelegationCert {
        cert_id: [21; 16],
        delegate_pub: delegate.public_key(),
        product: product.into(),
        not_before: now.saturating_sub(30),
        not_after: now + 1800,
        max_lease_secs: 1200,
        max_tier: 3,
        feature_mask: 7u32.into(),
    };
    let purchase = LicensePayload {
        class: Class::Entitlement,
        license_id: [22; 16],
        entitlement_id: id,
        product: product.into(),
        subject: "Memory test".into(),
        tier: 2,
        features: 7u32.into(),
        issued_at: now.saturating_sub(30),
        not_before: None,
        expires_at: Some(now + 1800),
        renew_after: None,
        grace_secs: 0,
        max_app_version: None,
        max_devices: 1,
        device_pub: None,
        device_hint: None,
        tags: None,
        unlock: Vec::new(),
    };
    let key = encode_signing_public_key(master.public_key());
    fs::write(path("master.pub"), format!("{key_id}:{key}\n"))?;
    fs::write(
        path("delegate.key"),
        format!("VOUCHKIT-DELEGATE-P256-2\n{}\n", hex::encode(delegate_seed)),
    )?;
    fs::write(
        path("cert.bin"),
        sign_delegation(key_id, &master, &delegation)?,
    )?;
    fs::write(
        path("server.toml"),
        r#"master_public_keys = ["master.pub"]
delegate_key = "delegate.key"
delegation_cert = "cert.bin"
lease_secs = 120
grace_secs = 60
"#,
    )?;
    let config = ServerConfig::load(&path("server.toml"))?;
    let store: Box<dyn ActivationStore> = Box::new(MemoryActivationStore::new());
    let service = ActivationServer::load_with_store(&config, store)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = service
        .router()
        .into_make_service_with_connect_info::<SocketAddr>();
    let task = tokio::spawn(async move { axum::serve(listener, app).await });
    let http = Client::builder().no_proxy().build()?;
    let route = |path| format!("http://{address}/v1/{path}");
    let entitlement = encode_token(&sign_master(key_id, &master, &purchase)?);

    let activate_a = ActivateRequest::new(entitlement.clone(), id, &a, None, app_version)?;
    let first: LeaseResponse = http
        .post(route("activate"))
        .json(&activate_a)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut options = VerifyOptions::new(product, app_version, first.server_time);
    options.device = Some(&a);
    let verifier = Verifier::with_public_keys(&[(key_id, master.public_key())], None);
    let verified = verifier.verify(&first.lease_token, &options)?;
    assert_eq!(
        verified
            .license()
            .context("usable lease")?
            .payload()
            .device_pub,
        Some(a.public())
    );

    let replay = http
        .post(route("activate"))
        .json(&activate_a)
        .send()
        .await?;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(replay.json::<ApiError>().await?.code, ErrorCode::Replay);
    let activate_b = ActivateRequest::new(entitlement.clone(), id, &b, None, app_version)?;
    let blocked = http
        .post(route("activate"))
        .json(&activate_b)
        .send()
        .await?;
    assert_eq!(blocked.status(), StatusCode::CONFLICT);
    assert_eq!(blocked.json::<ApiError>().await?.code, ErrorCode::SeatLimit);

    let renew = RenewRequest::new(first.lease_token, id, &a)?;
    let next: LeaseResponse = http
        .post(route("renew"))
        .json(&renew)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let release = DeactivateRequest::lease(next.lease_token, id, &a)?;
    http.post(route("deactivate"))
        .json(&release)
        .send()
        .await?
        .error_for_status()?;
    let activate_b = ActivateRequest::new(entitlement, id, &b, None, app_version)?;
    let second: LeaseResponse = http
        .post(route("activate"))
        .json(&activate_b)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let crl = Crl {
        seq: 1,
        issued_at: now,
        revoked_entitlements: vec![id],
        ..Crl::default()
    };
    let crl_bytes = sign_crl(key_id, &master, &crl)?;
    assert!(service.install_crl(&crl_bytes)?);
    let renew = RenewRequest::new(second.lease_token, id, &b)?;
    let revoked = http.post(route("renew")).json(&renew).send().await?;
    assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
    assert_eq!(revoked.json::<ApiError>().await?.code, ErrorCode::Revoked);
    let downloaded = http
        .get(route("crl"))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(downloaded.as_ref(), crl_bytes);
    assert!(!path("activations.sqlite3").exists());
    task.abort();
    Ok(())
}
