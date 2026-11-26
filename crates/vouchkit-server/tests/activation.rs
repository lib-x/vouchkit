use std::{
    fs,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use reqwest::{Client, Response, StatusCode};
use serde::Serialize;
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle};
use vouchkit_core::{
    Class, Crl, DelegationCert, DeviceKeyError, DeviceProver, Ed25519Signer, FeatureSlots, Id,
    LicenseError, LicensePayload, SigningError, SigningKey, Verifier, VerifyOptions, VerifyOutcome,
    encode_token,
    protocol::{
        ActivateRequest, ApiError, DeactivateRequest, DeactivateResponse, ErrorCode, LeaseResponse,
        RenewRequest,
    },
    sign_crl, sign_delegation, sign_master,
};
use vouchkit_server::{ActivationServer, ServerConfig, ServerError};

const PRODUCT: &str = "atelier";
const KEY_ID: u8 = 19;
const APP: (u16, u16, u16) = (1, 2, 3);

struct Device(SigningKey);

impl Device {
    fn seeded(byte: u8) -> Self {
        Self(SigningKey::from_seed(&[byte; 32]))
    }
}

impl DeviceProver for Device {
    fn public(&self) -> [u8; 32] {
        self.0.public()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], DeviceKeyError> {
        Ok(self.0.sign(message))
    }
}

struct Fixture {
    temp: TempDir,
    config: ServerConfig,
    server: ActivationServer,
    master: SigningKey,
    now: u64,
    features: FeatureSlots,
    url: String,
    http: Client,
    task: JoinHandle<()>,
}

impl Fixture {
    async fn new() -> Result<Self> {
        Self::with_config("").await
    }

    async fn with_config(extra: &str) -> Result<Self> {
        let temp = tempfile::tempdir()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let master = SigningKey::from_seed(&[19; 32]);
        let delegate = SigningKey::from_seed(&[53; 32]);
        let features = FeatureSlots::try_from_ranges(&[(4, 7), (500, 510)])?;
        let cert = DelegationCert {
            cert_id: [56; 16],
            delegate_pub: delegate.public(),
            product: PRODUCT.into(),
            not_before: now.saturating_sub(60),
            not_after: now + 86_400,
            max_lease_secs: 600,
            max_tier: 3,
            feature_mask: features.clone(),
        };
        fs::write(
            temp.path().join("master.pub"),
            format!("{KEY_ID}:{}\n", STANDARD_NO_PAD.encode(master.public())),
        )?;
        fs::write(
            temp.path().join("delegate.key"),
            format!("VOUCHKIT-DELEGATE-1\n{}\n", hex::encode([53; 32])),
        )?;
        fs::write(
            temp.path().join("cert.bin"),
            sign_delegation(KEY_ID, &master, &cert)?,
        )?;
        let config_path = temp.path().join("config.toml");
        fs::write(
            &config_path,
            format!(
                r#"master_public_keys = ["master.pub"]
delegate_key = "delegate.key"
delegation_cert = "cert.bin"
lease_secs = 2
grace_secs = 120
{extra}"#
            ),
        )?;
        let config = ServerConfig::load(&config_path)?;
        let server = ActivationServer::load(&config)?;
        let (url, task) = listen(&server).await?;
        Ok(Self {
            temp,
            config,
            server,
            master,
            now,
            features,
            url,
            http: Client::builder().no_proxy().build()?,
            task,
        })
    }

    fn verifier(&self) -> Verifier {
        Verifier::new(&[(KEY_ID, self.master.public())], None)
    }

    fn purchase(&self, id: Id) -> Result<String> {
        let payload = LicensePayload {
            class: Class::Entitlement,
            license_id: id.map(|byte| byte ^ 7),
            entitlement_id: id,
            product: PRODUCT.into(),
            subject: "Local test customer".into(),
            tier: 3,
            features: self.features.clone(),
            issued_at: self.now.saturating_sub(60),
            not_before: None,
            expires_at: Some(self.now + 600),
            renew_after: None,
            grace_secs: 0,
            max_app_version: Some(APP),
            max_devices: 1,
            device_pub: None,
            device_hint: None,
            tags: None,
            unlock: Vec::new(),
        };
        Ok(encode_token(&sign_master(KEY_ID, &self.master, &payload)?))
    }

    fn revocation(&self, seq: u64, revoked_entitlements: Vec<Id>) -> Result<Vec<u8>> {
        Ok(sign_crl(
            KEY_ID,
            &self.master,
            &Crl {
                seq,
                issued_at: self.now,
                revoked_entitlements,
                ..Crl::default()
            },
        )?)
    }

    async fn post(&self, path: &str, body: &impl Serialize) -> Result<Response> {
        Ok(self
            .http
            .post(format!("{}/v1/{path}", self.url))
            .json(body)
            .send()
            .await?)
    }

    async fn activate(&self, purchase: &str, id: Id, device: &Device) -> Result<LeaseResponse> {
        let request = ActivateRequest::new(purchase.to_owned(), id, device, None, APP)?;
        Ok(self
            .post("activate", &request)
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn listen(server: &ActivationServer) -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let app = server
        .router()
        .into_make_service_with_connect_info::<SocketAddr>();
    let task = tokio::spawn(async move {
        let _result = axum::serve(listener, app).await;
    });
    Ok((url, task))
}

async fn expect_error(response: Response, wanted: StatusCode, code: ErrorCode) -> Result<()> {
    assert_eq!(response.status(), wanted, "status for {code:?}");
    assert_eq!(response.json::<ApiError>().await?.code, code);
    Ok(())
}

#[tokio::test]
async fn http_activation_renewal_seat_release_and_revocation() -> Result<()> {
    let fixture = Fixture::new().await?;
    let id = [12; 16];
    let purchase = fixture.purchase(id)?;
    let a = Device::seeded(15);
    let b = Device::seeded(16);

    let health = fixture
        .http
        .get(format!("{}/healthz", fixture.url))
        .send()
        .await?;
    assert_eq!(health.status(), StatusCode::OK);

    let no_crl = fixture
        .http
        .get(format!("{}/v1/crl", fixture.url))
        .send()
        .await?;
    assert_eq!(no_crl.status(), StatusCode::NO_CONTENT);

    let request = ActivateRequest::new(purchase.clone(), id, &a, Some([3; 16]), APP)?;
    let first: LeaseResponse = fixture
        .post("activate", &request)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(first.crl_seq, 0);

    let mut opts = VerifyOptions::new(PRODUCT, APP, first.server_time);
    opts.device = Some(&a);
    let verifier = fixture.verifier();
    let valid = verifier.verify(&first.lease_token, &opts)?;
    assert!(matches!(valid, VerifyOutcome::Active(_)));
    let verified = valid.license().context("active lease")?;
    assert_eq!(verified.payload().entitlement_id, id);
    assert_eq!(verified.payload().features, fixture.features);
    assert_eq!(verified.payload().device_hint, Some([3; 16]));

    expect_error(
        fixture.post("activate", &request).await?,
        StatusCode::CONFLICT,
        ErrorCode::Replay,
    )
    .await?;

    let mut wrong_operation = DeactivateRequest::entitlement(purchase.clone(), id, &a)?;
    wrong_operation.nonce = request.nonce;
    wrong_operation.proof = request.proof;
    expect_error(
        fixture.post("deactivate", &wrong_operation).await?,
        StatusCode::FORBIDDEN,
        ErrorCode::DeviceProofFailed,
    )
    .await?;

    let repeat = fixture.activate(&purchase, id, &a).await?;
    assert!(verifier.verify(&repeat.lease_token, &opts).is_ok());

    let seat_request = ActivateRequest::new(purchase.clone(), id, &b, None, APP)?;
    expect_error(
        fixture.post("activate", &seat_request).await?,
        StatusCode::CONFLICT,
        ErrorCode::SeatLimit,
    )
    .await?;

    let renew = RenewRequest::new(first.lease_token.clone(), id, &a)?;
    let renewed: LeaseResponse = fixture
        .post("renew", &renew)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_ne!(renewed.lease_token, first.lease_token);

    let release = DeactivateRequest::lease(renewed.lease_token.clone(), id, &a)?;
    let released: DeactivateResponse = fixture
        .post("deactivate", &release)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(released.ok);
    let repeat_release = DeactivateRequest::lease(renewed.lease_token.clone(), id, &a)?;
    assert!(
        fixture
            .post("deactivate", &repeat_release)
            .await?
            .status()
            .is_success()
    );
    expect_error(
        fixture.post("activate", &seat_request).await?,
        StatusCode::CONFLICT,
        ErrorCode::Replay,
    )
    .await?;

    let _b_lease = fixture.activate(&purchase, id, &b).await?;
    let release = DeactivateRequest::entitlement(purchase.clone(), id, &b)?;
    assert!(
        fixture
            .post("deactivate", &release)
            .await?
            .status()
            .is_success()
    );

    let current = fixture.activate(&purchase, id, &a).await?;
    let expired_registration = DeactivateRequest::lease(renewed.lease_token, id, &a)?;
    expect_error(
        fixture.post("deactivate", &expired_registration).await?,
        StatusCode::CONFLICT,
        ErrorCode::Deactivated,
    )
    .await?;
    let obsolete = RenewRequest::new(first.lease_token, id, &a)?;
    expect_error(
        fixture.post("renew", &obsolete).await?,
        StatusCode::CONFLICT,
        ErrorCode::Deactivated,
    )
    .await?;

    let empty = fixture.revocation(1, Vec::new())?;
    let revoked = fixture.revocation(2, vec![id])?;
    let second_process = ActivationServer::load(&fixture.config)?;
    assert!(second_process.install_crl(&revoked)?);
    assert!(!fixture.server.install_crl(&revoked)?);
    assert!(matches!(
        fixture.server.install_crl(&empty),
        Err(ServerError::License(LicenseError::CrlRollback))
    ));
    assert!(matches!(
        fixture
            .server
            .install_crl(&fixture.revocation(2, Vec::new())?),
        Err(ServerError::CrlConflict)
    ));

    let renew = RenewRequest::new(current.lease_token.clone(), id, &a)?;
    expect_error(
        fixture.post("renew", &renew).await?,
        StatusCode::FORBIDDEN,
        ErrorCode::Revoked,
    )
    .await?;

    let distributed = fixture
        .http
        .get(format!("{}/v1/crl", fixture.url))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    assert_eq!(distributed.as_ref(), revoked);
    let crl = verifier.verify_crl(&distributed)?;
    opts.crl = Some(&crl);
    assert!(matches!(
        verifier.verify(&current.lease_token, &opts),
        Err(LicenseError::Revoked)
    ));
    assert!(fixture.temp.path().join("activations.sqlite3").exists());
    Ok(())
}

#[tokio::test]
async fn health_checks_share_the_tcp_peer_rate_limit() -> Result<()> {
    let fixture = Fixture::with_config("requests_per_ip_per_minute = 1").await?;
    let url = format!("{}/healthz", fixture.url);
    assert_eq!(
        fixture.http.get(&url).send().await?.status(),
        StatusCode::OK
    );
    let second = fixture
        .http
        .get(&url)
        .header("X-Forwarded-For", "192.0.2.53")
        .send()
        .await?;
    expect_error(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::RateLimited,
    )
    .await
}

#[tokio::test]
async fn simultaneous_new_devices_do_not_double_book_a_seat() -> Result<()> {
    let fixture = Fixture::new().await?;
    let id = [22; 16];
    let purchase = fixture.purchase(id)?;
    let a = ActivateRequest::new(purchase.clone(), id, &Device::seeded(28), None, APP)?;
    let b = ActivateRequest::new(purchase, id, &Device::seeded(29), None, APP)?;

    let peer = ActivationServer::load(&fixture.config)?;
    let (peer_url, peer_task) = listen(&peer).await?;
    let peer_request = fixture
        .http
        .post(format!("{peer_url}/v1/activate"))
        .json(&b);
    let results = tokio::join!(fixture.post("activate", &a), peer_request.send());
    peer_task.abort();
    let (a, b) = (results.0?, results.1?);
    let blocked = match (a.status(), b.status()) {
        (StatusCode::OK, StatusCode::CONFLICT) => b,
        (StatusCode::CONFLICT, StatusCode::OK) => a,
        (a, b) => anyhow::bail!("unexpected concurrent activation outcomes: {a} and {b}"),
    };
    expect_error(blocked, StatusCode::CONFLICT, ErrorCode::SeatLimit).await
}

#[tokio::test]
async fn rust_client_redeems_and_renews_over_the_reference_server() -> Result<()> {
    use vouchkit_client::{DeviceKey, MemoryStateStore, Renewal, Renewer, ReqwestTransport};

    let fixture = Fixture::new().await?;
    let purchase = fixture.purchase([23; 16])?;
    let keys = DeviceKey::generate()?;
    let transport = ReqwestTransport::loopback(&fixture.url)?;
    let mut store = MemoryStateStore::new();
    let mut client = Renewer::new(fixture.verifier(), PRODUCT, APP)?;
    let activated = client
        .activate(fixture.now, &purchase, &transport, &mut store, &keys)
        .await?;
    let renew_after = activated
        .license()
        .and_then(|lease| lease.payload().renew_after)
        .context("scheduled renewal")?;
    let renewal = client
        .renew_if_needed(renew_after, &transport, &mut store, &keys)
        .await?;
    assert!(matches!(renewal, Renewal::Renewed(_)));
    Ok(())
}

struct ExternalDelegate {
    sign_calls: Arc<AtomicUsize>,
    key: SigningKey,
}

impl Ed25519Signer for ExternalDelegate {
    fn public(&self) -> [u8; 32] {
        self.key.public()
    }

    fn try_sign(&self, transcript: &[u8]) -> Result<[u8; 64], SigningError> {
        if self.sign_calls.fetch_add(1, Ordering::Relaxed) == 0 {
            return Err(SigningError::Unavailable);
        }
        Ok(self.key.sign(transcript))
    }
}

#[tokio::test]
async fn custom_delegate_needs_no_key_file_and_allows_retry_after_an_outage() -> Result<()> {
    let fixture = Fixture::new().await?;
    fs::remove_file(fixture.temp.path().join("delegate.key"))?;
    let bad_key = SigningKey::from_seed(&[54; 32]);
    assert!(matches!(
        ActivationServer::load_with_delegate(&fixture.config, bad_key),
        Err(ServerError::Config(_))
    ));

    let sign_calls = Arc::new(AtomicUsize::new(0));
    let provider = ExternalDelegate {
        sign_calls: Arc::clone(&sign_calls),
        key: SigningKey::from_seed(&[53; 32]),
    };
    let peer = ActivationServer::load_with_delegate(&fixture.config, provider)?;
    let (url, task) = listen(&peer).await?;
    let id = [71; 16];
    let device = Device::seeded(72);
    let request = ActivateRequest::new(fixture.purchase(id)?, id, &device, None, APP)?;

    let request_builder = || {
        fixture
            .http
            .post(format!("{url}/v1/activate"))
            .json(&request)
    };
    expect_error(
        request_builder().send().await?,
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::Unavailable,
    )
    .await?;
    let response = request_builder()
        .send()
        .await?
        .error_for_status()?
        .json::<LeaseResponse>()
        .await?;
    task.abort();
    assert_eq!(sign_calls.load(Ordering::Relaxed), 2);
    expect_error(
        fixture.post("activate", &request).await?,
        StatusCode::CONFLICT,
        ErrorCode::Replay,
    )
    .await?;

    let mut opts = VerifyOptions::new(PRODUCT, APP, response.server_time);
    opts.device = Some(&device);
    assert!(
        fixture
            .verifier()
            .verify(&response.lease_token, &opts)
            .is_ok()
    );
    Ok(())
}
