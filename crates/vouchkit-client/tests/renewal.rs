use async_trait::async_trait;
use std::sync::atomic::{AtomicUsize, Ordering};
use vouchkit_client::{
    Action, ClientError, Deactivation, DeviceKey, FileStateStore, MemoryStateStore, Renewal,
    Renewer, Transport, TransportError,
};
use vouchkit_core::protocol::{
    ActivateRequest, DeactivateRequest, DeactivateResponse, ErrorCode, LeaseResponse, RenewRequest,
};
use vouchkit_core::{
    Class, Crl, DelegationCert, DeviceProver, FeatureSlots, LicenseError, LicensePayload,
    LicenseState, SigningKey, StateStore, Verifier, VerifyOutcome, encode_token, sign_crl,
    sign_delegation, sign_lease, sign_master,
};

const KEY_ID: u8 = 19;
const ENTITLEMENT: [u8; 16] = [7; 16];
const PRODUCT: &str = "editor";
const FIRST: u64 = 1_003;
const DUR: u64 = 40;
const GRACE: u32 = 12;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    master: SigningKey,
    delegate: SigningKey,
    certificate: Vec<u8>,
    device: DeviceKey,
}

impl Fixture {
    fn new() -> Result<Self, LicenseError> {
        let master = SigningKey::from_seed(&[4; 32]);
        let (delegate, device) = (
            SigningKey::from_seed(&[5; 32]),
            DeviceKey::from_seed(&[6; 32]),
        );
        let certificate = sign_delegation(
            KEY_ID,
            &master,
            &DelegationCert {
                cert_id: [9; 16],
                delegate_pub: delegate.public(),
                product: PRODUCT.to_owned(),
                not_before: 900,
                not_after: 4_000,
                max_lease_secs: 100,
                max_tier: 2,
                feature_mask: FeatureSlots::try_from_ranges(&[(42, 43)])?,
            },
        )?;
        Ok(Self {
            master,
            delegate,
            certificate,
            device,
        })
    }

    fn client(&self) -> Result<Renewer, LicenseError> {
        Renewer::new(
            Verifier::new(&[(KEY_ID, self.master.public())], None),
            PRODUCT,
            (1, 1, 0),
        )
    }

    fn entitlement_claims() -> Result<LicensePayload, LicenseError> {
        Ok(LicensePayload {
            class: Class::Entitlement,
            license_id: [1; 16],
            entitlement_id: ENTITLEMENT,
            product: PRODUCT.to_owned(),
            subject: "test purchase".to_owned(),
            tier: 1,
            features: FeatureSlots::try_from_ranges(&[(42, 42)])?,
            issued_at: 900,
            not_before: None,
            expires_at: Some(2_000),
            renew_after: None,
            grace_secs: 0,
            max_app_version: Some((1, 1, 0)),
            max_devices: 2,
            device_pub: None,
            device_hint: None,
            tags: None,
            unlock: vec![],
        })
    }

    fn entitlement(&self) -> Result<String, LicenseError> {
        Ok(encode_token(&sign_master(
            KEY_ID,
            &self.master,
            &Self::entitlement_claims()?,
        )?))
    }

    fn lease(
        &self,
        issued_at: u64,
        id: u8,
        modify: impl FnOnce(&mut LicensePayload),
    ) -> Result<LeaseResponse, LicenseError> {
        let mut claims = Self::entitlement_claims()?;
        claims.class = Class::Lease;
        claims.license_id = [id; 16];
        claims.issued_at = issued_at;
        claims.device_pub = Some(self.device.public());
        claims.renew_after = Some(issued_at + DUR / 2);
        claims.expires_at = Some(issued_at + DUR);
        claims.grace_secs = GRACE;
        modify(&mut claims);
        let lease_token = encode_token(&sign_lease(
            KEY_ID,
            &self.delegate,
            &self.certificate,
            &claims,
        )?);
        Ok(LeaseResponse {
            lease_token,
            server_time: issued_at,
            crl_seq: 0,
        })
    }

    fn crl(&self, seq: u64, revoked_entitlements: Vec<[u8; 16]>) -> Result<Vec<u8>, LicenseError> {
        sign_crl(
            KEY_ID,
            &self.master,
            &Crl {
                seq,
                issued_at: FIRST,
                revoked_entitlements,
                ..Crl::default()
            },
        )
    }
}

#[derive(Default)]
struct MockTransport {
    activation: Option<LeaseResponse>,
    renewal: Option<Result<LeaseResponse, TransportError>>,
    crl: Option<Vec<u8>>,
    renew_count: AtomicUsize,
}

impl MockTransport {
    fn activation(lease: LeaseResponse) -> Self {
        Self {
            activation: Some(lease),
            ..Self::default()
        }
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn activate(&self, _: &ActivateRequest) -> Result<LeaseResponse, TransportError> {
        self.activation.clone().ok_or(TransportError::Unavailable)
    }

    async fn renew(&self, _: &RenewRequest) -> Result<LeaseResponse, TransportError> {
        self.renew_count.fetch_add(1, Ordering::Relaxed);
        self.renewal
            .clone()
            .unwrap_or(Err(TransportError::Unavailable))
    }

    async fn deactivate(
        &self,
        _: &DeactivateRequest,
    ) -> Result<DeactivateResponse, TransportError> {
        Ok(DeactivateResponse { ok: true })
    }

    async fn fetch_crl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        Ok(self.crl.clone())
    }
}

#[tokio::test]
async fn signed_server_time_advances_watermark_and_renewal_failure_preserves_grace() -> TestResult {
    let fixture = Fixture::new()?;
    let mut client = fixture.client()?;
    let mut store = MemoryStateStore::new();
    let transport = MockTransport::activation(fixture.lease(FIRST, 2, |_| {})?);
    let outcome = client
        .activate(
            FIRST - 3,
            &fixture.entitlement()?,
            &transport,
            &mut store,
            &fixture.device,
        )
        .await?;
    assert!(matches!(outcome, VerifyOutcome::Active(_)));
    assert_eq!(
        store.get_last_seen_time(),
        Some(FIRST),
        "server issuance advances clock"
    );
    assert_eq!(client.tick(FIRST + DUR / 2 - 1), Action::None);
    assert_eq!(client.tick(FIRST + DUR / 2), Action::Renew);

    let due = FIRST + DUR / 2;
    assert!(matches!(
        client
            .renew_if_needed(due, &transport, &mut store, &fixture.device)
            .await,
        Err(ClientError::Transport(TransportError::Unavailable)),
    ));
    assert_eq!(
        client.tick(due),
        Action::None,
        "failed renewals apply backoff"
    );
    assert!(matches!(
        client
            .renew_if_needed(due + 1, &transport, &mut store, &fixture.device)
            .await?,
        Renewal::NotDue,
    ));
    assert_eq!(transport.renew_count.load(Ordering::Relaxed), 1);
    assert_eq!(
        client.state(FIRST + DUR, &mut store, &fixture.device),
        LicenseState::Grace {
            remaining_secs: u64::from(GRACE)
        },
    );
    assert_eq!(
        client.state(
            FIRST + DUR + u64::from(GRACE) - 1,
            &mut store,
            &fixture.device
        ),
        LicenseState::Grace { remaining_secs: 1 },
    );
    let end = FIRST + DUR + u64::from(GRACE);
    assert_eq!(
        client.state(end, &mut store, &fixture.device),
        LicenseState::Expired
    );
    assert_eq!(
        client.state(end - 1, &mut store, &fixture.device),
        LicenseState::Expired,
        "a small rollback cannot re-enter grace",
    );
    assert_eq!(
        client.state(end - 301, &mut store, &fixture.device),
        LicenseState::Invalid(LicenseError::ClockRollback),
    );
    Ok(())
}

#[tokio::test]
async fn invalid_response_cannot_replace_lease_or_poison_clock() -> TestResult {
    let fixture = Fixture::new()?;
    let mut client = fixture.client()?;
    let mut store = MemoryStateStore::new();
    let mut activation = fixture.lease(FIRST, 2, |_| {})?;
    activation.server_time = u64::MAX;
    let transport = MockTransport::activation(activation);
    assert!(matches!(
        client
            .activate(
                FIRST,
                &fixture.entitlement()?,
                &transport,
                &mut store,
                &fixture.device
            )
            .await,
        Err(ClientError::UnexpectedResponse),
    ));
    assert!(store.get_lease().is_none());
    assert_eq!(store.get_last_seen_time(), Some(FIRST));

    let valid = fixture.lease(FIRST, 2, |_| {})?;
    let mut transport = MockTransport::activation(valid.clone());
    transport.renewal = Some(Ok(fixture.lease(FIRST - 1, 3, |_| {})?));
    client
        .activate(
            FIRST,
            &fixture.entitlement()?,
            &transport,
            &mut store,
            &fixture.device,
        )
        .await?;
    let due = FIRST + DUR / 2;
    assert!(matches!(
        client
            .renew_if_needed(due, &transport, &mut store, &fixture.device)
            .await,
        Err(ClientError::UnexpectedResponse)
    ));
    assert_eq!(
        store.get_lease().as_deref(),
        Some(valid.lease_token.as_bytes())
    );

    let retry = due + 5;
    let replacement = fixture.lease(retry, 4, |_| {})?;
    transport.renewal = Some(Ok(replacement.clone()));
    assert!(matches!(
        client
            .renew_if_needed(retry, &transport, &mut store, &fixture.device)
            .await?,
        Renewal::Renewed(VerifyOutcome::Active(_))
    ));
    assert_eq!(
        store.get_lease().as_deref(),
        Some(replacement.lease_token.as_bytes())
    );
    client
        .deactivate(Deactivation::Lease, &transport, &mut store, &fixture.device)
        .await?;
    assert!(store.get_entitlement().is_none());
    assert_eq!(
        client.state(retry, &mut store, &fixture.device),
        LicenseState::NeedsActivation
    );
    Ok(())
}

#[tokio::test]
async fn signed_times_cannot_ratchet_beyond_tolerance_from_the_local_clock() -> TestResult {
    let fixture = Fixture::new()?;
    let mut client = fixture.client()?;
    let mut store = MemoryStateStore::new();
    let now = 1_000;
    let expected_watermark = now + 290;
    let first = fixture.lease(expected_watermark, 2, |_| {})?;
    let second = fixture.lease(now + 500, 3, |_| {})?;
    let entitlement = fixture.entitlement()?;
    client
        .activate(
            now,
            &entitlement,
            &MockTransport::activation(first),
            &mut store,
            &fixture.device,
        )
        .await?;
    assert!(matches!(
        client
            .activate(
                now,
                &entitlement,
                &MockTransport::activation(second),
                &mut store,
                &fixture.device
            )
            .await,
        Err(ClientError::UnexpectedResponse),
    ));
    assert_eq!(store.get_last_seen_time(), Some(expected_watermark));
    Ok(())
}

#[tokio::test]
async fn renewal_after_restart_enforces_the_original_signed_purchase_deadline() -> TestResult {
    let fixture = Fixture::new()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("license.state");
    let starts_at = 1_945;
    let due = starts_at + DUR / 2;
    let original = fixture.lease(starts_at, 2, |_| {})?;
    let candidate = fixture.lease(due, 3, |_| {})?;
    let entitlement = fixture.entitlement()?;
    let mut transport = MockTransport::activation(original.clone());
    transport.renewal = Some(Ok(candidate));
    {
        let mut store = FileStateStore::open(&path)?;
        fixture
            .client()?
            .activate(
                starts_at,
                &entitlement,
                &transport,
                &mut store,
                &fixture.device,
            )
            .await?;
    }

    let mut store = FileStateStore::open(&path)?;
    assert_eq!(
        store.get_entitlement().as_deref(),
        Some(entitlement.as_bytes())
    );
    let mut client = fixture.client()?;
    assert!(matches!(
        client
            .renew_if_needed(due, &transport, &mut store, &fixture.device)
            .await,
        Err(ClientError::UnexpectedResponse),
    ));
    assert_eq!(
        store.get_lease().as_deref(),
        Some(original.lease_token.as_bytes())
    );
    assert!(matches!(
        client.state(due, &mut store, &fixture.device),
        LicenseState::RenewSoon { .. }
    ));
    Ok(())
}

#[tokio::test]
async fn delegate_response_cannot_exceed_the_purchased_grant() -> TestResult {
    let fixture = Fixture::new()?;
    let mut client = fixture.client()?;
    let mut store = MemoryStateStore::new();
    let response = fixture.lease(FIRST, 2, |claims| claims.tier += 1)?;
    let transport = MockTransport::activation(response);
    assert!(matches!(
        client
            .activate(
                FIRST,
                &fixture.entitlement()?,
                &transport,
                &mut store,
                &fixture.device
            )
            .await,
        Err(ClientError::UnexpectedResponse)
    ));
    assert!(store.get_lease().is_none());
    Ok(())
}

#[tokio::test]
async fn signed_crl_from_revoked_renewal_invalidates_cache_and_prevents_rollback() -> TestResult {
    let fixture = Fixture::new()?;
    let mut client = fixture.client()?;
    let mut store = MemoryStateStore::new();
    let mut response = fixture.lease(FIRST, 2, |_| {})?;
    response.crl_seq = 1;
    let prior = fixture.crl(1, vec![])?;
    let mut transport = MockTransport::activation(response);
    transport.crl = Some(prior.clone());
    client
        .activate(
            FIRST,
            &fixture.entitlement()?,
            &transport,
            &mut store,
            &fixture.device,
        )
        .await?;
    assert_eq!(store.get_max_crl_seq(), Some(1));
    assert_eq!(store.get_crl().as_deref(), Some(prior.as_slice()));

    transport.renewal = Some(Err(TransportError::Rejected(ErrorCode::Revoked)));
    transport.crl = Some(fixture.crl(2, vec![ENTITLEMENT])?);
    let due = FIRST + DUR / 2;
    assert!(matches!(
        client
            .renew_if_needed(due, &transport, &mut store, &fixture.device)
            .await,
        Err(ClientError::Transport(TransportError::Rejected(
            ErrorCode::Revoked
        )))
    ));
    assert_eq!(store.get_max_crl_seq(), Some(2));
    assert_eq!(
        client.state(due, &mut store, &fixture.device),
        LicenseState::Invalid(LicenseError::Revoked)
    );
    transport.crl = Some(prior);
    assert!(matches!(
        client.refresh_crl(&transport, &mut store).await,
        Err(ClientError::License(LicenseError::CrlRollback))
    ));
    assert_eq!(store.get_max_crl_seq(), Some(2));
    Ok(())
}
