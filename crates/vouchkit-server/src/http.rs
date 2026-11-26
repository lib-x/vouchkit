use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Request, State, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use vouchkit_core::{
    LicenseError,
    protocol::{
        ActivateRequest, ApiError, DeactivateRequest, DeactivateResponse, ErrorCode, LeaseResponse,
        RenewRequest,
    },
};
use zeroize::Zeroize;

use crate::{ActivationServer, ServerError};

const MAX_REQUEST_BYTES: usize = 8_192;

pub(crate) fn router(server: ActivationServer) -> Router {
    Router::new()
        .route("/v1/activate", post(activate))
        .route("/v1/renew", post(renew))
        .route("/v1/deactivate", post(deactivate))
        .route("/v1/crl", get(crl))
        .route("/healthz", get(health))
        .route_layer(middleware::from_fn_with_state(
            server.clone(),
            request_guard,
        ))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(server)
}

async fn request_guard(
    State(server): State<ActivationServer>,
    request: Request,
    next: Next,
) -> Result<Response, HttpError> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .ok_or(ServerError::Config("TCP connection info is required"))?;
    server.inner.limits.check_ip(peer.0.ip())?;
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

async fn worker<T: Send + 'static>(
    server: ActivationServer,
    operation: impl FnOnce(&ActivationServer) -> Result<T, ServerError> + Send + 'static,
) -> Result<T, HttpError> {
    let slot = Arc::clone(&server.inner.http_slots)
        .try_acquire_owned()
        .map_err(|_| ServerError::RateLimited)?;
    tokio::task::spawn_blocking(move || {
        // Keep the slot occupied if the request disconnects during blocking work.
        let _slot = slot;
        operation(&server)
    })
    .await
    .map_err(|_| ServerError::Poisoned)?
    .map_err(HttpError::from)
}

async fn activate(
    State(server): State<ActivationServer>,
    request: Result<Json<ActivateRequest>, JsonRejection>,
) -> Result<Json<LeaseResponse>, HttpError> {
    let Json(mut request) = request.map_err(HttpError::bad_request)?;
    worker(server, move |server| {
        let result = server.activate(&request);
        request.entitlement_token.zeroize();
        result
    })
    .await
    .map(Json)
}

async fn renew(
    State(server): State<ActivationServer>,
    request: Result<Json<RenewRequest>, JsonRejection>,
) -> Result<Json<LeaseResponse>, HttpError> {
    let Json(mut request) = request.map_err(HttpError::bad_request)?;
    worker(server, move |server| {
        let result = server.renew(&request);
        request.lease_token.zeroize();
        result
    })
    .await
    .map(Json)
}

async fn deactivate(
    State(server): State<ActivationServer>,
    request: Result<Json<DeactivateRequest>, JsonRejection>,
) -> Result<Json<DeactivateResponse>, HttpError> {
    let Json(mut request) = request.map_err(HttpError::bad_request)?;
    worker(server, move |server| {
        let result = server.deactivate(&request);
        request.lease_token.zeroize();
        request.entitlement_token.zeroize();
        result
    })
    .await
    .map(|()| Json(DeactivateResponse { ok: true }))
}

async fn crl(State(server): State<ActivationServer>) -> Result<Response, HttpError> {
    let Some(bytes) = worker(server, ActivationServer::crl).await? else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    Ok((
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        )],
        Body::from(bytes),
    )
        .into_response())
}

#[derive(Serialize)]
pub(crate) struct Health {
    pub(crate) status: &'static str,
    pub(crate) certificate_remaining_days: u64,
}

async fn health(State(server): State<ActivationServer>) -> Result<impl IntoResponse, HttpError> {
    let health = worker(server, ActivationServer::health).await?;
    let status = if health.status == "ok" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    Ok((status, Json(health)))
}

struct HttpError {
    status: StatusCode,
    code: ErrorCode,
}

impl HttpError {
    fn bad_request(_: JsonRejection) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: ErrorCode::BadRequest,
        }
    }
}

impl From<ServerError> for HttpError {
    fn from(error: ServerError) -> Self {
        let (status, code) = match error {
            ServerError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, ErrorCode::RateLimited),
            ServerError::CertificateInactive | ServerError::Clock => {
                (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Unavailable)
            }
            ServerError::License(error) => match error {
                LicenseError::Malformed => (StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
                LicenseError::SeatLimit => (StatusCode::CONFLICT, ErrorCode::SeatLimit),
                LicenseError::Deactivated => (StatusCode::CONFLICT, ErrorCode::Deactivated),
                LicenseError::Replay => (StatusCode::CONFLICT, ErrorCode::Replay),
                LicenseError::DeviceProofFailed => {
                    (StatusCode::FORBIDDEN, ErrorCode::DeviceProofFailed)
                }
                LicenseError::Revoked => (StatusCode::FORBIDDEN, ErrorCode::Revoked),
                LicenseError::CertRevoked => (StatusCode::FORBIDDEN, ErrorCode::CertRevoked),
                LicenseError::Expired => (StatusCode::FORBIDDEN, ErrorCode::Expired),
                LicenseError::VersionNotCovered => {
                    (StatusCode::FORBIDDEN, ErrorCode::VersionNotCovered)
                }
                LicenseError::Randomness
                | LicenseError::Signing(_)
                | LicenseError::ClockRollback
                | LicenseError::CrlRollback => {
                    (StatusCode::SERVICE_UNAVAILABLE, ErrorCode::Unavailable)
                }
                _ => (StatusCode::FORBIDDEN, ErrorCode::InvalidLicense),
            },
            _ => {
                tracing::error!(error = %error, "activation service operation failed");
                (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal)
            }
        };
        Self { status, code }
    }
}

impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(ApiError { code: self.code })).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        response
    }
}
