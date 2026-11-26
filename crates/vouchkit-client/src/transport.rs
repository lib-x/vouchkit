use async_trait::async_trait;
use thiserror::Error;
use vouchkit_core::protocol::{
    ActivateRequest, DeactivateRequest, DeactivateResponse, ErrorCode, LeaseResponse, RenewRequest,
};

/// Transport for the versioned activation protocol.
///
/// Implementations should authenticate and encrypt the channel and limit
/// response sizes before allocating.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Exchanges a purchase for a device-bound lease.
    async fn activate(&self, request: &ActivateRequest) -> Result<LeaseResponse, TransportError>;

    /// Renews an existing device-bound lease.
    async fn renew(&self, request: &RenewRequest) -> Result<LeaseResponse, TransportError>;

    /// Releases a device's active seat.
    async fn deactivate(
        &self,
        request: &DeactivateRequest,
    ) -> Result<DeactivateResponse, TransportError>;

    /// Downloads a signed CRL or reports that the server has no CRL.
    async fn fetch_crl(&self) -> Result<Option<Vec<u8>>, TransportError>;
}

/// Failures reported by an activation transport.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The endpoint URL violates the transport's scheme or origin requirements.
    #[error("invalid activation server endpoint")]
    InvalidEndpoint,
    /// The server could not be reached or the connection timed out.
    #[error("activation server unavailable")]
    Unavailable,
    /// The server sent a response that exceeds its allowed size.
    #[error("activation response exceeds its size limit")]
    TooLarge,
    /// The response could not be decoded as the activation protocol.
    #[error("invalid activation protocol response")]
    Protocol,
    /// The server returned a typed activation error.
    #[error("activation server rejected the request ({0:?})")]
    Rejected(ErrorCode),
}

#[cfg(feature = "reqwest")]
pub use http::ReqwestTransport;

#[cfg(feature = "reqwest")]
mod http {
    use std::net::IpAddr;

    use reqwest::{Client, Response, StatusCode, Url};
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use vouchkit_core::protocol::{ApiError, MAX_CRL_BYTES, MAX_JSON_BYTES};
    use zeroize::Zeroizing;

    use super::{
        ActivateRequest, DeactivateRequest, DeactivateResponse, ErrorCode, LeaseResponse,
        RenewRequest, Transport, TransportError, async_trait,
    };

    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

    /// JSON over HTTPS transport with bounded responses and redirects disabled.
    #[derive(Debug, Clone)]
    pub struct ReqwestTransport {
        client: Client,
        endpoint: Url,
    }

    impl ReqwestTransport {
        /// Connects only to an HTTPS activation origin.
        ///
        /// # Errors
        ///
        /// Returns an error if the endpoint is invalid or TLS initialization fails.
        pub fn new(endpoint: &str) -> Result<Self, TransportError> {
            Self::from_endpoint(endpoint, Scheme::Https)
        }

        /// Connects over HTTP to an explicit numeric loopback origin for local use.
        ///
        /// # Errors
        ///
        /// Returns an error for non-loopback endpoints or client initialization failure.
        pub fn loopback(endpoint: &str) -> Result<Self, TransportError> {
            Self::from_endpoint(endpoint, Scheme::Loopback)
        }

        fn from_endpoint(endpoint: &str, scheme: Scheme) -> Result<Self, TransportError> {
            let mut endpoint = Url::parse(endpoint).map_err(|_| TransportError::InvalidEndpoint)?;
            if endpoint.host_str().is_none()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
            {
                return Err(TransportError::InvalidEndpoint);
            }
            let mut builder = Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(CONNECT_TIMEOUT)
                .timeout(REQUEST_TIMEOUT);
            match scheme {
                Scheme::Https if endpoint.scheme() == "https" => {
                    builder = builder.https_only(true);
                }
                Scheme::Loopback if endpoint.scheme() == "http" && is_loopback(&endpoint) => {
                    builder = builder.no_proxy();
                }
                _ => return Err(TransportError::InvalidEndpoint),
            }
            if !endpoint.path().ends_with('/') {
                endpoint
                    .path_segments_mut()
                    .map_err(|()| TransportError::InvalidEndpoint)?
                    .push("");
            }
            let client = builder.build().map_err(|_| TransportError::Unavailable)?;
            Ok(Self { client, endpoint })
        }

        fn url(&self, path: &str) -> Result<Url, TransportError> {
            self.endpoint
                .join(path)
                .map_err(|_| TransportError::InvalidEndpoint)
        }

        async fn post<S, R>(&self, path: &str, data: &S) -> Result<R, TransportError>
        where
            S: Serialize + Sync,
            R: DeserializeOwned,
        {
            let response = self
                .client
                .post(self.url(path)?)
                .json(data)
                .send()
                .await
                .map_err(|_| TransportError::Unavailable)?;
            let response = accept(response).await?;
            let body = Zeroizing::new(bounded_body(response, MAX_JSON_BYTES).await?);
            serde_json::from_slice(&body).map_err(|_| TransportError::Protocol)
        }
    }

    #[derive(Clone, Copy)]
    enum Scheme {
        Https,
        Loopback,
    }

    fn is_loopback(endpoint: &Url) -> bool {
        endpoint
            .host_str()
            .and_then(|host| host.trim_matches(['[', ']']).parse::<IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
    }

    #[async_trait]
    impl Transport for ReqwestTransport {
        async fn activate(
            &self,
            request: &ActivateRequest,
        ) -> Result<LeaseResponse, TransportError> {
            self.post("v1/activate", request).await
        }

        async fn renew(&self, request: &RenewRequest) -> Result<LeaseResponse, TransportError> {
            self.post("v1/renew", request).await
        }

        async fn deactivate(
            &self,
            request: &DeactivateRequest,
        ) -> Result<DeactivateResponse, TransportError> {
            self.post("v1/deactivate", request).await
        }

        async fn fetch_crl(&self) -> Result<Option<Vec<u8>>, TransportError> {
            let response = self
                .client
                .get(self.url("v1/crl")?)
                .send()
                .await
                .map_err(|_| TransportError::Unavailable)?;
            if response.status() == StatusCode::NO_CONTENT {
                return Ok(None);
            }
            let response = accept(response).await?;
            bounded_body(response, MAX_CRL_BYTES).await.map(Some)
        }
    }

    async fn accept(response: Response) -> Result<Response, TransportError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let body = Zeroizing::new(bounded_body(response, MAX_JSON_BYTES).await?);
        if let Ok(server_error) = serde_json::from_slice::<ApiError>(&body) {
            return Err(TransportError::Rejected(server_error.code));
        }
        Err(match status {
            StatusCode::TOO_MANY_REQUESTS => TransportError::Rejected(ErrorCode::RateLimited),
            status if status.is_server_error() => TransportError::Unavailable,
            _ => TransportError::Protocol,
        })
    }

    async fn bounded_body(mut response: Response, limit: usize) -> Result<Vec<u8>, TransportError> {
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(TransportError::TooLarge);
        }
        let mut output = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| TransportError::Unavailable)?
        {
            if chunk.len() > limit.saturating_sub(output.len()) {
                return Err(TransportError::TooLarge);
            }
            output.extend_from_slice(&chunk);
        }
        Ok(output)
    }
}

#[cfg(all(test, feature = "reqwest"))]
mod tests {
    use super::{ReqwestTransport, TransportError};

    #[test]
    fn requires_https_or_an_explicit_numeric_loopback_endpoint() {
        assert!(ReqwestTransport::new("https://example.com/activation").is_ok());
        assert!(matches!(
            ReqwestTransport::new("http://example.com"),
            Err(TransportError::InvalidEndpoint),
        ));
        assert!(ReqwestTransport::loopback("http://[::1]:8080").is_ok());
        assert!(matches!(
            ReqwestTransport::loopback("http://localhost:8080"),
            Err(TransportError::InvalidEndpoint),
        ));
        assert!(matches!(
            ReqwestTransport::new("https://user:password@example.com"),
            Err(TransportError::InvalidEndpoint),
        ));
    }
}
