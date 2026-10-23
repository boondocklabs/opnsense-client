//! An asynchronous OPNsense API client running on Tokio.
//!
//! Endpoints are separate path segments: `["core", "firmware", "info"]` maps to
//! `/api/core/firmware/info`. Responses can be your own Serde types or
//! [`serde_json::Value`]. HTTP success does not imply an OPNsense operation
//! succeeded; callers must inspect endpoint-specific result/validation fields.
//!
//! ```no_run
//! use opnsense_client::Client;
//! use serde_json::Value;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = Client::new("https://opnsense.local", "api-key", "api-secret")?;
//! let info = client.firmware_info().await?;
//! let aliases: Value = client.get(&["firewall", "alias", "get"]).await?;
//! # Ok(())
//! # }
//! ```

use std::{fmt, time::Duration};

use reqwest::{Method, Url, header::ACCEPT, redirect::Policy};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

pub mod insight;
mod stream;

pub use reqwest::{Certificate, StatusCode};
pub use stream::{Event, EventStream};

/// Errors constructing a client, sending a request, or decoding its response.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid client configuration: {0}")]
    Configuration(&'static str),
    #[error(
        "endpoint must contain module, controller, and command; segments cannot be empty, '.' or '..'"
    )]
    InvalidEndpoint,
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("request exceeded its timeout")]
    Timeout,
    /// The body is retained for diagnostics, but omitted from Display.
    #[error("OPNsense returned HTTP {status}")]
    Http { status: StatusCode, body: String },
    #[error("response exceeded the configured body limit")]
    ResponseTooLarge,
    #[error("expected a text/event-stream response")]
    InvalidStreamContentType,
    #[error("invalid JSON response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("response is not valid UTF-8: {0}")]
    InvalidText(#[from] std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Cloneable client with a shared connection pool. No runtime is created.
#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    base_url: Url,
    key: String,
    secret: String,
    timeout: Duration,
    max_response_bytes: usize,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url)
            .field("credentials", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl Client {
    /// Access typed historical NetFlow reports and CSV exports.
    pub fn insight(&self) -> insight::Insight<'_> {
        insight::Insight::new(self)
    }

    /// Build with verified HTTPS, a 30-second timeout, and an 8 MiB body limit.
    pub fn new(base_url: &str, key: impl Into<String>, secret: impl Into<String>) -> Result<Self> {
        Self::builder(base_url, key, secret).build()
    }

    pub fn builder(
        base_url: impl Into<String>,
        key: impl Into<String>,
        secret: impl Into<String>,
    ) -> ClientBuilder {
        ClientBuilder {
            base_url: base_url.into(),
            key: key.into(),
            secret: secret.into(),
            timeout: Duration::from_secs(30),
            max_response_bytes: 8 * 1024 * 1024,
            allow_http: false,
            roots: Vec::new(),
        }
    }

    /// GET a JSON response. Each endpoint element is encoded as one path segment.
    pub async fn get<T: DeserializeOwned>(&self, endpoint: &[&str]) -> Result<T> {
        self.execute(self.request(Method::GET, endpoint)?).await
    }

    /// Download a bounded binary or text response (for example an Insight CSV).
    pub async fn get_bytes(&self, endpoint: &[&str]) -> Result<Vec<u8>> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(ACCEPT, reqwest::header::HeaderValue::from_static("*/*"));
        self.execute_bytes(self.request(Method::GET, endpoint)?.headers(headers))
            .await
    }

    /// GET with URL-encoded query parameters, including OPNsense search options.
    pub async fn get_with_query<T: DeserializeOwned, Q: Serialize + ?Sized>(
        &self,
        endpoint: &[&str],
        query: &Q,
    ) -> Result<T> {
        self.execute(self.request(Method::GET, endpoint)?.query(query))
            .await
    }

    /// POST a JSON body. Use `&serde_json::json!({})` for an empty object.
    /// Requests are never automatically retried by this client.
    pub async fn post<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        endpoint: &[&str],
        body: &B,
    ) -> Result<T> {
        self.execute(self.request(Method::POST, endpoint)?.json(body))
            .await
    }

    /// GET `/api/core/firmware/info`.
    pub async fn firmware_info(&self) -> Result<Value> {
        self.get(&["core", "firmware", "info"]).await
    }

    /// POST `/api/core/firmware/status`, as specified by the current API reference.
    pub async fn firmware_status(&self) -> Result<Value> {
        self.post(&["core", "firmware", "status"], &serde_json::json!({}))
            .await
    }

    /// Open a Server-Sent Events (SSE) GET endpoint. No automatic reconnects.
    /// The client timeout applies to opening the stream and each wait for an
    /// event, rather than the lifetime of the connection. Drop to disconnect.
    pub async fn stream(&self, endpoint: &[&str]) -> Result<EventStream> {
        self.open_stream(self.request(Method::GET, endpoint)?).await
    }

    /// Open an SSE endpoint with URL-encoded query parameters.
    pub async fn stream_with_query<Q: Serialize + ?Sized>(
        &self,
        endpoint: &[&str],
        query: &Q,
    ) -> Result<EventStream> {
        self.open_stream(self.request(Method::GET, endpoint)?.query(query))
            .await
    }

    /// Live CPU samples from `/api/diagnostics/cpu_usage/stream`.
    pub async fn cpu_usage_stream(&self) -> Result<EventStream> {
        self.stream(&["diagnostics", "cpu_usage", "stream"]).await
    }

    /// Live interface traffic samples. The interval must be positive; set the
    /// client timeout longer than this interval to allow time for each sample.
    pub async fn traffic_stream(&self, poll_interval_seconds: u32) -> Result<EventStream> {
        if poll_interval_seconds == 0 {
            return Err(Error::Configuration(
                "traffic poll interval must be positive",
            ));
        }
        self.stream(&[
            "diagnostics",
            "traffic",
            "stream",
            &poll_interval_seconds.to_string(),
        ])
        .await
    }

    async fn open_stream(&self, request: reqwest::RequestBuilder) -> Result<EventStream> {
        tokio::time::timeout(self.timeout, async {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                ACCEPT,
                reqwest::header::HeaderValue::from_static("text/event-stream"),
            );
            let response = request.headers(headers).send().await?;
            if !response.status().is_success() {
                let status = response.status();
                let body = read_body(response, self.max_response_bytes).await?;
                return Err(Error::Http {
                    status,
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
            }
            let is_sse = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| {
                    value
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .eq_ignore_ascii_case("text/event-stream")
                });
            if !is_sse {
                return Err(Error::InvalidStreamContentType);
            }
            Ok(EventStream::new(
                response,
                self.timeout,
                self.max_response_bytes,
            ))
        })
        .await
        .map_err(|_| Error::Timeout)?
    }

    fn request(&self, method: Method, endpoint: &[&str]) -> Result<reqwest::RequestBuilder> {
        if endpoint.len() < 3 || endpoint.iter().any(|s| matches!(*s, "" | "." | "..")) {
            return Err(Error::InvalidEndpoint);
        }
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| Error::InvalidEndpoint)?
            .pop_if_empty()
            .extend(endpoint);
        Ok(self
            .http
            .request(method, url)
            .basic_auth(&self.key, Some(&self.secret))
            .header(ACCEPT, "application/json"))
    }

    async fn execute<T: DeserializeOwned>(&self, request: reqwest::RequestBuilder) -> Result<T> {
        Ok(serde_json::from_slice(&self.execute_bytes(request).await?)?)
    }

    async fn execute_bytes(&self, request: reqwest::RequestBuilder) -> Result<Vec<u8>> {
        tokio::time::timeout(self.timeout, async {
            let response = request.send().await?;
            let status = response.status();
            let body = read_body(response, self.max_response_bytes).await?;
            if !status.is_success() {
                return Err(Error::Http {
                    status,
                    body: String::from_utf8_lossy(&body).into_owned(),
                });
            }
            Ok(body)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}

/// Client settings. Debug output deliberately omits credentials.
pub struct ClientBuilder {
    base_url: String,
    key: String,
    secret: String,
    timeout: Duration,
    max_response_bytes: usize,
    allow_http: bool,
    roots: Vec<Certificate>,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("credentials", &"[REDACTED]")
            .field("timeout", &self.timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("allow_http", &self.allow_http)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// Total time for a JSON request. For SSE, this limits opening the stream
    /// and each wait for the next event; heartbeats do not reset the event deadline.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Bound JSON/error bodies and individual SSE frames. Default: 8 MiB.
    pub fn max_response_bytes(mut self, bytes: usize) -> Self {
        self.max_response_bytes = bytes;
        self
    }

    /// Trust an additional CA or self-signed certificate, preserving verification.
    pub fn add_root_certificate(mut self, certificate: Certificate) -> Self {
        self.roots.push(certificate);
        self
    }

    /// Permit unencrypted HTTP (credentials will be sent without TLS).
    /// Intended for local tests and explicitly trusted networks.
    pub fn allow_http(mut self, allow: bool) -> Self {
        self.allow_http = allow;
        self
    }

    /// Accept a firewall origin, reverse-proxy prefix, or URL ending in `/api/`.
    /// Embedded credentials, queries, and fragments are rejected. Redirects are
    /// disabled so login pages and alternate hosts cannot silently replace API responses.
    pub fn build(self) -> Result<Client> {
        let mut base_url = Url::parse(&self.base_url)
            .map_err(|_| Error::Configuration("base URL must be an absolute HTTP(S) URL"))?;
        if base_url.host_str().is_none()
            || !(base_url.scheme() == "https" || (self.allow_http && base_url.scheme() == "http"))
        {
            return Err(Error::Configuration(
                "base URL must use HTTPS (or explicitly allow HTTP)",
            ));
        }
        if !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(Error::Configuration(
                "base URL cannot contain credentials, query, or fragment",
            ));
        }
        if self.key.is_empty() || self.key.contains(':') || self.secret.is_empty() {
            return Err(Error::Configuration(
                "key and secret must be nonempty; key cannot contain ':'",
            ));
        }
        if self.timeout.is_zero() || self.max_response_bytes == 0 {
            return Err(Error::Configuration(
                "timeout and response body limit must be positive",
            ));
        }
        let is_api = base_url.path().trim_end_matches('/').ends_with("/api");
        let mut path = base_url
            .path_segments_mut()
            .map_err(|_| Error::Configuration("base URL cannot contain path segments"))?;
        path.pop_if_empty();
        if !is_api {
            path.push("api");
        }
        path.push("");
        drop(path);

        let mut http = reqwest::Client::builder()
            .tls_backend_rustls()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .connect_timeout(self.timeout)
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ));
        // Preserve the previous public-root + extra-root trust model. Using
        // WebPKI also avoids platform-specific certificate policies for private CAs.
        let mut roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|root| Certificate::from_der(root.as_ref()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        roots.extend(self.roots);
        http = http.tls_certs_only(roots);
        Ok(Client {
            http: http.build()?,
            base_url,
            key: self.key,
            secret: self.secret,
            timeout: self.timeout,
            max_response_bytes: self.max_response_bytes,
        })
    }
}

async fn read_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(Error::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
