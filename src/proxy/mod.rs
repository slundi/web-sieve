//! Core MITM proxy server: accept loop, CONNECT handling, and HTTP forwarding.

pub mod ca;
pub mod fingerprint;
pub mod headers;
pub mod tls;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::Mutex;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::error::ProxyError;
use crate::proxy::ca::CertificateAuthority;
use crate::proxy::fingerprint::FingerprintProfiles;

/// Shorthand body type used throughout the proxy.
type BoxBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Convert an [`Empty`] body to [`BoxBody`].
fn empty_body() -> BoxBody {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

/// Convert a byte slice to a [`BoxBody`].
fn full_body(data: impl Into<Bytes>) -> BoxBody {
    Full::new(data.into()).map_err(|e| match e {}).boxed()
}

/// Start the proxy listener and serve connections forever.
///
/// Binds to `addr`, accepts TCP connections, and dispatches each to
/// [`handle_connection`] on a new Tokio task.
///
/// # Errors
///
/// Returns a [`ProxyError`] if binding to `addr` fails.
pub async fn run(
    addr: SocketAddr,
    ca: Arc<CertificateAuthority>,
    profiles: Arc<FingerprintProfiles>,
) -> Result<(), ProxyError> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("proxy listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::debug!("accepted connection from {peer}");

        let ca = Arc::clone(&ca);
        let profiles = Arc::clone(&profiles);

        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, ca, profiles).await {
                tracing::warn!("connection error from {peer}: {err}");
            }
        });
    }
}

/// Serve a single client TCP connection via HTTP/1.1.
async fn handle_connection(
    stream: TcpStream,
    ca: Arc<CertificateAuthority>,
    profiles: Arc<FingerprintProfiles>,
) -> Result<(), ProxyError> {
    let io = TokioIo::new(stream);
    server_http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(
            io,
            service_fn(move |req| {
                let ca = Arc::clone(&ca);
                let profiles = Arc::clone(&profiles);
                async move { proxy_request(req, ca, profiles).await }
            }),
        )
        .with_upgrades()
        .await
        .map_err(ProxyError::Http)
}

/// Route a request to either [`handle_connect`] or [`forward_http`].
async fn proxy_request(
    req: Request<Incoming>,
    ca: Arc<CertificateAuthority>,
    profiles: Arc<FingerprintProfiles>,
) -> Result<Response<BoxBody>, ProxyError> {
    if req.method() == Method::CONNECT {
        handle_connect(req, ca, profiles).await
    } else {
        forward_http(req).await
    }
}

/// Handle a CONNECT tunnel request by performing MITM TLS interception.
///
/// Returns `200 Connection Established` immediately, then upgrades the
/// connection and performs the TLS handshake in a background task.
async fn handle_connect(
    req: Request<Incoming>,
    ca: Arc<CertificateAuthority>,
    profiles: Arc<FingerprintProfiles>,
) -> Result<Response<BoxBody>, ProxyError> {
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| ProxyError::InvalidAuthority("missing authority".to_string()))?
        .clone();

    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);

    // Select the browser TLS fingerprint profile from the User-Agent header.
    let ua = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let browser = fingerprint::Browser::from_user_agent(&ua);
    let (ja3_string, ja3_hash) = fingerprint::ja3_for_browser(browser);
    tracing::debug!(%host, ?browser, ja3 = %ja3_hash, ja3_raw = %ja3_string, "CONNECT: selected fingerprint profile");
    let profile_config = profiles.config_for(browser);

    let upgrade = hyper::upgrade::on(req);

    tokio::spawn(async move {
        match upgrade.await {
            Ok(upgraded) => {
                if let Err(err) = do_mitm(upgraded, host, port, ca, profile_config).await {
                    tracing::warn!("MITM error: {err}");
                }
            }
            Err(err) => tracing::warn!("upgrade error: {err}"),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .expect("valid response"))
}

/// Perform MITM interception on an upgraded connection.
///
/// Accepts the client TLS handshake using a domain-specific leaf certificate,
/// then connects to the upstream server using the browser-matched TLS profile
/// and forwards each HTTP request.
async fn do_mitm(
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    port: u16,
    ca: Arc<CertificateAuthority>,
    client_config: Arc<ClientConfig>,
) -> Result<(), ProxyError> {
    // Accept the client's TLS handshake using a per-domain leaf cert.
    let server_cfg = ca.server_config(&host)?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let client_tls = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .map_err(ProxyError::Io)?;

    // Open an upstream TCP + TLS connection.
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| ProxyError::InvalidDnsName(host.clone()))?
        .to_owned();
    let connector = TlsConnector::from(client_config);
    let upstream_tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(ProxyError::Io)?;

    // Perform HTTP/1.1 handshake with upstream.
    let (sender, conn) = client_http1::handshake(TokioIo::new(upstream_tls))
        .await
        .map_err(ProxyError::Http)?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!("upstream connection error: {err}");
        }
    });

    // Wrap sender in Arc<Mutex<>> so it can be shared across service_fn calls.
    let sender = Arc::new(Mutex::new(sender));

    // Serve the decrypted client stream, forwarding each request upstream.
    server_http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(
            TokioIo::new(client_tls),
            service_fn(move |req: Request<Incoming>| {
                let sender = Arc::clone(&sender);
                async move {
                    let (mut parts, body) = req.into_parts();
                    headers::strip_hop_by_hop(&mut parts.headers);
                    let body_bytes = body.collect().await.map_err(ProxyError::Http)?.to_bytes();

                    let upstream_req = Request::from_parts(parts, full_body(body_bytes));

                    let resp = {
                        let mut s = sender.lock().await;
                        s.send_request(upstream_req)
                            .await
                            .map_err(ProxyError::Http)?
                    };

                    let (mut resp_parts, resp_body) = resp.into_parts();
                    headers::strip_hop_by_hop(&mut resp_parts.headers);
                    let resp_bytes = resp_body
                        .collect()
                        .await
                        .map_err(ProxyError::Http)?
                        .to_bytes();

                    Ok::<_, ProxyError>(Response::from_parts(resp_parts, full_body(resp_bytes)))
                }
            }),
        )
        .await
        .map_err(ProxyError::Http)
}

/// Forward a plain HTTP request to its destination.
///
/// Strips hop-by-hop headers before forwarding and from the upstream response.
async fn forward_http(req: Request<Incoming>) -> Result<Response<BoxBody>, ProxyError> {
    let uri = req.uri().clone();
    let host = uri
        .host()
        .ok_or_else(|| ProxyError::InvalidAuthority("missing host in HTTP request".to_string()))?
        .to_string();
    let port = uri.port_u16().unwrap_or(80);

    let (mut parts, body) = req.into_parts();

    // Strip all hop-by-hop headers (including proxy-connection).
    headers::strip_hop_by_hop(&mut parts.headers);

    let body_bytes = body.collect().await.map_err(ProxyError::Http)?.to_bytes();

    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let (mut sender, conn) = client_http1::handshake(TokioIo::new(tcp))
        .await
        .map_err(ProxyError::Http)?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            tracing::warn!("HTTP upstream connection error: {err}");
        }
    });

    let upstream_req = Request::from_parts(parts, full_body(body_bytes));
    let resp = sender
        .send_request(upstream_req)
        .await
        .map_err(ProxyError::Http)?;

    let (mut resp_parts, resp_body) = resp.into_parts();
    headers::strip_hop_by_hop(&mut resp_parts.headers);
    let resp_bytes = resp_body
        .collect()
        .await
        .map_err(ProxyError::Http)?
        .to_bytes();

    Ok(Response::from_parts(resp_parts, full_body(resp_bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_body_is_boxed() {
        let _body: BoxBody = empty_body();
    }

    #[test]
    fn test_full_body_with_bytes() {
        let _body: BoxBody = full_body(Bytes::from_static(b"hello"));
    }

    #[test]
    fn test_connect_missing_authority_returns_none() {
        // Verify that a URI without an authority has no authority component.
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("/no-authority")
            .body(())
            .expect("request");
        assert!(req.uri().authority().is_none());
    }
}
