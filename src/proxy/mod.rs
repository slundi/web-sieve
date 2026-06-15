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
use crate::filter::AdBlockEngine;
use crate::proxy::ca::CertificateAuthority;
use crate::proxy::fingerprint::FingerprintProfiles;
use crate::scanner::TextScanner;
use crate::scripting::{RequestCtx, ScriptEngine};

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
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
) -> Result<(), ProxyError> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("proxy listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::debug!("accepted connection from {peer}");

        let ca = Arc::clone(&ca);
        let profiles = Arc::clone(&profiles);
        let engine = Arc::clone(&engine);
        let blocker = Arc::clone(&blocker);
        let scanner = Arc::clone(&scanner);

        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(stream, ca, profiles, engine, blocker, scanner).await
            {
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
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
) -> Result<(), ProxyError> {
    let io = TokioIo::new(stream);
    server_http1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(
            io,
            service_fn(move |req| {
                let ca = Arc::clone(&ca);
                let profiles = Arc::clone(&profiles);
                let engine = Arc::clone(&engine);
                let blocker = Arc::clone(&blocker);
                let scanner = Arc::clone(&scanner);
                async move { proxy_request(req, ca, profiles, engine, blocker, scanner).await }
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
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
) -> Result<Response<BoxBody>, ProxyError> {
    if req.method() == Method::CONNECT {
        handle_connect(req, ca, profiles, engine, blocker, scanner).await
    } else {
        forward_http(req, engine, blocker, scanner).await
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
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
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
                if let Err(err) = do_mitm(
                    upgraded,
                    host,
                    port,
                    ca,
                    profile_config,
                    engine,
                    blocker,
                    scanner,
                )
                .await
                {
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
/// and forwards each HTTP request.  Network-blocked requests are answered with
/// `204 No Content` without touching the upstream.
#[allow(clippy::too_many_arguments)]
async fn do_mitm(
    upgraded: hyper::upgrade::Upgraded,
    host: String,
    port: u16,
    ca: Arc<CertificateAuthority>,
    client_config: Arc<ClientConfig>,
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
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
                let engine = Arc::clone(&engine);
                let blocker = Arc::clone(&blocker);
                let scanner = Arc::clone(&scanner);
                let host = host.clone();
                async move {
                    let (mut req_parts, body) = req.into_parts();
                    headers::strip_hop_by_hop(&mut req_parts.headers);
                    let body_bytes = body.collect().await.map_err(ProxyError::Http)?.to_bytes();

                    // Network blocking: check before forwarding to upstream.
                    let req_url = format!("https://{host}{}", req_parts.uri);
                    if blocker.is_blocked(&req_url, &host).await {
                        tracing::debug!(url = %req_url, "request blocked by ad filter");
                        return Ok(Response::builder()
                            .status(StatusCode::NO_CONTENT)
                            .body(empty_body())
                            .expect("valid response"));
                    }

                    let upstream_req =
                        Request::from_parts(req_parts.clone(), full_body(body_bytes));

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

                    let content_type = resp_parts
                        .headers
                        .get(hyper::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let is_html = content_type.contains("text/html");
                    let is_text = is_html || content_type.contains("text/plain");

                    // Scan text payloads in async context and collect matches for scripting.
                    let scan_matches = if is_text {
                        let m = scanner.scan(&resp_bytes).await;
                        if !m.is_empty() {
                            tracing::warn!(
                                url = %req_url,
                                categories = ?m.iter()
                                    .map(|s| format!("{}:{}", s.category, s.count))
                                    .collect::<Vec<_>>(),
                                "content scan flagged"
                            );
                        }
                        m
                    } else {
                        Vec::new()
                    };

                    // Run scripting + cosmetic rules for all text responses;
                    // check for BlockPage before applying HTML rewriting.
                    let maybe_bytes: Option<bytes::Bytes> = if is_text {
                        let content_length = resp_bytes.len();
                        let ctx = RequestCtx {
                            url: req_url.clone(),
                            host: host.clone(),
                            content_type: content_type.clone(),
                            scan_matches,
                            content_length,
                        };
                        let cosmetic_css = if is_html {
                            blocker.cosmetic_css_for(&host).await
                        } else {
                            None
                        };
                        let engine = Arc::clone(&engine);
                        let raw: bytes::Bytes = resp_bytes;
                        tokio::task::spawn_blocking(move || {
                            let mut ops: Vec<crate::rewriter::RewriteOp> = Vec::new();
                            if let Some(css) = cosmetic_css {
                                ops.push(crate::rewriter::RewriteOp::InjectStyle(css));
                            }
                            ops.extend(engine.run_rules(&ctx));
                            if ops
                                .iter()
                                .any(|o| matches!(o, crate::rewriter::RewriteOp::BlockPage))
                            {
                                return None;
                            }
                            if !is_html || ops.is_empty() {
                                Some(raw)
                            } else {
                                Some(
                                    crate::rewriter::apply(&ops, &raw)
                                        .map(bytes::Bytes::from)
                                        .unwrap_or(raw),
                                )
                            }
                        })
                        .await
                        .map_err(|e| ProxyError::Scripting(e.to_string()))?
                    } else {
                        Some(resp_bytes)
                    };

                    let final_bytes = match maybe_bytes {
                        None => {
                            tracing::info!(url = %req_url, "page blocked by content filter");
                            return Ok(Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(full_body("Blocked by content filter"))
                                .expect("valid response"));
                        }
                        Some(b) => b,
                    };

                    resp_parts.headers.remove(hyper::header::CONTENT_LENGTH);
                    Ok::<_, ProxyError>(Response::from_parts(resp_parts, full_body(final_bytes)))
                }
            }),
        )
        .await
        .map_err(ProxyError::Http)
}

/// Forward a plain HTTP request to its destination.
///
/// Strips hop-by-hop headers before forwarding and from the upstream response.
/// Network-blocked requests are answered with `204 No Content` without touching
/// the upstream.  HTML responses are passed through the ad-block cosmetic injector
/// and the scripting engine before being returned.
async fn forward_http(
    req: Request<Incoming>,
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
) -> Result<Response<BoxBody>, ProxyError> {
    let uri = req.uri().clone();
    let host = uri
        .host()
        .ok_or_else(|| ProxyError::InvalidAuthority("missing host in HTTP request".to_string()))?
        .to_string();
    let port = uri.port_u16().unwrap_or(80);

    // Network blocking: check before connecting to upstream.
    if blocker.is_blocked(&uri.to_string(), &host).await {
        tracing::debug!(host = %host, "request blocked by ad filter");
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(empty_body())
            .expect("valid response"));
    }

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

    let content_type = resp_parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let is_html = content_type.contains("text/html");
    let is_text = is_html || content_type.contains("text/plain");

    // Scan text payloads in async context and collect matches for scripting.
    let scan_matches = if is_text {
        let m = scanner.scan(&resp_bytes).await;
        if !m.is_empty() {
            tracing::warn!(
                url = %uri,
                categories = ?m.iter()
                    .map(|s| format!("{}:{}", s.category, s.count))
                    .collect::<Vec<_>>(),
                "content scan flagged"
            );
        }
        m
    } else {
        Vec::new()
    };

    // Run scripting + cosmetic rules for all text responses;
    // check for BlockPage before applying HTML rewriting.
    let maybe_bytes: Option<bytes::Bytes> = if is_text {
        let content_length = resp_bytes.len();
        let ctx = RequestCtx {
            url: uri.to_string(),
            host: host.clone(),
            content_type: content_type.clone(),
            scan_matches,
            content_length,
        };
        let cosmetic_css = if is_html {
            blocker.cosmetic_css_for(&host).await
        } else {
            None
        };
        let raw = resp_bytes;
        tokio::task::spawn_blocking(move || {
            let mut ops: Vec<crate::rewriter::RewriteOp> = Vec::new();
            if let Some(css) = cosmetic_css {
                ops.push(crate::rewriter::RewriteOp::InjectStyle(css));
            }
            ops.extend(engine.run_rules(&ctx));
            if ops
                .iter()
                .any(|o| matches!(o, crate::rewriter::RewriteOp::BlockPage))
            {
                return None;
            }
            // Plain HTTP = unverified domain; check for phishing indicators.
            if is_html && crate::phishing::check(&raw) {
                tracing::warn!(url = %ctx.url, "phishing indicators detected, blocking");
                return None;
            }
            if !is_html || ops.is_empty() {
                Some(raw)
            } else {
                Some(
                    crate::rewriter::apply(&ops, &raw)
                        .map(bytes::Bytes::from)
                        .unwrap_or(raw),
                )
            }
        })
        .await
        .map_err(|e| ProxyError::Scripting(e.to_string()))?
    } else {
        Some(resp_bytes)
    };

    let final_bytes = match maybe_bytes {
        None => {
            tracing::info!(url = %uri, "page blocked by content filter");
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(full_body("Blocked by content filter"))
                .expect("valid response"));
        }
        Some(b) => b,
    };

    resp_parts.headers.remove(hyper::header::CONTENT_LENGTH);
    Ok(Response::from_parts(resp_parts, full_body(final_bytes)))
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
