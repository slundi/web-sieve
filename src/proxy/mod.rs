//! Core MITM proxy server: accept loop, CONNECT handling, and HTTP forwarding.

pub mod ca;
pub mod fingerprint;
pub mod headers;
pub mod routing;
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
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
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
use crate::templates::TemplateEngine;

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

/// Response returned when a CONNECT request appears inside a MITM'd browser↔proxy
/// stream (nested MITM, extended-CONNECT for WebSockets-over-h2, MASQUE, …).
///
/// Kept as a pure function so the 501 branch of [`handle_mitm_request`] can be
/// asserted in isolation without spinning up the full proxy stack.
fn nested_connect_response() -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::NOT_IMPLEMENTED)
        .body(full_body("CONNECT inside MITM'd stream is not supported"))
        .expect("valid response")
}

/// Rewrite the `Host` request header to the effective upstream host.
///
/// Called after a subdomain activation trigger redirects the upstream target:
/// the browser sent `Host: <mode>.<proto>.<real_host>` but the request is
/// actually being forwarded to `<real_host>`, so origin servers need the
/// rewritten value to route correctly.
fn rewrite_host_header(headers: &mut hyper::HeaderMap, upstream_host: &str) {
    if let Ok(value) = hyper::header::HeaderValue::from_str(upstream_host) {
        headers.insert(hyper::header::HOST, value);
    }
}

/// Collect a header map into `(lowercased-name, value)` pairs, skipping any value
/// that is not valid UTF-8. Exposed to Starlark rules via `request_headers()` /
/// `response_headers()`.
fn header_pairs(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_owned()))
        })
        .collect()
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
    templates: Arc<TemplateEngine>,
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
        let templates = Arc::clone(&templates);

        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(stream, ca, profiles, engine, blocker, scanner, templates).await
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
    templates: Arc<TemplateEngine>,
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
                let templates = Arc::clone(&templates);
                async move {
                    proxy_request(req, ca, profiles, engine, blocker, scanner, templates).await
                }
            }),
        )
        .with_upgrades()
        .await
        .map_err(ProxyError::Http)
}

/// Route a request to either [`handle_connect`] or [`forward_http`].
#[allow(clippy::too_many_arguments)]
async fn proxy_request(
    req: Request<Incoming>,
    ca: Arc<CertificateAuthority>,
    profiles: Arc<FingerprintProfiles>,
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
    templates: Arc<TemplateEngine>,
) -> Result<Response<BoxBody>, ProxyError> {
    if req.method() == Method::CONNECT {
        handle_connect(req, ca, profiles, engine, blocker, scanner, templates).await
    } else {
        forward_http(req, engine, blocker, scanner, templates).await
    }
}

/// Routing target for a MITM'd connection.
///
/// A subdomain activation trigger (`<mode>.https.<host>`) rewrites the
/// effective upstream target while the browser continues to see the original
/// authority on the leaf certificate.
struct RoutingTarget {
    /// Authority the browser CONNECTed to; used for the leaf certificate.
    client_authority: String,
    /// Effective upstream host (may differ from `client_authority` when a
    /// subdomain trigger applied).
    upstream_host: String,
    /// Effective upstream port.
    upstream_port: u16,
    /// Subdomain-derived activation mode, if any.
    subdomain_mode: Option<String>,
}

/// Handle a CONNECT tunnel request by performing MITM TLS interception.
///
/// Returns `200 Connection Established` immediately, then upgrades the
/// connection and performs the TLS handshake in a background task.
#[allow(clippy::too_many_arguments)]
async fn handle_connect(
    req: Request<Incoming>,
    ca: Arc<CertificateAuthority>,
    profiles: Arc<FingerprintProfiles>,
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
    templates: Arc<TemplateEngine>,
) -> Result<Response<BoxBody>, ProxyError> {
    let authority = req
        .uri()
        .authority()
        .ok_or_else(|| ProxyError::InvalidAuthority("missing authority".to_string()))?
        .clone();

    let client_authority = authority.host().to_string();
    let connect_port = authority.port_u16().unwrap_or(443);

    // A CONNECT tunnel to `<mode>.<proto>.<real_host>` rewrites the effective
    // upstream target so the browser sees the trigger subdomain (with its own
    // leaf cert) while the proxy actually speaks to the real host. `http`
    // triggers over a CONNECT tunnel are not supported and fall back to the
    // literal CONNECT authority.
    let trigger = routing::parse_host_trigger(&client_authority);
    let target = match trigger {
        Some(t) if t.upstream_https => RoutingTarget {
            client_authority: client_authority.clone(),
            upstream_host: t.target_host,
            upstream_port: t.target_port,
            subdomain_mode: Some(t.mode),
        },
        Some(t) => {
            tracing::warn!(
                client_authority = %client_authority,
                mode = %t.mode,
                "subdomain trigger with 'http' proto ignored inside CONNECT tunnel"
            );
            RoutingTarget {
                client_authority: client_authority.clone(),
                upstream_host: client_authority.clone(),
                upstream_port: connect_port,
                subdomain_mode: None,
            }
        }
        None => RoutingTarget {
            client_authority: client_authority.clone(),
            upstream_host: client_authority.clone(),
            upstream_port: connect_port,
            subdomain_mode: None,
        },
    };

    // Select the browser TLS fingerprint profile from the User-Agent header.
    let ua = req
        .headers()
        .get(hyper::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let browser = fingerprint::Browser::from_user_agent(&ua);
    if tracing::enabled!(tracing::Level::DEBUG) {
        let (ja3_string, ja3_hash) = fingerprint::ja3_for_browser(browser);
        tracing::debug!(
            client_authority = %target.client_authority,
            upstream_host = %target.upstream_host,
            subdomain_mode = ?target.subdomain_mode,
            ?browser,
            ja3 = %ja3_hash,
            ja3_raw = %ja3_string,
            "CONNECT: selected fingerprint profile"
        );
    }
    let profile_config = profiles.config_for(browser);

    let upgrade = hyper::upgrade::on(req);

    tokio::spawn(async move {
        match upgrade.await {
            Ok(upgraded) => {
                if let Err(err) = do_mitm(
                    upgraded,
                    target,
                    ca,
                    profile_config,
                    engine,
                    blocker,
                    scanner,
                    templates,
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
    target: RoutingTarget,
    ca: Arc<CertificateAuthority>,
    client_config: Arc<ClientConfig>,
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
    templates: Arc<TemplateEngine>,
) -> Result<(), ProxyError> {
    let RoutingTarget {
        client_authority,
        upstream_host,
        upstream_port,
        subdomain_mode,
    } = target;

    // Accept the client's TLS handshake using a per-domain leaf cert that
    // matches the authority the browser CONNECTed to (may be a trigger
    // subdomain like `reader.https.example.com`).
    let server_cfg = ca.server_config(&client_authority)?;
    let acceptor = TlsAcceptor::from(server_cfg);
    let client_tls = acceptor
        .accept(TokioIo::new(upgraded))
        .await
        .map_err(ProxyError::Io)?;

    // Open an upstream TCP + TLS connection to the effective target.
    let tcp = TcpStream::connect((upstream_host.as_str(), upstream_port)).await?;
    let server_name = ServerName::try_from(upstream_host.clone())
        .map_err(|_| ProxyError::InvalidDnsName(upstream_host.clone()))?
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

    // Serve the decrypted client stream. `auto::Builder` picks HTTP/2 or
    // HTTP/1.1 based on the ALPN protocol negotiated during the TLS
    // handshake (see `CertificateAuthority::build_server_config`). Each
    // concurrent HTTP/2 stream is driven as its own tokio task by hyper.
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().preserve_header_case(true);
    builder
        .serve_connection(
            TokioIo::new(client_tls),
            service_fn(move |req: Request<Incoming>| {
                let sender = Arc::clone(&sender);
                let engine = Arc::clone(&engine);
                let blocker = Arc::clone(&blocker);
                let scanner = Arc::clone(&scanner);
                let templates = Arc::clone(&templates);
                let upstream_host = upstream_host.clone();
                let subdomain_mode = subdomain_mode.clone();
                handle_mitm_request(
                    req,
                    sender,
                    engine,
                    blocker,
                    scanner,
                    templates,
                    upstream_host,
                    subdomain_mode,
                )
            }),
        )
        .await
        .map_err(|e| ProxyError::ServerConnection(e.to_string()))
}

/// Shared alias for the upstream HTTP/1.1 sender used from the MITM handler.
///
/// Wrapped in `Arc<Mutex<…>>` because a single HTTP/2 client connection may
/// dispatch several concurrent streams that must all use the same upstream
/// pipe.
type UpstreamSender = Arc<Mutex<hyper::client::conn::http1::SendRequest<BoxBody>>>;

/// Handle a single request received on the MITM'd browser↔proxy connection.
///
/// This function is protocol-agnostic and is invoked identically by hyper's
/// HTTP/1.1 driver and its HTTP/2 driver (dispatched via
/// [`hyper_util::server::conn::auto`]).  Each h2 stream runs this function
/// on its own tokio task, so `lol-html` rewriting runs per-stream in
/// parallel.
#[allow(clippy::too_many_arguments)]
async fn handle_mitm_request(
    req: Request<Incoming>,
    sender: UpstreamSender,
    engine: Arc<ScriptEngine>,
    blocker: Arc<AdBlockEngine>,
    scanner: Arc<TextScanner>,
    templates: Arc<TemplateEngine>,
    upstream_host: String,
    subdomain_mode: Option<String>,
) -> Result<Response<BoxBody>, ProxyError> {
    // Nested MITM (CONNECT-inside-h2, extended CONNECT for WebSockets over
    // h2, MASQUE, …) is not supported — return 501 to keep the surface
    // small.  Ordinary browsers never send CONNECT inside a MITM'd stream.
    if req.method() == Method::CONNECT {
        tracing::warn!(
            authority = ?req.uri().authority().map(|a| a.as_str()),
            "CONNECT inside MITM'd stream is not supported"
        );
        return Ok(nested_connect_response());
    }

    let (mut req_parts, body) = req.into_parts();

    // Extract activation modes from the header before it is stripped by
    // `strip_activation_header` — leaking the header upstream would expose
    // the browser extension.
    let header_modes = routing::parse_header_modes(&req_parts.headers);
    routing::strip_activation_header(&mut req_parts.headers);
    let modes = routing::merge_modes(subdomain_mode.as_deref(), &header_modes);

    headers::strip_hop_by_hop(&mut req_parts.headers);
    headers::strip_accept_encoding(&mut req_parts.headers);
    rewrite_host_header(&mut req_parts.headers, &upstream_host);
    let body_bytes = body.collect().await.map_err(ProxyError::Http)?.to_bytes();

    // Network blocking: check before forwarding to upstream. The URL uses
    // the effective upstream host so Starlark rules and ad-block lists see
    // the real target.
    let req_url = format!("https://{upstream_host}{}", req_parts.uri);
    if blocker.is_blocked(&req_url, &upstream_host).await {
        tracing::debug!(url = %req_url, "request blocked by ad filter");
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(empty_body())
            .expect("valid response"));
    }

    let upstream_req = Request::from_parts(req_parts.clone(), full_body(body_bytes));

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
    let raw_pass_through = routing::is_raw(&modes);
    let trigger_ops = routing::modes_to_ops(&modes);

    // Scan text payloads in async context and collect matches for scripting.
    // Skipped in raw pass-through mode.
    let scan_matches = if is_text && !raw_pass_through {
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

    // Run scripting + cosmetic rules for all text responses; check for
    // BlockPage before applying HTML rewriting. Raw pass-through skips this
    // pipeline entirely.
    let maybe_bytes: Option<bytes::Bytes> = if is_text && !raw_pass_through {
        let content_length = resp_bytes.len();
        let ctx = RequestCtx {
            url: req_url.clone(),
            host: upstream_host.clone(),
            content_type: content_type.clone(),
            status_code: resp_parts.status.as_u16(),
            request_headers: header_pairs(&req_parts.headers),
            response_headers: header_pairs(&resp_parts.headers),
            scan_matches,
            content_length,
            body: resp_bytes.clone(),
        };
        let cosmetic_css = if is_html {
            blocker.cosmetic_css_for(&upstream_host).await
        } else {
            None
        };
        let engine = Arc::clone(&engine);
        let raw: bytes::Bytes = resp_bytes;
        let (maybe_bytes, webhook_targets) = tokio::task::spawn_blocking(move || {
            let mut ops: Vec<crate::rewriter::RewriteOp> = Vec::new();
            if let Some(css) = cosmetic_css {
                ops.push(crate::rewriter::RewriteOp::InjectStyle(css));
            }
            ops.extend(engine.run_rules(&ctx));
            ops.extend(trigger_ops);
            if ops
                .iter()
                .any(|o| matches!(o, crate::rewriter::RewriteOp::BlockPage))
            {
                return (None, Vec::new());
            }
            let webhooks: Vec<(String, String)> = ops
                .iter()
                .filter_map(|op| {
                    if let crate::rewriter::RewriteOp::Webhook { url, body } = op {
                        Some((url.clone(), body.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            if !is_html || ops.is_empty() {
                (Some(raw), webhooks)
            } else {
                (
                    Some(
                        crate::rewriter::apply_with_templates(&ops, &raw, Some(&templates))
                            .map(bytes::Bytes::from)
                            .unwrap_or(raw),
                    ),
                    webhooks,
                )
            }
        })
        .await
        .map_err(|e| ProxyError::Scripting(e.to_string()))?;
        for (url, body) in webhook_targets {
            tokio::spawn(crate::rewriter::fire_webhook(url, body));
        }
        maybe_bytes
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

    resp_parts.headers.insert(
        hyper::header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from(final_bytes.len()),
    );
    Ok(Response::from_parts(resp_parts, full_body(final_bytes)))
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
    templates: Arc<TemplateEngine>,
) -> Result<Response<BoxBody>, ProxyError> {
    let uri = req.uri().clone();
    let request_host = uri
        .host()
        .ok_or_else(|| ProxyError::InvalidAuthority("missing host in HTTP request".to_string()))?
        .to_string();
    let request_port = uri.port_u16().unwrap_or(80);

    // Detect subdomain activation triggers on the request URI. Unlike CONNECT,
    // plain HTTP handles both `http` and `https` upstream by TCP connection
    // choice — but this proxy code path is only reached for unencrypted
    // browser-to-proxy traffic, so the trigger's `<proto>` label controls the
    // upstream port only.
    let host_trigger = routing::parse_host_trigger(&request_host);
    let (upstream_host, upstream_port, subdomain_mode) = match &host_trigger {
        Some(t) => (t.target_host.clone(), t.target_port, Some(t.mode.clone())),
        None => (request_host.clone(), request_port, None),
    };

    // Network blocking: check before connecting to upstream. Use the effective
    // upstream host so lists and rules see the real target.
    let effective_url = if host_trigger.is_some() {
        let path_and_query = uri
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_default();
        format!("http://{upstream_host}{path_and_query}")
    } else {
        uri.to_string()
    };
    if blocker.is_blocked(&effective_url, &upstream_host).await {
        tracing::debug!(host = %upstream_host, "request blocked by ad filter");
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(empty_body())
            .expect("valid response"));
    }

    let (mut parts, body) = req.into_parts();

    // Extract activation modes before the header is stripped.
    let header_modes = routing::parse_header_modes(&parts.headers);
    routing::strip_activation_header(&mut parts.headers);
    let modes = routing::merge_modes(subdomain_mode.as_deref(), &header_modes);
    let raw_pass_through = routing::is_raw(&modes);
    let trigger_ops = routing::modes_to_ops(&modes);

    // Strip all hop-by-hop headers (including proxy-connection).
    headers::strip_hop_by_hop(&mut parts.headers);
    headers::strip_accept_encoding(&mut parts.headers);
    rewrite_host_header(&mut parts.headers, &upstream_host);

    // Capture forwarded request headers before `parts` is moved into the upstream request.
    let request_headers = header_pairs(&parts.headers);

    let body_bytes = body.collect().await.map_err(ProxyError::Http)?.to_bytes();

    let tcp = TcpStream::connect((upstream_host.as_str(), upstream_port)).await?;
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
    // Skipped in raw pass-through mode.
    let scan_matches = if is_text && !raw_pass_through {
        let m = scanner.scan(&resp_bytes).await;
        if !m.is_empty() {
            tracing::warn!(
                url = %effective_url,
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
    // Raw pass-through skips this pipeline entirely.
    let maybe_bytes: Option<bytes::Bytes> = if is_text && !raw_pass_through {
        let content_length = resp_bytes.len();
        let ctx = RequestCtx {
            url: effective_url.clone(),
            host: upstream_host.clone(),
            content_type: content_type.clone(),
            status_code: resp_parts.status.as_u16(),
            request_headers,
            response_headers: header_pairs(&resp_parts.headers),
            scan_matches,
            content_length,
            body: resp_bytes.clone(),
        };
        let cosmetic_css = if is_html {
            blocker.cosmetic_css_for(&upstream_host).await
        } else {
            None
        };
        let raw = resp_bytes;
        let (maybe_bytes, webhook_targets) = tokio::task::spawn_blocking(move || {
            let mut ops: Vec<crate::rewriter::RewriteOp> = Vec::new();
            if let Some(css) = cosmetic_css {
                ops.push(crate::rewriter::RewriteOp::InjectStyle(css));
            }
            ops.extend(engine.run_rules(&ctx));
            ops.extend(trigger_ops);
            if ops
                .iter()
                .any(|o| matches!(o, crate::rewriter::RewriteOp::BlockPage))
            {
                return (None, Vec::new());
            }
            // Plain HTTP = unverified domain; check for phishing indicators.
            if is_html && crate::phishing::check(&raw) {
                tracing::warn!(url = %ctx.url, "phishing indicators detected, blocking");
                return (None, Vec::new());
            }
            let webhooks: Vec<(String, String)> = ops
                .iter()
                .filter_map(|op| {
                    if let crate::rewriter::RewriteOp::Webhook { url, body } = op {
                        Some((url.clone(), body.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            if !is_html || ops.is_empty() {
                (Some(raw), webhooks)
            } else {
                (
                    Some(
                        crate::rewriter::apply_with_templates(&ops, &raw, Some(&templates))
                            .map(bytes::Bytes::from)
                            .unwrap_or(raw),
                    ),
                    webhooks,
                )
            }
        })
        .await
        .map_err(|e| ProxyError::Scripting(e.to_string()))?;
        for (url, body) in webhook_targets {
            tokio::spawn(crate::rewriter::fire_webhook(url, body));
        }
        maybe_bytes
    } else {
        Some(resp_bytes)
    };

    let final_bytes = match maybe_bytes {
        None => {
            tracing::info!(url = %effective_url, "page blocked by content filter");
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(full_body("Blocked by content filter"))
                .expect("valid response"));
        }
        Some(b) => b,
    };

    resp_parts.headers.insert(
        hyper::header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from(final_bytes.len()),
    );
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

    #[tokio::test]
    async fn test_nested_connect_response_is_501_with_body() {
        let resp = nested_connect_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        assert_eq!(
            body,
            Bytes::from_static(b"CONNECT inside MITM'd stream is not supported"),
            "501 body must state the reason for the browser extension / user"
        );
    }

    #[test]
    fn content_length_insert_overwrites_stale_upstream_value() {
        use hyper::header::{CONTENT_LENGTH, HeaderValue};

        let upstream_len: usize = 100;
        let rewritten = Bytes::from(vec![b'x'; 137]);

        let mut headers = hyper::HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from(upstream_len));

        // Simulate what the proxy now does after rewriting.
        headers.insert(CONTENT_LENGTH, HeaderValue::from(rewritten.len()));

        let reported: usize = headers[CONTENT_LENGTH].to_str().unwrap().parse().unwrap();
        assert_eq!(
            reported,
            rewritten.len(),
            "Content-Length must reflect rewritten body"
        );
        assert_ne!(
            reported, upstream_len,
            "stale upstream value must be replaced"
        );
    }
}
