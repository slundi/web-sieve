//! Integration tests: verify the proxy can forward plain HTTP requests.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use web_sieve::filter::AdBlockEngine;
use web_sieve::proxy::ca::CertificateAuthority;
use web_sieve::proxy::fingerprint::FingerprintProfiles;
use web_sieve::proxy::tls::load_system_root_store;
use web_sieve::scanner::TextScanner;
use web_sieve::scripting::ScriptEngine;
use web_sieve::templates::TemplateEngine;

/// Install the default rustls crypto provider exactly once per test binary.
fn setup_crypto() {
    static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    ONCE.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Generate a self-signed leaf certificate for `localhost`.
fn make_localhost_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key = KeyPair::generate().expect("keypair");
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::DnsName(
        "localhost".try_into().expect("valid DNS name"),
    )];
    let cert = params.self_signed(&key).expect("self-signed");
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (cert_der, key_der)
}

/// Start an HTTPS origin serving `text/plain` "OK" for any request.  Returns
/// the bound address and the DER-encoded leaf certificate so the proxy can
/// trust it.
async fn start_https_origin() -> (SocketAddr, CertificateDer<'static>) {
    setup_crypto();
    let (cert_der, key_der) = make_localhost_cert();
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind origin");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let _ = server_http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(tls),
                        service_fn(|_req: Request<Incoming>| async move {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(hyper::header::CONTENT_TYPE, "text/plain")
                                    .body(
                                        http_body_util::Full::new(Bytes::from_static(b"OK"))
                                            .map_err(|e| match e {})
                                            .boxed(),
                                    )
                                    .expect("response"),
                            )
                        }),
                    )
                    .await;
            });
        }
    });

    (addr, cert_der)
}

/// Start the web-sieve proxy on an ephemeral port with a root store that
/// trusts `extra_root` (typically the origin's self-signed cert). Returns
/// the proxy address and its CA certificate in PEM form.
async fn start_proxy_with_extra_root(extra_root: CertificateDer<'static>) -> (SocketAddr, String) {
    setup_crypto();
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = CertificateAuthority::load_or_create(
        &dir.path().join("ca.crt"),
        &dir.path().join("ca.key"),
        2048,
    )
    .expect("CA");
    let ca_pem = ca.ca_cert_pem().to_owned();

    let rules_dir = dir.path().join("rules");
    let engine = ScriptEngine::new(rules_dir, 0.01)
        .await
        .expect("scripting engine");

    let lists_dir = dir.path().join("lists");
    let blocker = AdBlockEngine::new(lists_dir)
        .await
        .expect("ad-block engine");

    let dicts_dir = dir.path().join("dicts");
    let scanner = TextScanner::new(dicts_dir).await.expect("text scanner");

    let templates = TemplateEngine::new(dir.path().join("templates"))
        .await
        .expect("template engine");

    // Keep tempdir alive for the duration of the test.
    std::mem::forget(dir);

    let mut root_store = RootCertStore::empty();
    root_store.add(extra_root).expect("add root cert");
    let profiles = Arc::new(FingerprintProfiles::new(root_store).expect("fingerprint profiles"));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("local addr");
    drop(listener);

    tokio::spawn(async move {
        web_sieve::proxy::run(
            proxy_addr, ca, profiles, engine, blocker, scanner, templates,
        )
        .await
        .expect("proxy run");
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    (proxy_addr, ca_pem)
}

/// Start a minimal HTTP echo server and return its bound address.
async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind echo server");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = server_http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(|_req: Request<Incoming>| async move {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .body(
                                        http_body_util::Full::new(Bytes::from_static(b"OK"))
                                            .map_err(|e| match e {})
                                            .boxed(),
                                    )
                                    .expect("response"),
                            )
                        }),
                    )
                    .await;
            });
        }
    });

    addr
}

/// Start the web-sieve proxy on an ephemeral port and return its address.
async fn start_proxy() -> SocketAddr {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = CertificateAuthority::load_or_create(
        &dir.path().join("ca.crt"),
        &dir.path().join("ca.key"),
        2048,
    )
    .expect("CA");

    let rules_dir = dir.path().join("rules");
    let engine = ScriptEngine::new(rules_dir, 0.01)
        .await
        .expect("scripting engine");

    let lists_dir = dir.path().join("lists");
    let blocker = AdBlockEngine::new(lists_dir)
        .await
        .expect("ad-block engine");

    let dicts_dir = dir.path().join("dicts");
    let scanner = TextScanner::new(dicts_dir).await.expect("text scanner");

    let templates = TemplateEngine::new(dir.path().join("templates"))
        .await
        .expect("template engine");

    // Keep tempdir alive for the duration of the test by leaking it.
    std::mem::forget(dir);

    let root_store = load_system_root_store();
    let profiles = Arc::new(FingerprintProfiles::new(root_store).expect("fingerprint profiles"));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("local addr");
    drop(listener);

    tokio::spawn(async move {
        web_sieve::proxy::run(
            proxy_addr, ca, profiles, engine, blocker, scanner, templates,
        )
        .await
        .expect("proxy run");
    });

    // Give the proxy a moment to start listening.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    proxy_addr
}

/// Start a minimal HTTP origin that always answers `200 text/html` with `body`.
async fn start_html_origin(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind html origin");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let _ = server_http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |_req: Request<Incoming>| async move {
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(hyper::header::CONTENT_TYPE, "text/html")
                                    .body(
                                        http_body_util::Full::new(Bytes::from_static(
                                            body.as_bytes(),
                                        ))
                                        .map_err(|e| match e {})
                                        .boxed(),
                                    )
                                    .expect("response"),
                            )
                        }),
                    )
                    .await;
            });
        }
    });

    addr
}

/// Start the proxy with the given `.star` rules and Minijinja templates
/// pre-installed, and return its address.
async fn start_proxy_with_rules(rules: &[(&str, &str)], templates: &[(&str, &str)]) -> SocketAddr {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = CertificateAuthority::load_or_create(
        &dir.path().join("ca.crt"),
        &dir.path().join("ca.key"),
        2048,
    )
    .expect("CA");

    let rules_dir = dir.path().join("rules");
    std::fs::create_dir_all(&rules_dir).expect("create rules dir");
    for (name, body) in rules {
        std::fs::write(rules_dir.join(name), body).expect("write rule");
    }
    let engine = ScriptEngine::new(rules_dir, 0.01)
        .await
        .expect("scripting engine");

    let templates_dir = dir.path().join("templates");
    std::fs::create_dir_all(&templates_dir).expect("create templates dir");
    for (name, body) in templates {
        std::fs::write(templates_dir.join(name), body).expect("write template");
    }
    let templates = TemplateEngine::new(templates_dir)
        .await
        .expect("template engine");

    let blocker = AdBlockEngine::new(dir.path().join("lists"))
        .await
        .expect("ad-block engine");
    let scanner = TextScanner::new(dir.path().join("dicts"))
        .await
        .expect("text scanner");

    // Keep tempdir alive for the duration of the test by leaking it.
    std::mem::forget(dir);

    let root_store = load_system_root_store();
    let profiles = Arc::new(FingerprintProfiles::new(root_store).expect("fingerprint profiles"));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("local addr");
    drop(listener);

    tokio::spawn(async move {
        web_sieve::proxy::run(
            proxy_addr, ca, profiles, engine, blocker, scanner, templates,
        )
        .await
        .expect("proxy run");
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    proxy_addr
}

/// Fetch `uri` through the proxy at `proxy_addr` and return the response body.
async fn get_through_proxy(proxy_addr: SocketAddr, uri: &str, host: &str) -> (StatusCode, String) {
    let tcp = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect to proxy");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .expect("handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method(hyper::Method::GET)
        .uri(uri)
        .header(hyper::header::HOST, host)
        .body(Empty::<Bytes>::new())
        .expect("request");

    let resp = sender.send_request(req).await.expect("send request");
    let status = resp.status();
    let body = resp.collect().await.expect("collect body").to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// End-to-end guard for [Roadmap 6.4]: a Starlark rule calling
/// `render_template()` must replace the upstream page with the rendered
/// Minijinja template.
#[tokio::test]
async fn test_render_template_replaces_page_end_to_end() {
    let origin_addr = start_html_origin("<html><body>UPSTREAM</body></html>").await;
    let proxy_addr = start_proxy_with_rules(
        &[(
            "render.star",
            "URLS = [\"*\"]\ndef process(request):\n    render_template(\"demo\", {\"name\": \"web-sieve\"})\n",
        )],
        &[("demo.html", "<html><body><h1>{{ name }}</h1></body></html>")],
    )
    .await;

    let uri = format!("http://{origin_addr}/");
    let (status, body) = get_through_proxy(proxy_addr, &uri, &origin_addr.to_string()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "<html><body><h1>web-sieve</h1></body></html>");
    assert!(!body.contains("UPSTREAM"), "upstream page must be replaced");
}

/// A rule naming a template that does not exist must leave the upstream page
/// intact rather than serving an empty or broken document.
#[tokio::test]
async fn test_render_template_missing_template_passes_page_through() {
    let origin_addr = start_html_origin("<html><body>UPSTREAM</body></html>").await;
    let proxy_addr = start_proxy_with_rules(
        &[(
            "render.star",
            "URLS = [\"*\"]\ndef process(request):\n    render_template(\"absent\", {})\n",
        )],
        &[],
    )
    .await;

    let uri = format!("http://{origin_addr}/");
    let (status, body) = get_through_proxy(proxy_addr, &uri, &origin_addr.to_string()).await;

    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("UPSTREAM"),
        "missing template must fall back to the upstream page, got: {body}"
    );
}

/// Make a plain HTTP request through the proxy and verify we get 200 back.
#[tokio::test]
async fn test_plain_http_proxy_round_trip() {
    let echo_addr = start_echo_server().await;
    let proxy_addr = start_proxy().await;

    // Connect directly to the proxy with a request that targets the echo server.
    let tcp = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect to proxy");

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .expect("handshake");

    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri = format!("http://{echo_addr}/");
    let req = Request::builder()
        .method(hyper::Method::GET)
        .uri(&uri)
        .header(hyper::header::HOST, echo_addr.to_string())
        .body(Empty::<Bytes>::new())
        .expect("request");

    let resp = sender.send_request(req).await.expect("send request");
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.collect().await.expect("collect body").to_bytes();
    assert_eq!(body, Bytes::from_static(b"OK"));
}

/// End-to-end HTTP/2 test: MITM the CONNECT tunnel, negotiate `h2` via ALPN
/// on the browser↔proxy leg, and drive an HTTP/2 request through it.
///
/// This is the guard for [Roadmap 6.3]: it fails if the leaf `ServerConfig`
/// stops advertising `h2` or if `do_mitm` regresses to hard-wired HTTP/1.1.
#[tokio::test]
async fn test_mitm_negotiates_http2_via_alpn() {
    let (origin_addr, origin_cert) = start_https_origin().await;
    let (proxy_addr, ca_pem) = start_proxy_with_extra_root(origin_cert).await;

    // Client trusts the proxy's CA and advertises h2/http/1.1.
    let mut client_roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        client_roots
            .add(cert.expect("valid cert in CA PEM"))
            .expect("add root");
    }
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(client_roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(client_config));

    // Open the CONNECT tunnel via HTTP/1.1 (browsers CONNECT to proxies over h1).
    let tcp = tokio::net::TcpStream::connect(proxy_addr)
        .await
        .expect("connect to proxy");
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
        .await
        .expect("h1 handshake with proxy");
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });

    let authority = format!("localhost:{}", origin_addr.port());
    let connect_req = Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(&authority)
        .body(Empty::<Bytes>::new())
        .expect("CONNECT request");
    let resp = sender
        .send_request(connect_req)
        .await
        .expect("CONNECT send");
    assert_eq!(resp.status(), StatusCode::OK, "CONNECT should return 200");

    let upgraded = hyper::upgrade::on(resp)
        .await
        .expect("upgrade CONNECT tunnel");

    // TLS handshake through the tunnel — the proxy MITMs with a leaf for `localhost`.
    let server_name = ServerName::try_from("localhost").expect("valid server name");
    let tls_stream = connector
        .connect(server_name, TokioIo::new(upgraded))
        .await
        .expect("client-side TLS handshake");

    // ALPN must have selected h2 — this is the core assertion for 6.3.
    let alpn = tls_stream.get_ref().1.alpn_protocol();
    assert_eq!(
        alpn,
        Some(&b"h2"[..]),
        "expected HTTP/2 negotiated via ALPN, got {alpn:?}"
    );

    // Drive an HTTP/2 request over the MITM'd tunnel.
    let (mut h2_sender, h2_conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_stream))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = h2_conn.await;
    });

    let req = Request::builder()
        .method(hyper::Method::GET)
        .uri("/")
        .header(hyper::header::HOST, &authority)
        .body(Empty::<Bytes>::new())
        .expect("h2 request");
    let resp = h2_sender.send_request(req).await.expect("h2 send");
    assert_eq!(resp.status(), StatusCode::OK, "h2 GET / should return 200");

    let body = resp.collect().await.expect("collect h2 body").to_bytes();
    assert_eq!(body, Bytes::from_static(b"OK"), "h2 body must be 'OK'");
}
