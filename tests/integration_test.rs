//! Integration tests: verify the proxy can forward plain HTTP requests.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use web_sieve::filter::AdBlockEngine;
use web_sieve::proxy::ca::CertificateAuthority;
use web_sieve::proxy::fingerprint::FingerprintProfiles;
use web_sieve::proxy::tls::load_system_root_store;
use web_sieve::scanner::TextScanner;
use web_sieve::scripting::ScriptEngine;

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
    )
    .expect("CA");

    let rules_dir = dir.path().join("rules");
    let engine = ScriptEngine::new(rules_dir)
        .await
        .expect("scripting engine");

    let lists_dir = dir.path().join("lists");
    let blocker = AdBlockEngine::new(lists_dir)
        .await
        .expect("ad-block engine");

    let dicts_dir = dir.path().join("dicts");
    let scanner = TextScanner::new(dicts_dir).await.expect("text scanner");

    // Keep tempdir alive for the duration of the test by leaking it.
    std::mem::forget(dir);

    let root_store = load_system_root_store();
    let profiles = Arc::new(FingerprintProfiles::new(root_store).expect("fingerprint profiles"));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let proxy_addr = listener.local_addr().expect("local addr");
    drop(listener);

    tokio::spawn(async move {
        web_sieve::proxy::run(proxy_addr, ca, profiles, engine, blocker, scanner)
            .await
            .expect("proxy run");
    });

    // Give the proxy a moment to start listening.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    proxy_addr
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
