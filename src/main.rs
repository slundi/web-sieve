//! web-sieve binary entry point.
//!
//! Parses CLI arguments, initialises tracing, then starts the proxy server.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use bpaf::Bpaf;
use tracing_subscriber::EnvFilter;
use web_sieve::config::Config;
use web_sieve::proxy::ca::CertificateAuthority;
use web_sieve::proxy::fingerprint::FingerprintProfiles;
use web_sieve::proxy::tls::load_system_root_store;

/// Command-line options for the web-sieve proxy.
#[derive(Debug, Clone, Bpaf)]
#[bpaf(options, version)]
struct Opts {
    /// Address to listen on (default: 127.0.0.1:8080).
    #[bpaf(long("bind"), argument("ADDR"), optional)]
    bind: Option<SocketAddr>,

    /// Path to the root CA certificate PEM file.
    #[bpaf(long("ca-cert"), argument("PATH"), optional)]
    ca_cert: Option<PathBuf>,

    /// Path to the root CA private key PEM file.
    #[bpaf(long("ca-key"), argument("PATH"), optional)]
    ca_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise structured logging; honour RUST_LOG env var.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let opts = opts().run();

    let defaults = Config::default();
    let config = Config {
        bind_addr: opts.bind.unwrap_or(defaults.bind_addr),
        ca_cert_path: opts.ca_cert.unwrap_or(defaults.ca_cert_path),
        ca_key_path: opts.ca_key.unwrap_or(defaults.ca_key_path),
    };

    tracing::info!("starting web-sieve proxy");
    tracing::debug!(?config, "resolved configuration");

    let ca = CertificateAuthority::load_or_create(&config.ca_cert_path, &config.ca_key_path)
        .context("failed to initialise certificate authority")?;

    let root_store = load_system_root_store();
    let profiles = Arc::new(
        FingerprintProfiles::new(root_store).context("failed to build fingerprint profiles")?,
    );

    web_sieve::proxy::run(config.bind_addr, ca, profiles)
        .await
        .context("proxy exited with error")?;

    Ok(())
}
