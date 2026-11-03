//! web-sieve binary entry point.
//!
//! Parses CLI arguments, initialises tracing, then starts the proxy server.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use bpaf::Bpaf;
use tracing_subscriber::EnvFilter;
use web_sieve::assets::AssetServer;
use web_sieve::config::Config;
use web_sieve::filter::AdBlockEngine;
use web_sieve::proxy::Pipeline;
use web_sieve::proxy::ca::CertificateAuthority;
use web_sieve::proxy::fingerprint::FingerprintProfiles;
use web_sieve::proxy::tls::load_system_root_store;
use web_sieve::scanner::TextScanner;
use web_sieve::scripting::ScriptEngine;
use web_sieve::templates::TemplateEngine;

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

    /// Directory containing Starlark rule files (*.star).
    #[bpaf(long("rules-dir"), argument("PATH"), optional)]
    rules_dir: Option<PathBuf>,

    /// Directory containing ad-block list files (*.txt in EasyList/uBlock format).
    #[bpaf(long("lists-dir"), argument("PATH"), optional)]
    lists_dir: Option<PathBuf>,

    /// Directory containing content-scanner dictionary files (*.txt, one term per line).
    #[bpaf(long("dicts-dir"), argument("PATH"), optional)]
    dicts_dir: Option<PathBuf>,

    /// XDG data directory holding shared assets (`css`, `js`, `fonts`,
    /// `scripts`, `templates`), served under `<asset-host>/assets/…`
    /// (default: `$XDG_DATA_HOME/web-sieve`).
    #[bpaf(long("data-dir"), argument("PATH"), optional)]
    data_dir: Option<PathBuf>,

    /// Directory containing Minijinja display templates (default:
    /// `<data-dir>/templates`).
    #[bpaf(long("templates-dir"), argument("PATH"), optional)]
    templates_dir: Option<PathBuf>,

    /// Hostname answered locally for static assets, with no upstream
    /// connection and no DNS or /etc/hosts entry needed (default:
    /// `webprism.local`).
    #[bpaf(long("asset-host"), argument("HOST"), optional)]
    asset_host: Option<String>,

    /// Origin allowed to read assets cross-origin. Repeat for several, or pass
    /// `*` for any. Omitted entirely, assets stay same-origin.
    #[bpaf(long("cors-allow-origin"), argument("ORIGIN"), many)]
    cors_allow_origin: Vec<String>,

    /// Hits-per-byte density threshold for semantic blocking rules (default: 0.01).
    /// Starlark scripts read this via `density_threshold()` instead of hard-coding a value.
    #[bpaf(long("density-threshold"), argument("FLOAT"), optional)]
    density_threshold: Option<f32>,

    /// Maximum number of per-domain TLS certificates to keep in the cache (default: 2048).
    #[bpaf(long("cert-cache-capacity"), argument("N"), optional)]
    cert_cache_capacity: Option<usize>,
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
    // `--data-dir` moves the shared asset root; templates follow it unless
    // `--templates-dir` names a location explicitly.
    let data_dir = opts.data_dir.unwrap_or(defaults.data_dir);
    let templates_dir = opts
        .templates_dir
        .unwrap_or_else(|| data_dir.join("templates"));
    let config = Config {
        bind_addr: opts.bind.unwrap_or(defaults.bind_addr),
        ca_cert_path: opts.ca_cert.unwrap_or(defaults.ca_cert_path),
        ca_key_path: opts.ca_key.unwrap_or(defaults.ca_key_path),
        rules_dir: opts.rules_dir.unwrap_or(defaults.rules_dir),
        lists_dir: opts.lists_dir.unwrap_or(defaults.lists_dir),
        dicts_dir: opts.dicts_dir.unwrap_or(defaults.dicts_dir),
        data_dir,
        templates_dir,
        asset_host: opts.asset_host.unwrap_or(defaults.asset_host),
        cors_allow_origins: opts.cors_allow_origin,
        density_threshold: opts.density_threshold.unwrap_or(defaults.density_threshold),
        cert_cache_capacity: opts
            .cert_cache_capacity
            .unwrap_or(defaults.cert_cache_capacity),
    };

    tracing::info!("starting web-sieve proxy");
    tracing::debug!(?config, "resolved configuration");

    let ca = CertificateAuthority::load_or_create(
        &config.ca_cert_path,
        &config.ca_key_path,
        config.cert_cache_capacity,
    )
    .context("failed to initialise certificate authority")?;

    let root_store = load_system_root_store();
    let profiles = Arc::new(
        FingerprintProfiles::new(root_store).context("failed to build fingerprint profiles")?,
    );

    let engine = ScriptEngine::new(config.rules_dir.clone(), config.density_threshold)
        .await
        .context("failed to initialise scripting engine")?;

    let blocker = AdBlockEngine::new(config.lists_dir.clone())
        .await
        .context("failed to initialise ad-block engine")?;

    let scanner = TextScanner::new(config.dicts_dir.clone())
        .await
        .context("failed to initialise text scanner")?;

    // The shared asset root must exist before it can be canonicalised on each
    // lookup; the per-script root is the rules directory the engine created.
    tokio::fs::create_dir_all(&config.data_dir)
        .await
        .context("failed to create data directory")?;
    let assets = Arc::new(AssetServer::new(
        config.asset_host.clone(),
        config.data_dir.clone(),
        config.rules_dir.clone(),
        config.cors_allow_origins.clone(),
    ));

    let templates = TemplateEngine::with_assets(config.templates_dir.clone(), Arc::clone(&assets))
        .await
        .context("failed to initialise template engine")?;

    let pipeline = Arc::new(Pipeline {
        engine,
        blocker,
        scanner,
        templates,
        assets,
    });

    web_sieve::proxy::run(config.bind_addr, ca, profiles, pipeline)
        .await
        .context("proxy exited with error")?;

    Ok(())
}
