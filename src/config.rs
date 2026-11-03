//! Configuration types and default paths for the web-sieve proxy.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Runtime configuration for the web-sieve proxy.
///
/// # Examples
///
/// ```
/// use web_sieve::config::Config;
///
/// let config = Config::default();
/// assert_eq!(config.bind_addr.to_string(), "127.0.0.1:8080");
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    /// Address the proxy will listen on.
    pub bind_addr: SocketAddr,
    /// Path to the root CA certificate PEM file.
    pub ca_cert_path: PathBuf,
    /// Path to the root CA private key PEM file.
    pub ca_key_path: PathBuf,
    /// Directory containing Starlark rule files (*.star).
    pub rules_dir: PathBuf,
    /// Directory containing ad-block list files (*.txt in EasyList/uBlock format).
    pub lists_dir: PathBuf,
    /// Directory containing content-scanner dictionary files (*.txt, one term per line).
    pub dicts_dir: PathBuf,
    /// XDG *data* directory (not the config one): the root for shareable
    /// content rather than machine-local settings.  Holds `css/`, `js/`,
    /// `fonts/`, `scripts/`, and `templates/`, and is the shared asset root
    /// served under `<asset_host>/assets/…`.
    pub data_dir: PathBuf,
    /// Directory containing Minijinja display templates.  Defaults to
    /// `data_dir/templates` but may be pointed elsewhere independently.
    pub templates_dir: PathBuf,
    /// Hostname the proxy answers locally for static assets, bypassing any
    /// upstream connection.  Default: `webprism.local`.
    pub asset_host: String,
    /// Origins permitted to read assets cross-origin.  Empty — the default —
    /// keeps assets same-origin; `*` allows any origin.
    pub cors_allow_origins: Vec<String>,
    /// Density threshold for semantic blocking: hits-per-byte ratio above which
    /// a Starlark rule may call `block_page()`.  Exposed to scripts via
    /// `density_threshold()`.  Default: `0.01` (1 hit per 100 bytes).
    pub density_threshold: f32,
    /// Maximum number of per-domain [`rustls::ServerConfig`] objects kept in
    /// the certificate cache.  Oldest entries are evicted when the limit is
    /// reached.  Default: `2048`.
    pub cert_cache_capacity: usize,
}

impl Default for Config {
    fn default() -> Self {
        let config_dir = config_dir();
        let data_dir = data_dir();
        Self {
            bind_addr: "127.0.0.1:8080"
                .parse()
                .expect("hard-coded address is valid"),
            ca_cert_path: config_dir.join("ca.crt"),
            ca_key_path: config_dir.join("ca.key"),
            rules_dir: config_dir.join("rules"),
            lists_dir: config_dir.join("lists"),
            dicts_dir: config_dir.join("dicts"),
            templates_dir: data_dir.join("templates"),
            data_dir,
            asset_host: crate::assets::DEFAULT_ASSET_HOST.to_string(),
            cors_allow_origins: Vec::new(),
            density_threshold: 0.01,
            cert_cache_capacity: 2048,
        }
    }
}

/// Returns the web-sieve configuration directory, honouring `$XDG_CONFIG_HOME`.
fn config_dir() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", ".config")
}

/// Returns the web-sieve data directory, honouring `$XDG_DATA_HOME`.
fn data_dir() -> PathBuf {
    xdg_dir("XDG_DATA_HOME", ".local/share")
}

/// Resolve `$<env_var>/web-sieve`, falling back to `$HOME/<fallback>/web-sieve`.
fn xdg_dir(env_var: &str, fallback: &str) -> PathBuf {
    let base = std::env::var_os(env_var)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            home.join(fallback)
        });
    base.join("web-sieve")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_bind_addr() {
        let config = Config::default();
        assert_eq!(config.bind_addr.port(), 8080);
        assert_eq!(config.bind_addr.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_default_ca_paths_under_config_dir() {
        let config = Config::default();
        assert!(config.ca_cert_path.to_string_lossy().contains("web-sieve"));
        assert!(config.ca_cert_path.file_name().unwrap() == "ca.crt");
        assert!(config.ca_key_path.file_name().unwrap() == "ca.key");
    }

    #[test]
    fn test_default_rules_dir() {
        let config = Config::default();
        assert!(config.rules_dir.to_string_lossy().contains("web-sieve"));
        assert!(config.rules_dir.ends_with("rules"));
    }

    #[test]
    fn test_default_lists_dir() {
        let config = Config::default();
        assert!(config.lists_dir.to_string_lossy().contains("web-sieve"));
        assert!(config.lists_dir.ends_with("lists"));
    }

    #[test]
    fn test_default_dicts_dir() {
        let config = Config::default();
        assert!(config.dicts_dir.to_string_lossy().contains("web-sieve"));
        assert!(config.dicts_dir.ends_with("dicts"));
    }

    #[test]
    fn test_default_templates_dir_under_data_dir() {
        let config = Config::default();
        let path = config.templates_dir.to_string_lossy().into_owned();
        assert!(path.contains("web-sieve"), "unexpected path: {path}");
        assert!(config.templates_dir.ends_with("templates"));
        assert!(
            !config.templates_dir.starts_with(&config.rules_dir),
            "templates must live in the data dir, not under the rules dir"
        );
    }

    #[test]
    fn test_default_templates_dir_sits_under_data_dir() {
        let config = Config::default();
        assert!(
            config.templates_dir.starts_with(&config.data_dir),
            "templates dir must default to a child of the data dir"
        );
    }

    #[test]
    fn test_default_asset_host() {
        assert_eq!(Config::default().asset_host, "webprism.local");
    }

    #[test]
    fn test_default_cors_allow_origins_is_empty() {
        assert!(
            Config::default().cors_allow_origins.is_empty(),
            "assets must default to same-origin only"
        );
    }

    #[test]
    fn test_default_density_threshold() {
        let config = Config::default();
        assert!((config.density_threshold - 0.01_f32).abs() < f32::EPSILON);
    }

    #[test]
    fn test_default_cert_cache_capacity() {
        assert_eq!(Config::default().cert_cache_capacity, 2048);
    }
}
