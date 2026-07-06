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
        Self {
            bind_addr: "127.0.0.1:8080"
                .parse()
                .expect("hard-coded address is valid"),
            ca_cert_path: config_dir.join("ca.crt"),
            ca_key_path: config_dir.join("ca.key"),
            rules_dir: config_dir.join("rules"),
            lists_dir: config_dir.join("lists"),
            dicts_dir: config_dir.join("dicts"),
            density_threshold: 0.01,
            cert_cache_capacity: 2048,
        }
    }
}

/// Returns the web-sieve configuration directory, honouring `$XDG_CONFIG_HOME`.
fn config_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            home.join(".config")
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
    fn test_default_density_threshold() {
        let config = Config::default();
        assert!((config.density_threshold - 0.01_f32).abs() < f32::EPSILON);
    }

    #[test]
    fn test_default_cert_cache_capacity() {
        assert_eq!(Config::default().cert_cache_capacity, 2048);
    }
}
