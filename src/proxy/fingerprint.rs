//! Browser TLS fingerprint profiles and JA3 computation.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::RootCertStore;

use crate::error::ProxyError;

// ---------------------------------------------------------------------------
// Browser detection
// ---------------------------------------------------------------------------

/// Identifies the browser family from a User-Agent string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Browser {
    /// Google Chrome, Chromium, Microsoft Edge, or Opera.
    Chrome,
    /// Mozilla Firefox.
    Firefox,
    /// Apple Safari.
    Safari,
    /// Unrecognised or missing User-Agent.
    Unknown,
}

impl Browser {
    /// Detect the browser family from a `User-Agent` header value.
    ///
    /// Detection rules (applied in priority order):
    /// - Contains `"Firefox/"` → [`Browser::Firefox`]
    /// - Contains `"Safari/"` but **not** `"Chrome/"` and **not** `"Chromium/"` → [`Browser::Safari`]
    /// - Contains `"Chrome/"`, `"Chromium/"`, `"Edg/"`, or `"OPR/"` → [`Browser::Chrome`]
    /// - Otherwise → [`Browser::Unknown`]
    pub fn from_user_agent(ua: &str) -> Browser {
        if ua.contains("Firefox/") {
            return Browser::Firefox;
        }
        if ua.contains("Safari/") && !ua.contains("Chrome/") && !ua.contains("Chromium/") {
            return Browser::Safari;
        }
        if ua.contains("Chrome/")
            || ua.contains("Chromium/")
            || ua.contains("Edg/")
            || ua.contains("OPR/")
        {
            return Browser::Chrome;
        }
        Browser::Unknown
    }
}

// ---------------------------------------------------------------------------
// Per-browser cipher suite and kx_group orderings
// ---------------------------------------------------------------------------

/// Build a [`ClientConfig`] for a Chrome 120+ TLS fingerprint.
fn chrome_config(root_store: RootCertStore) -> Result<ClientConfig, ProxyError> {
    use rustls::crypto::aws_lc_rs::cipher_suite::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
    use rustls::crypto::aws_lc_rs::kx_group::{SECP256R1, SECP384R1, X25519};

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    provider.kx_groups = vec![X25519, SECP256R1, SECP384R1];

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Build a [`ClientConfig`] for a Firefox 120+ TLS fingerprint.
fn firefox_config(root_store: RootCertStore) -> Result<ClientConfig, ProxyError> {
    use rustls::crypto::aws_lc_rs::cipher_suite::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
    use rustls::crypto::aws_lc_rs::kx_group::{SECP256R1, SECP384R1, X25519};

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![
        TLS13_AES_128_GCM_SHA256,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    provider.kx_groups = vec![X25519, SECP256R1, SECP384R1];

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Build a [`ClientConfig`] for a Safari 17+ TLS fingerprint.
fn safari_config(root_store: RootCertStore) -> Result<ClientConfig, ProxyError> {
    use rustls::crypto::aws_lc_rs::cipher_suite::{
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
    use rustls::crypto::aws_lc_rs::kx_group::{SECP256R1, SECP384R1, X25519};

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites = vec![
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    provider.kx_groups = vec![X25519, SECP256R1, SECP384R1];

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

// ---------------------------------------------------------------------------
// FingerprintProfiles
// ---------------------------------------------------------------------------

/// Pre-built TLS [`ClientConfig`] instances for each known browser fingerprint.
///
/// Build once at startup via [`FingerprintProfiles::new`] and share across
/// tasks via [`Arc`].
pub struct FingerprintProfiles {
    chrome: Arc<ClientConfig>,
    firefox: Arc<ClientConfig>,
    safari: Arc<ClientConfig>,
    unknown: Arc<ClientConfig>,
}

impl FingerprintProfiles {
    /// Build all profiles from the given root certificate store.
    ///
    /// Each profile clones the store so that cipher-suite ordering can differ
    /// per profile without any shared mutable state.
    pub fn new(root_store: RootCertStore) -> Result<Self, ProxyError> {
        let chrome = Arc::new(chrome_config(root_store.clone())?);
        let firefox = Arc::new(firefox_config(root_store.clone())?);
        let safari = Arc::new(safari_config(root_store.clone())?);
        // Unknown falls back to the Chrome profile (safest default).
        let unknown = Arc::new(chrome_config(root_store)?);

        Ok(Self {
            chrome,
            firefox,
            safari,
            unknown,
        })
    }

    /// Return the [`ClientConfig`] for the given [`Browser`].
    pub fn config_for(&self, browser: Browser) -> Arc<ClientConfig> {
        match browser {
            Browser::Chrome => Arc::clone(&self.chrome),
            Browser::Firefox => Arc::clone(&self.firefox),
            Browser::Safari => Arc::clone(&self.safari),
            Browser::Unknown => Arc::clone(&self.unknown),
        }
    }
}

// ---------------------------------------------------------------------------
// JA3 computation
// ---------------------------------------------------------------------------

/// GREASE values that must be filtered from JA3 fields.
const GREASE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Cipher suite IDs (decimal) used in JA3 strings — Chrome/Unknown order.
const CIPHER_IDS_CHROME: &[u16] = &[
    4865,  // TLS13_AES_128_GCM_SHA256
    4866,  // TLS13_AES_256_GCM_SHA384
    4867,  // TLS13_CHACHA20_POLY1305_SHA256
    49195, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    49199, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    49196, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    49200, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    52393, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    52392, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
];

/// Cipher suite IDs (decimal) used in JA3 strings — Firefox order.
const CIPHER_IDS_FIREFOX: &[u16] = &[
    4865,  // TLS13_AES_128_GCM_SHA256
    4867,  // TLS13_CHACHA20_POLY1305_SHA256
    4866,  // TLS13_AES_256_GCM_SHA384
    49195, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    49199, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    49196, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    49200, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    52393, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    52392, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
];

/// Cipher suite IDs (decimal) used in JA3 strings — Safari order.
const CIPHER_IDS_SAFARI: &[u16] = &[
    4865,  // TLS13_AES_128_GCM_SHA256
    4866,  // TLS13_AES_256_GCM_SHA384
    4867,  // TLS13_CHACHA20_POLY1305_SHA256
    49196, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    49195, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    49200, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    49199, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    52392, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    52393, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
];

/// Extension IDs for each browser (GREASE already excluded).
const EXTENSIONS_CHROME: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21];
const EXTENSIONS_FIREFOX: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 51, 45, 43, 21];
const EXTENSIONS_SAFARI: &[u16] = &[0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 21];

/// Named curve IDs used in all profiles: X25519=29, SECP256R1=23, SECP384R1=24.
const KX_GROUP_IDS: &[u16] = &[29, 23, 24];

/// EC point format: 0 = uncompressed.
const POINT_FORMATS: &[u16] = &[0];

/// Filter GREASE values from a slice of IDs and join them as dash-separated decimals.
fn join_ids(ids: &[u16]) -> String {
    ids.iter()
        .filter(|id| !GREASE.contains(id))
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Compute the JA3 fingerprint string and its MD5 hash for a browser profile.
///
/// JA3 format: `TLSVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats`
///
/// The hash is the lowercase hex MD5 of that string.  TLS version in the
/// ClientHello is always 771 (TLS 1.2) even when TLS 1.3 is negotiated.
///
/// Returns `(ja3_string, ja3_hash)`.
pub fn ja3_for_browser(browser: Browser) -> (String, String) {
    let (cipher_ids, ext_ids) = match browser {
        Browser::Chrome | Browser::Unknown => (CIPHER_IDS_CHROME, EXTENSIONS_CHROME),
        Browser::Firefox => (CIPHER_IDS_FIREFOX, EXTENSIONS_FIREFOX),
        Browser::Safari => (CIPHER_IDS_SAFARI, EXTENSIONS_SAFARI),
    };

    let ja3_string = format!(
        "771,{},{},{},{}",
        join_ids(cipher_ids),
        join_ids(ext_ids),
        join_ids(KX_GROUP_IDS),
        join_ids(POINT_FORMATS),
    );

    let ja3_hash = format!("{:x}", md5::compute(ja3_string.as_bytes()));

    (ja3_string, ja3_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Browser::from_user_agent ---

    #[test]
    fn test_browser_from_ua_chrome() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        assert_eq!(Browser::from_user_agent(ua), Browser::Chrome);
    }

    #[test]
    fn test_browser_from_ua_firefox() {
        let ua = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0";
        assert_eq!(Browser::from_user_agent(ua), Browser::Firefox);
    }

    #[test]
    fn test_browser_from_ua_safari() {
        let ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        assert_eq!(Browser::from_user_agent(ua), Browser::Safari);
    }

    #[test]
    fn test_browser_from_ua_edge() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
        assert_eq!(Browser::from_user_agent(ua), Browser::Chrome);
    }

    #[test]
    fn test_browser_from_ua_unknown() {
        let ua = "curl/8.1.2";
        assert_eq!(Browser::from_user_agent(ua), Browser::Unknown);
    }

    // --- JA3 ---

    #[test]
    fn test_ja3_string_format() {
        let (ja3_string, _) = ja3_for_browser(Browser::Chrome);
        assert!(
            ja3_string.starts_with("771,"),
            "JA3 string must start with TLS version 771"
        );
        assert_eq!(
            ja3_string.chars().filter(|c| *c == ',').count(),
            4,
            "JA3 string must have exactly 4 commas"
        );
    }

    #[test]
    fn test_ja3_hash_length() {
        for browser in [
            Browser::Chrome,
            Browser::Firefox,
            Browser::Safari,
            Browser::Unknown,
        ] {
            let (_, hash) = ja3_for_browser(browser);
            assert_eq!(
                hash.len(),
                32,
                "JA3 MD5 hash must be 32 hex chars for {browser:?}"
            );
        }
    }

    // --- ALPN regression: h2 must not be advertised upstream ---

    #[test]
    fn test_alpn_http1_only() {
        use rustls::RootCertStore;
        let profiles = FingerprintProfiles::new(RootCertStore::empty()).unwrap();
        for browser in [
            Browser::Chrome,
            Browser::Firefox,
            Browser::Safari,
            Browser::Unknown,
        ] {
            let config = profiles.config_for(browser);
            assert_eq!(
                config.alpn_protocols,
                vec![b"http/1.1".to_vec()],
                "profile {browser:?} must not advertise h2 — upstream only speaks HTTP/1.1"
            );
        }
    }
}
