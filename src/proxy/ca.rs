//! Root CA management and per-domain leaf certificate generation.

use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

use crate::error::ProxyError;

/// Manages the root Certificate Authority and issues per-domain leaf certificates.
///
/// Leaf [`ServerConfig`] objects are cached so that TLS handshakes for the same
/// domain reuse the same certificate, avoiding unnecessary re-signing work.
pub struct CertificateAuthority {
    /// PEM-encoded root CA certificate (for user installation).
    ca_cert_pem: String,
    /// CA signing key.
    ca_key: KeyPair,
    /// CA parameters used to build an [`Issuer`] for signing leaf certs.
    ca_params: CertificateParams,
    /// Bounded LRU cache of per-domain [`ServerConfig`].
    cache: Mutex<lru::LruCache<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    /// Load an existing CA from PEM files, or generate and persist a new one.
    ///
    /// If both `cert_path` and `key_path` exist they are read; otherwise a new
    /// ECDSA P-256 CA is generated and written to those paths (creating parent
    /// directories as needed).
    ///
    /// `cache_capacity` bounds the per-domain [`ServerConfig`] LRU cache.
    /// Passing `0` is a programmer error and will panic.
    ///
    /// # Errors
    ///
    /// Returns a [`ProxyError`] if the files cannot be read/written or if
    /// certificate generation fails.
    pub fn load_or_create(
        cert_path: &Path,
        key_path: &Path,
        cache_capacity: usize,
    ) -> Result<Arc<Self>, ProxyError> {
        let cap = NonZeroUsize::new(cache_capacity)
            .expect("cert_cache_capacity must be greater than zero");

        if cert_path.exists() && key_path.exists() {
            tracing::info!("loading existing CA from {}", cert_path.display());
            let ca_key = KeyPair::from_pem(&std::fs::read_to_string(key_path)?)
                .map_err(ProxyError::Certificate)?;
            let ca_cert_pem = std::fs::read_to_string(cert_path)?;
            // Validate the PEM is parseable.
            let _ = CertificateDer::from_pem_slice(ca_cert_pem.as_bytes())
                .map_err(|e| ProxyError::RootCerts(e.to_string()))?;
            let ca_params = build_ca_params();
            return Ok(Arc::new(Self {
                ca_cert_pem,
                ca_key,
                ca_params,
                cache: Mutex::new(lru::LruCache::new(cap)),
            }));
        }

        tracing::info!("generating new root CA");
        let ca_key = KeyPair::generate().map_err(ProxyError::Certificate)?;
        let ca_params = build_ca_params();
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(ProxyError::Certificate)?;
        let ca_cert_pem = ca_cert.pem();

        // Persist.
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(cert_path, &ca_cert_pem)?;
        std::fs::write(key_path, ca_key.serialize_pem())?;
        tracing::info!("CA written to {}", cert_path.display());

        Ok(Arc::new(Self {
            ca_cert_pem,
            ca_key,
            ca_params,
            cache: Mutex::new(lru::LruCache::new(cap)),
        }))
    }

    /// Return the root CA certificate in PEM format.
    ///
    /// Use this to expose the CA certificate for user installation.
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Build (or return a cached) [`ServerConfig`] for the given `domain`.
    ///
    /// A fresh ECDSA P-256 leaf certificate valid for `domain` is signed by the
    /// root CA and wrapped in a [`ServerConfig`] that can be used with
    /// [`tokio_rustls::TlsAcceptor`].
    ///
    /// # Errors
    ///
    /// Returns a [`ProxyError`] if certificate generation or TLS configuration
    /// fails.
    pub fn server_config(&self, domain: &str) -> Result<Arc<ServerConfig>, ProxyError> {
        {
            let mut cache = self.cache.lock().expect("CA cache lock poisoned");
            if let Some(cfg) = cache.get(domain) {
                return Ok(Arc::clone(cfg));
            }
        }

        let cfg = Arc::new(self.build_server_config(domain)?);

        let mut cache = self.cache.lock().expect("CA cache lock poisoned");
        cache.put(domain.to_string(), Arc::clone(&cfg));
        Ok(cfg)
    }

    /// Generate a leaf certificate for `domain` signed by this CA.
    fn build_server_config(&self, domain: &str) -> Result<ServerConfig, ProxyError> {
        let leaf_key = KeyPair::generate().map_err(ProxyError::Certificate)?;

        let san = SanType::DnsName(
            domain
                .try_into()
                .map_err(|_| ProxyError::InvalidDnsName(domain.to_string()))?,
        );

        let mut leaf_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        leaf_params.distinguished_name = dn;
        leaf_params.subject_alt_names = vec![san];
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let (not_before, not_after) = leaf_validity();
        leaf_params.not_before = not_before;
        leaf_params.not_after = not_after;

        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);

        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .map_err(ProxyError::Certificate)?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(ProxyError::Tls)?;

        // Advertise HTTP/2 first, HTTP/1.1 second. The MITM leg negotiates the
        // browser↔proxy protocol via ALPN; clients that do not offer `h2` fall
        // back to `http/1.1` seamlessly.
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(server_config)
    }
}

/// Validity window for the root CA: 1 day in the past to 10 years in the future.
///
/// The 1-day back-date absorbs minor clock skew between the proxy host and
/// TLS clients that validate `notBefore` strictly.
fn ca_validity() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (
        now - time::Duration::days(1),
        now + time::Duration::days(365 * 10),
    )
}

/// Validity window for a leaf certificate: ±1 day from now.
///
/// Short-lived leaves are fine here because they are regenerated from the
/// in-memory CA whenever the LRU cache evicts them; clients never store them.
fn leaf_validity() -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    (now - time::Duration::days(1), now + time::Duration::days(1))
}

/// Build [`CertificateParams`] for the root CA.
fn build_ca_params() -> CertificateParams {
    let mut ca_params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "web-sieve Root CA");
    dn.push(DnType::OrganizationName, "web-sieve");
    ca_params.distinguished_name = dn;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let (not_before, not_after) = ca_validity();
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    ca_params
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_crypto() {
        static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    fn temp_ca() -> (Arc<CertificateAuthority>, tempfile::TempDir) {
        setup_crypto();
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("ca.crt");
        let key = dir.path().join("ca.key");
        let ca =
            CertificateAuthority::load_or_create(&cert, &key, 2048).expect("CA creation failed");
        (ca, dir)
    }

    #[test]
    fn test_load_or_create_generates_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("ca.crt");
        let key = dir.path().join("ca.key");

        let ca = CertificateAuthority::load_or_create(&cert, &key, 2048).expect("create CA");
        assert!(cert.exists(), "cert file should be written");
        assert!(key.exists(), "key file should be written");

        let pem = ca.ca_cert_pem();
        assert!(pem.contains("CERTIFICATE"));
    }

    #[test]
    fn test_load_or_create_loads_existing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("ca.crt");
        let key = dir.path().join("ca.key");

        CertificateAuthority::load_or_create(&cert, &key, 2048).expect("first create");
        CertificateAuthority::load_or_create(&cert, &key, 2048).expect("reload CA");
    }

    #[test]
    fn test_server_config_for_domain() {
        let (ca, _dir) = temp_ca();
        let cfg = ca.server_config("example.com").expect("server config");
        let _clone = Arc::clone(&cfg);
    }

    #[test]
    fn test_server_config_advertises_h2_and_http11_alpn() {
        let (ca, _dir) = temp_ca();
        let cfg = ca.server_config("example.com").expect("server config");
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            "leaf ServerConfig must advertise `h2` first, then `http/1.1`"
        );
    }

    #[test]
    fn test_server_config_alpn_h2_ordered_before_http11() {
        // Regression guard: ALPN preference is order-sensitive. Rustls picks
        // the server's first match among the client's offers, so h2 must lead.
        let (ca, _dir) = temp_ca();
        let cfg = ca
            .server_config("ordered.example.com")
            .expect("server config");
        let first = cfg.alpn_protocols.first().expect("at least one protocol");
        assert_eq!(first.as_slice(), b"h2", "h2 must be first in ALPN list");
    }

    #[test]
    fn test_server_config_caches_result() {
        let (ca, _dir) = temp_ca();
        let cfg1 = ca.server_config("cached.example.com").expect("first");
        let cfg2 = ca.server_config("cached.example.com").expect("second");
        assert!(Arc::ptr_eq(&cfg1, &cfg2), "configs should be the same Arc");
    }

    #[test]
    fn test_server_config_evicts_lru_when_full() {
        setup_crypto();
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = CertificateAuthority::load_or_create(
            &dir.path().join("ca.crt"),
            &dir.path().join("ca.key"),
            2,
        )
        .expect("CA");

        // Fill the cache to capacity.
        let cfg_a1 = ca.server_config("a.com").expect("a first");
        let _cfg_b = ca.server_config("b.com").expect("b"); // a is now LRU

        // Inserting a third domain evicts a.com (the LRU entry).
        let _cfg_c = ca.server_config("c.com").expect("c");

        // Re-issuing a.com must return a fresh Arc — it was evicted.
        let cfg_a2 = ca.server_config("a.com").expect("a re-issued");
        assert!(
            !Arc::ptr_eq(&cfg_a1, &cfg_a2),
            "a.com should have been evicted and re-issued with a new ServerConfig"
        );
    }

    // ─── Validity window tests ────────────────────────────────────────────

    #[test]
    fn test_ca_validity_not_before_in_past() {
        let now = OffsetDateTime::now_utc();
        let (not_before, _) = ca_validity();
        assert!(
            not_before < now,
            "CA not_before must be in the past (clock-skew buffer)"
        );
        // Must not be more than 2 days old — catches accidental hardcoding.
        assert!(
            not_before > now - time::Duration::days(2),
            "CA not_before is unexpectedly far in the past"
        );
    }

    #[test]
    fn test_ca_validity_not_after_far_future() {
        let now = OffsetDateTime::now_utc();
        let (_, not_after) = ca_validity();
        assert!(
            not_after > now + time::Duration::days(365),
            "CA not_after must be at least 1 year ahead"
        );
        // Sanity upper bound — catches accidental 1000-year values.
        assert!(
            not_after < now + time::Duration::days(365 * 15),
            "CA not_after is unexpectedly far in the future"
        );
    }

    #[test]
    fn test_leaf_validity_not_before_in_past() {
        let now = OffsetDateTime::now_utc();
        let (not_before, _) = leaf_validity();
        assert!(not_before < now, "leaf not_before must be in the past");
        assert!(
            not_before > now - time::Duration::days(2),
            "leaf not_before is unexpectedly far in the past"
        );
    }

    #[test]
    fn test_leaf_validity_not_after_near_future() {
        let now = OffsetDateTime::now_utc();
        let (_, not_after) = leaf_validity();
        assert!(not_after > now, "leaf not_after must be in the future");
        assert!(
            not_after < now + time::Duration::days(2),
            "leaf not_after must be within 2 days (short-lived cert)"
        );
    }
}
