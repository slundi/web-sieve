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
        leaf_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2034, 1, 1);

        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key);

        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .map_err(ProxyError::Certificate)?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(ProxyError::Tls)?;

        Ok(server_config)
    }
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
    ca_params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    ca_params.not_after = rcgen::date_time_ymd(2034, 1, 1);
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
}
