//! TLS client configuration for upstream connections.

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;

use crate::error::ProxyError;

/// Candidate paths to the system root certificate bundle.
const SYSTEM_CERT_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

/// Build a [`RootCertStore`] from the first available system cert bundle.
///
/// Tries each path in [`SYSTEM_CERT_PATHS`] in order and loads the first
/// file that exists.  If no file is found, a warning is logged and an empty
/// store is returned (most upstream TLS connections will then fail certificate
/// verification).
pub fn load_system_root_store() -> RootCertStore {
    let mut root_store = RootCertStore::empty();

    for path in SYSTEM_CERT_PATHS {
        if std::path::Path::new(path).exists() {
            match load_certs_from_file(path, &mut root_store) {
                Ok(count) => {
                    tracing::debug!("loaded {count} root certificates from {path}");
                    return root_store;
                }
                Err(err) => {
                    tracing::warn!("failed to load root certs from {path}: {err}");
                }
            }
        }
    }

    tracing::warn!("no system root certificate store found; upstream TLS verification will fail");
    root_store
}

/// Build a [`ClientConfig`] that trusts system root certificates.
///
/// This is a thin wrapper around [`load_system_root_store`] that builds a
/// default (non-fingerprinted) TLS client config for backward compatibility.
///
/// # Errors
///
/// Returns a [`ProxyError`] if the [`ClientConfig`] cannot be constructed.
pub fn make_client_config() -> Result<Arc<ClientConfig>, ProxyError> {
    let root_store = load_system_root_store();

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Parse PEM certificates from `path` and add them to `store`.
///
/// Returns the number of certificates successfully added.
fn load_certs_from_file(path: &str, store: &mut RootCertStore) -> Result<usize, ProxyError> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| ProxyError::RootCerts(e.to_string()))?
        .flatten()
        .collect();

    let mut count = 0usize;
    for cert in certs {
        match store.add(cert) {
            Ok(()) => count += 1,
            Err(e) => tracing::warn!("skipping cert in {path}: {e}"),
        }
    }
    Ok(count)
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

    #[test]
    fn test_make_client_config_returns_ok() {
        setup_crypto();
        let result = make_client_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_make_client_config_is_arc() {
        setup_crypto();
        let config = make_client_config().unwrap();
        // Verify we can clone the Arc without issues.
        let _clone = Arc::clone(&config);
    }

    #[test]
    fn test_load_system_root_store_returns_store() {
        // Should always return a RootCertStore (empty or populated).
        let _store = load_system_root_store();
    }

    #[test]
    fn test_load_certs_skips_bad_cert_and_returns_ok() {
        setup_crypto();
        use std::io::Write;

        // Valid PEM wrapper around random non-DER bytes: pem_file_iter accepts
        // this, but store.add() rejects it. Before the fix, add() would abort
        // with Err; after the fix it logs a warning and returns Ok(0).
        let bad_pem =
            b"-----BEGIN CERTIFICATE-----\ndGhpcyBpcyBub3QgYSBjZXJ0aWZpY2F0ZQ==\n-----END CERTIFICATE-----\n";

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(bad_pem).unwrap();

        let mut store = RootCertStore::empty();
        let result = load_certs_from_file(tmp.path().to_str().unwrap(), &mut store);

        assert!(
            result.is_ok(),
            "bad cert must not abort loading: {result:?}"
        );
        assert_eq!(result.unwrap(), 0, "no valid certs were added");
    }

    #[test]
    fn test_load_certs_count_reflects_successfully_added() {
        setup_crypto();
        use std::io::Write;

        // An empty PEM file: no certs to add → count must be 0, not an error.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"").unwrap();

        let mut store = RootCertStore::empty();
        let result = load_certs_from_file(tmp.path().to_str().unwrap(), &mut store);

        // pem_file_iter on an empty file returns an iterator with 0 items.
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }
}
