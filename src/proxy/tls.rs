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

/// Build a [`ClientConfig`] that trusts system root certificates.
///
/// The function tries each path in [`SYSTEM_CERT_PATHS`] in order and loads
/// the first file that exists.  If no file is found, a warning is logged and
/// an empty root store is used (most upstream TLS connections will then fail
/// certificate verification).
///
/// # Errors
///
/// Returns a [`ProxyError`] if the [`ClientConfig`] cannot be constructed.
pub fn make_client_config() -> Result<Arc<ClientConfig>, ProxyError> {
    let mut root_store = RootCertStore::empty();

    let mut loaded = false;
    for path in SYSTEM_CERT_PATHS {
        if std::path::Path::new(path).exists() {
            match load_certs_from_file(path, &mut root_store) {
                Ok(count) => {
                    tracing::debug!("loaded {count} root certificates from {path}");
                    loaded = true;
                    break;
                }
                Err(err) => {
                    tracing::warn!("failed to load root certs from {path}: {err}");
                }
            }
        }
    }

    if !loaded {
        tracing::warn!(
            "no system root certificate store found; upstream TLS verification will fail"
        );
    }

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

    let count = certs.len();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| ProxyError::RootCerts(e.to_string()))?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_client_config_returns_ok() {
        // Should succeed even if no system certs are found.
        let result = make_client_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_make_client_config_is_arc() {
        let config = make_client_config().unwrap();
        // Verify we can clone the Arc without issues.
        let _clone = Arc::clone(&config);
    }
}
