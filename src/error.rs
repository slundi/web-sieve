//! Unified error type for the web-sieve library.

use thiserror::Error;

/// All errors that can occur within the web-sieve proxy library.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A certificate generation or signing error occurred.
    #[error("certificate error: {0}")]
    Certificate(#[from] rcgen::Error),

    /// A TLS error occurred.
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    /// A hyper HTTP error occurred.
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),

    /// An invalid or missing host in the CONNECT request.
    #[error("invalid CONNECT authority: {0}")]
    InvalidAuthority(String),

    /// A DNS name was invalid.
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),

    /// The system root certificate store could not be loaded.
    #[error("failed to load system root certificates: {0}")]
    RootCerts(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_error_display_io() {
        let err = ProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_proxy_error_display_invalid_authority() {
        let err = ProxyError::InvalidAuthority("bad:host:port".to_string());
        assert!(err.to_string().contains("invalid CONNECT authority"));
    }
}
