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

    /// An error surfaced by hyper's server connection driver (h1/h2 auto).
    ///
    /// Wrapped as a string because `hyper_util`'s auto builder returns a
    /// boxed error rather than a concrete `hyper::Error`.
    #[error("server connection error: {0}")]
    ServerConnection(String),

    /// An invalid or missing host in the CONNECT request.
    #[error("invalid CONNECT authority: {0}")]
    InvalidAuthority(String),

    /// A DNS name was invalid.
    #[error("invalid DNS name: {0}")]
    InvalidDnsName(String),

    /// The system root certificate store could not be loaded.
    #[error("failed to load system root certificates: {0}")]
    RootCerts(String),

    /// A scripting engine error.
    #[error("scripting error: {0}")]
    Scripting(String),

    /// An HTML rewriting error.
    #[error("rewriting error: {0}")]
    Rewriting(String),
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

    #[test]
    fn test_proxy_error_display_scripting() {
        let err = ProxyError::Scripting("eval failed".to_string());
        assert!(err.to_string().contains("scripting error"));
    }

    #[test]
    fn test_proxy_error_display_rewriting() {
        let err = ProxyError::Rewriting("selector error".to_string());
        assert!(err.to_string().contains("rewriting error"));
    }

    #[test]
    fn test_proxy_error_display_server_connection() {
        let err = ProxyError::ServerConnection("h2 stream closed".to_string());
        assert!(err.to_string().contains("server connection error"));
    }
}
