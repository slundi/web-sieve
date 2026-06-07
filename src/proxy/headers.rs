//! Hop-by-hop header filtering for transparent proxy forwarding.

use hyper::header::HeaderMap;

/// Standard hop-by-hop header names that must never be forwarded.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
];

/// Remove all hop-by-hop headers from `headers`.
///
/// Strips the standard set (Connection, Keep-Alive, Proxy-Authenticate,
/// Proxy-Authorization, TE, Trailers, Transfer-Encoding, Upgrade,
/// Proxy-Connection) plus any headers listed in the `Connection` header
/// value itself.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    // Collect any header names listed inside the Connection header value.
    // These are additional headers the sender wants treated as hop-by-hop.
    let connection_extras: Vec<String> = headers
        .get("connection")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    // Remove all standard hop-by-hop headers.
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }

    // Remove any headers named in the Connection value.
    for extra in &connection_extras {
        headers.remove(extra.as_str());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderName, HeaderValue};

    #[test]
    fn test_strips_standard_hop_by_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close"));
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        headers.insert("content-type", HeaderValue::from_static("text/html"));

        strip_hop_by_hop(&mut headers);

        assert!(headers.get("connection").is_none());
        assert!(headers.get("keep-alive").is_none());
        assert!(headers.get("proxy-connection").is_none());
        // End-to-end headers must survive.
        assert!(headers.get("content-type").is_some());
    }

    #[test]
    fn test_preserves_end_to_end() {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", HeaderValue::from_static("session=abc"));
        headers.insert("authorization", HeaderValue::from_static("Bearer token"));
        headers.insert("user-agent", HeaderValue::from_static("Mozilla/5.0"));
        headers.insert("x-custom", HeaderValue::from_static("value"));

        strip_hop_by_hop(&mut headers);

        assert!(headers.get("cookie").is_some());
        assert!(headers.get("authorization").is_some());
        assert!(headers.get("user-agent").is_some());
        assert!(headers.get("x-custom").is_some());
    }

    #[test]
    fn test_strips_connection_listed_headers() {
        let mut headers = HeaderMap::new();
        // Connection header lists "foo" as hop-by-hop.
        headers.insert("connection", HeaderValue::from_static("foo"));
        headers.insert(
            HeaderName::from_static("foo"),
            HeaderValue::from_static("bar"),
        );
        headers.insert("content-length", HeaderValue::from_static("42"));

        strip_hop_by_hop(&mut headers);

        assert!(headers.get("connection").is_none());
        assert!(headers.get("foo").is_none());
        // Non-listed end-to-end header survives.
        assert!(headers.get("content-length").is_some());
    }
}
