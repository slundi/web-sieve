//! Proxy routing and activation triggers.
//!
//! Two mechanisms activate a rewriting mode without touching Starlark rules:
//!
//! * **Subdomain trigger** — a request to `<mode>.<proto>.<host…>` (e.g.
//!   `reader.https.example.com`) is recognised, the effective upstream target
//!   is rewritten to `<host…>` on the port implied by `<proto>`, and the mode
//!   is queued as a [`RewriteOp`] on the intercepted response.
//! * **Header trigger** — the optional browser extension may add
//!   `X-Proxy-Control: <mode>[, <mode>…]` to a request. The header is stripped
//!   before forwarding and every listed mode is queued alongside subdomain
//!   modes.
//!
//! Both mechanisms are additive; subdomain and header modes are merged and
//! de-duplicated in first-seen order.

use hyper::HeaderMap;

use crate::rewriter::RewriteOp;

/// HTTP header name (lower-cased) used to signal activation modes from a
/// browser extension.
pub const ACTIVATION_HEADER: &str = "x-proxy-control";

/// Mode name that requests a raw pass-through: skip Starlark rules, cosmetic
/// filtering, and HTML rewriting entirely.
pub const RAW_MODE: &str = "raw";

/// A subdomain-based activation trigger extracted from a request host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTrigger {
    /// Activation mode (e.g. `"reader"`, `"block"`, `"raw"`).
    pub mode: String,
    /// Effective upstream host, with the `<mode>.<proto>.` prefix stripped.
    pub target_host: String,
    /// Effective upstream port (`443` for `https`, `80` for `http`).
    pub target_port: u16,
    /// Whether the effective upstream connection uses TLS.
    pub upstream_https: bool,
}

/// Parse `host` for a subdomain activation trigger of the form
/// `<mode>.<proto>.<host…>`.
///
/// `<proto>` must be exactly `http` or `https`. `<host…>` must contain at
/// least one dot to keep the trigger unambiguous — e.g. `reader.https.x`
/// alone is refused because `x` is not a plausible domain.
///
/// Returns `None` when the host does not match the pattern.
pub fn parse_host_trigger(host: &str) -> Option<HostTrigger> {
    let (mode, rest) = host.split_once('.')?;
    if mode.is_empty() || !is_valid_mode_label(mode) {
        return None;
    }

    let (proto, target) = rest.split_once('.')?;
    let upstream_https = match proto {
        "https" => true,
        "http" => false,
        _ => return None,
    };

    if !target.contains('.') || target.is_empty() {
        return None;
    }

    let target_port = if upstream_https { 443 } else { 80 };
    Some(HostTrigger {
        mode: mode.to_ascii_lowercase(),
        target_host: target.to_owned(),
        target_port,
        upstream_https,
    })
}

/// Return `true` if `label` is a plausible activation mode label.
///
/// Restricts trigger names to ASCII letters, digits, and `-` so ordinary
/// hosts (`www.example.com`, `api.example.com`, …) are not accidentally
/// interpreted as triggers.
fn is_valid_mode_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Parse the `X-Proxy-Control` header into a list of activation mode names.
///
/// Values are split on commas, trimmed, lower-cased, and empty tokens are
/// dropped. Returns an empty vector when the header is absent.
pub fn parse_header_modes(headers: &HeaderMap) -> Vec<String> {
    headers
        .get(ACTIVATION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(',')
                .map(|m| m.trim().to_ascii_lowercase())
                .filter(|m| !m.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Remove the activation header before the request is forwarded upstream.
///
/// The header is proxy-internal — leaking it to origin servers would expose
/// the browser extension's presence and provide a fingerprinting vector.
pub fn strip_activation_header(headers: &mut HeaderMap) {
    headers.remove(ACTIVATION_HEADER);
}

/// Merge subdomain and header modes into a deduplicated list, preserving
/// first-seen order.
pub fn merge_modes(subdomain_mode: Option<&str>, header_modes: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(m) = subdomain_mode
        && !m.is_empty()
    {
        out.push(m.to_ascii_lowercase());
    }
    for m in header_modes {
        let normalised = m.to_ascii_lowercase();
        if !normalised.is_empty() && !out.contains(&normalised) {
            out.push(normalised);
        }
    }
    out
}

/// Translate a single activation mode into the [`RewriteOp`]s it should emit.
///
/// Unknown modes yield an empty vector so a stray `X-Proxy-Control` value can
/// never crash the pipeline. `raw` also yields no ops — it is signalled to
/// the pipeline separately via [`is_raw`].
pub fn mode_to_ops(mode: &str) -> Vec<RewriteOp> {
    match mode {
        "reader" => vec![RewriteOp::ReaderMode],
        "block" => vec![RewriteOp::BlockPage],
        RAW_MODE => Vec::new(),
        other => {
            tracing::debug!(mode = %other, "unknown activation mode, ignoring");
            Vec::new()
        }
    }
}

/// Expand a list of modes into the union of their [`RewriteOp`]s.
pub fn modes_to_ops(modes: &[String]) -> Vec<RewriteOp> {
    modes.iter().flat_map(|m| mode_to_ops(m)).collect()
}

/// Return `true` when the mode list contains a pass-through request.
///
/// Callers should skip Starlark rule evaluation, cosmetic CSS injection, and
/// HTML rewriting when this is `true`.
pub fn is_raw(modes: &[String]) -> bool {
    modes.iter().any(|m| m == RAW_MODE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::HeaderMap;
    use hyper::header::{HeaderName, HeaderValue};

    // ─── parse_host_trigger ───────────────────────────────────────────────

    #[test]
    fn test_parse_host_trigger_reader_https() {
        let t = parse_host_trigger("reader.https.example.com").expect("trigger");
        assert_eq!(t.mode, "reader");
        assert_eq!(t.target_host, "example.com");
        assert_eq!(t.target_port, 443);
        assert!(t.upstream_https);
    }

    #[test]
    fn test_parse_host_trigger_http_proto() {
        let t = parse_host_trigger("block.http.internal.lan").expect("trigger");
        assert_eq!(t.mode, "block");
        assert_eq!(t.target_host, "internal.lan");
        assert_eq!(t.target_port, 80);
        assert!(!t.upstream_https);
    }

    #[test]
    fn test_parse_host_trigger_multi_label_target() {
        let t = parse_host_trigger("reader.https.old.reddit.com").expect("trigger");
        assert_eq!(t.mode, "reader");
        assert_eq!(t.target_host, "old.reddit.com");
        assert_eq!(t.target_port, 443);
    }

    #[test]
    fn test_parse_host_trigger_mode_lowercased() {
        let t = parse_host_trigger("READER.https.example.com").expect("trigger");
        assert_eq!(t.mode, "reader");
        assert_eq!(t.target_host, "example.com");
    }

    #[test]
    fn test_parse_host_trigger_no_proto_label() {
        assert!(parse_host_trigger("reader.example.com").is_none());
    }

    #[test]
    fn test_parse_host_trigger_bad_proto() {
        assert!(parse_host_trigger("reader.ftp.example.com").is_none());
    }

    #[test]
    fn test_parse_host_trigger_bare_domain() {
        assert!(parse_host_trigger("example.com").is_none());
    }

    #[test]
    fn test_parse_host_trigger_single_label() {
        assert!(parse_host_trigger("example").is_none());
    }

    #[test]
    fn test_parse_host_trigger_target_must_have_dot() {
        // Refuses `reader.https.localhost` — target label must look like a domain.
        assert!(parse_host_trigger("reader.https.localhost").is_none());
    }

    #[test]
    fn test_parse_host_trigger_empty_mode() {
        assert!(parse_host_trigger(".https.example.com").is_none());
    }

    #[test]
    fn test_parse_host_trigger_invalid_mode_char() {
        // Mode label containing '_' — reject to avoid catching real subdomains.
        assert!(parse_host_trigger("read_er.https.example.com").is_none());
    }

    #[test]
    fn test_parse_host_trigger_no_trigger_for_ordinary_subdomain() {
        assert!(parse_host_trigger("www.example.com").is_none());
        assert!(parse_host_trigger("api.v2.example.com").is_none());
    }

    // ─── parse_header_modes ───────────────────────────────────────────────

    fn header_map_with(name: &'static str, value: &'static str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
        h
    }

    #[test]
    fn test_parse_header_modes_absent() {
        let h = HeaderMap::new();
        assert!(parse_header_modes(&h).is_empty());
    }

    #[test]
    fn test_parse_header_modes_single() {
        let h = header_map_with("x-proxy-control", "reader");
        assert_eq!(parse_header_modes(&h), vec!["reader".to_owned()]);
    }

    #[test]
    fn test_parse_header_modes_multi() {
        let h = header_map_with("x-proxy-control", "reader, raw ,block");
        assert_eq!(
            parse_header_modes(&h),
            vec!["reader".to_owned(), "raw".to_owned(), "block".to_owned()]
        );
    }

    #[test]
    fn test_parse_header_modes_lowercased() {
        let h = header_map_with("x-proxy-control", "READER,Block");
        assert_eq!(
            parse_header_modes(&h),
            vec!["reader".to_owned(), "block".to_owned()]
        );
    }

    #[test]
    fn test_parse_header_modes_empty_tokens_dropped() {
        let h = header_map_with("x-proxy-control", " , reader,, ");
        assert_eq!(parse_header_modes(&h), vec!["reader".to_owned()]);
    }

    // ─── strip_activation_header ──────────────────────────────────────────

    #[test]
    fn test_strip_activation_header_removes_only_target() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("x-proxy-control"),
            HeaderValue::from_static("reader"),
        );
        h.insert(
            HeaderName::from_static("user-agent"),
            HeaderValue::from_static("Mozilla/5.0"),
        );
        strip_activation_header(&mut h);
        assert!(h.get("x-proxy-control").is_none());
        assert!(h.get("user-agent").is_some());
    }

    #[test]
    fn test_strip_activation_header_noop_when_absent() {
        let mut h = HeaderMap::new();
        h.insert(
            HeaderName::from_static("authorization"),
            HeaderValue::from_static("Bearer x"),
        );
        strip_activation_header(&mut h);
        assert!(h.get("authorization").is_some());
    }

    // ─── merge_modes ──────────────────────────────────────────────────────

    #[test]
    fn test_merge_modes_subdomain_only() {
        assert_eq!(merge_modes(Some("reader"), &[]), vec!["reader".to_owned()]);
    }

    #[test]
    fn test_merge_modes_header_only() {
        let out = merge_modes(None, &["reader".to_owned(), "raw".to_owned()]);
        assert_eq!(out, vec!["reader".to_owned(), "raw".to_owned()]);
    }

    #[test]
    fn test_merge_modes_additive() {
        let out = merge_modes(Some("reader"), &["block".to_owned()]);
        assert_eq!(out, vec!["reader".to_owned(), "block".to_owned()]);
    }

    #[test]
    fn test_merge_modes_dedup_preserves_first_seen_order() {
        let out = merge_modes(
            Some("reader"),
            &["READER".to_owned(), "block".to_owned(), "block".to_owned()],
        );
        assert_eq!(out, vec!["reader".to_owned(), "block".to_owned()]);
    }

    #[test]
    fn test_merge_modes_empty() {
        assert!(merge_modes(None, &[]).is_empty());
    }

    #[test]
    fn test_merge_modes_ignores_empty_subdomain() {
        let out = merge_modes(Some(""), &["reader".to_owned()]);
        assert_eq!(out, vec!["reader".to_owned()]);
    }

    // ─── mode_to_ops / modes_to_ops ───────────────────────────────────────

    #[test]
    fn test_mode_to_ops_reader() {
        assert_eq!(mode_to_ops("reader"), vec![RewriteOp::ReaderMode]);
    }

    #[test]
    fn test_mode_to_ops_block() {
        assert_eq!(mode_to_ops("block"), vec![RewriteOp::BlockPage]);
    }

    #[test]
    fn test_mode_to_ops_raw_is_empty() {
        assert!(mode_to_ops("raw").is_empty());
    }

    #[test]
    fn test_mode_to_ops_unknown_is_empty() {
        assert!(mode_to_ops("nonsense").is_empty());
    }

    #[test]
    fn test_modes_to_ops_combines_modes() {
        let ops = modes_to_ops(&["reader".to_owned(), "block".to_owned()]);
        assert_eq!(ops, vec![RewriteOp::ReaderMode, RewriteOp::BlockPage]);
    }

    #[test]
    fn test_modes_to_ops_skips_raw_and_unknown() {
        let ops = modes_to_ops(&["raw".to_owned(), "reader".to_owned(), "unknown".to_owned()]);
        assert_eq!(ops, vec![RewriteOp::ReaderMode]);
    }

    // ─── is_raw ───────────────────────────────────────────────────────────

    #[test]
    fn test_is_raw_true_when_present() {
        assert!(is_raw(&["raw".to_owned()]));
        assert!(is_raw(&["reader".to_owned(), "raw".to_owned()]));
    }

    #[test]
    fn test_is_raw_false_otherwise() {
        assert!(!is_raw(&[]));
        assert!(!is_raw(&["reader".to_owned()]));
        assert!(!is_raw(&["block".to_owned()]));
    }
}
