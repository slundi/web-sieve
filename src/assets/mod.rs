//! Static asset resolution for the local `webprism.local` endpoint.
//!
//! The proxy answers requests whose `Host` matches the configured asset host
//! directly, without contacting any upstream — so no DNS record and no
//! `/etc/hosts` entry are needed. Everything under `/assets/…` resolves to a
//! file from one of two roots:
//!
//! * **Shared assets** — the XDG data directory (`css/`, `js/`, `fonts/`,
//!   `scripts/`, `templates/`, …), so users can add or override files.
//! * **Per-script assets** — a community script's own folder under the rules
//!   directory (`rules/<script>/` holding the `.star` plus its `icon`, `css`,
//!   `js`), served at `/assets/<script>/…`.
//!
//! Per-script assets win over shared ones for namespaced references, so a
//! script can ship a file without worrying about colliding with a shared name.
//!
//! Files are read from disk on every request rather than cached, which makes
//! edits take effect immediately — the same hot-reload behaviour a watcher
//! would provide, without the staleness window.
//!
//! # Path safety
//!
//! Request paths are percent-decoded, then every segment is validated:
//! traversal (`..`), dotfiles, backslashes, and NUL bytes are rejected. The
//! resolved path is canonicalised and must still live under its root, so a
//! symlink pointing outside the asset directories cannot be followed.

use std::path::{Path, PathBuf};

/// Default hostname the proxy answers locally for static assets.
pub const DEFAULT_ASSET_HOST: &str = "webprism.local";

/// URL path prefix under which all assets are served.
pub const ASSET_PREFIX: &str = "/assets/";

/// A resolved asset ready to be written into an HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// File contents.
    pub bytes: Vec<u8>,
    /// MIME type derived from the file extension.
    pub content_type: &'static str,
}

/// Strip the `/assets/` prefix from a request path.
///
/// Returns `None` for any path outside the asset namespace.
pub fn strip_asset_prefix(path: &str) -> Option<&str> {
    path.strip_prefix(ASSET_PREFIX)
}

/// Remove a trailing `:port` from a `Host` header value, leaving IPv6 literals
/// (`[::1]`) intact.
fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        return match host.find(']') {
            Some(end) => &host[..=end],
            None => host,
        };
    }
    match host.rsplit_once(':') {
        Some((bare, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => bare,
        _ => host,
    }
}

/// Decode `%XX` escapes in a URL path segment.
///
/// Returns `None` for a truncated or non-hex escape, or when the result is not
/// valid UTF-8 — both are malformed input that must not reach the filesystem.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let high = (hex[0] as char).to_digit(16)?;
            let low = (hex[1] as char).to_digit(16)?;
            out.push((high * 16 + low) as u8);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-decode `raw` and validate it as a safe relative path.
///
/// Empty and `.` segments are collapsed. Anything that could escape the asset
/// root or expose a hidden file — `..`, a leading dot, a backslash, a NUL — is
/// rejected outright rather than sanitised, so a crafted path fails closed.
fn sanitize_relative_path(raw: &str) -> Option<String> {
    let decoded = percent_decode(raw)?;
    if decoded.contains('\0') {
        return None;
    }

    let mut segments: Vec<&str> = Vec::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => continue,
            s if s.starts_with('.') => return None,
            s if s.contains('\\') => return None,
            s => segments.push(s),
        }
    }

    if segments.is_empty() {
        return None;
    }
    Some(segments.join("/"))
}

/// Extensions never served, whatever root they resolve under.
///
/// A per-script folder holds its `.star` rule next to the `icon`, `css`, and
/// `js` it ships, and that folder is served wholesale. Rule sources are logic,
/// not assets — and may embed webhook URLs or tokens — so they are withheld.
const DENIED_EXTENSIONS: &[&str] = &["star"];

/// Return `true` when `path` has an extension that must never be served.
fn is_denied(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            DENIED_EXTENSIONS
                .iter()
                .any(|denied| ext.eq_ignore_ascii_case(denied))
        })
}

/// Resolve `rel` under `root`, proving the result is an existing regular file
/// that has not escaped the root via a symlink.
fn resolve_under(root: &Path, rel: &str) -> Option<PathBuf> {
    let canonical_root = root.canonicalize().ok()?;
    let candidate = canonical_root.join(rel).canonicalize().ok()?;
    if !candidate.starts_with(&canonical_root) {
        tracing::warn!(
            path = %candidate.display(),
            root = %canonical_root.display(),
            "asset resolved outside its root, refusing"
        );
        return None;
    }
    if !candidate.is_file() {
        return None;
    }
    Some(candidate)
}

/// Map a file extension to a MIME type.
///
/// Unknown extensions fall back to `application/octet-stream`, which browsers
/// will download rather than execute.
pub fn content_type_for(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    match extension.as_str() {
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "html" | "htm" => "text/html; charset=utf-8",
        "txt" | "md" => "text/plain; charset=utf-8",
        "xml" => "application/xml; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Resolves static assets for the local endpoint and decides CORS exposure.
///
/// # Examples
///
/// ```
/// use std::path::PathBuf;
/// use web_sieve::assets::AssetServer;
///
/// let server = AssetServer::new(
///     "webprism.local".to_string(),
///     PathBuf::from("/var/empty/data"),
///     PathBuf::from("/var/empty/rules"),
///     Vec::new(),
/// );
/// assert!(server.matches_host("webprism.local:443"));
/// assert!(!server.matches_host("example.com"));
/// ```
#[derive(Debug, Clone)]
pub struct AssetServer {
    /// Hostname answered locally (compared case-insensitively, port ignored).
    host: String,
    /// Shared asset root — the XDG data directory.
    shared_root: PathBuf,
    /// Per-script asset root — the Starlark rules directory.
    scripts_root: PathBuf,
    /// Origins allowed to read assets cross-origin. Empty means same-origin only.
    cors_allow_origins: Vec<String>,
}

impl AssetServer {
    /// Create an [`AssetServer`].
    ///
    /// `cors_allow_origins` may contain `*` to allow any origin; an empty list
    /// keeps assets same-origin, which is the default.
    pub fn new(
        host: String,
        shared_root: PathBuf,
        scripts_root: PathBuf,
        cors_allow_origins: Vec<String>,
    ) -> Self {
        Self {
            host,
            shared_root,
            scripts_root,
            cors_allow_origins,
        }
    }

    /// Return the hostname this server answers.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return `true` when `host` (with or without a port) is the asset host.
    pub fn matches_host(&self, host: &str) -> bool {
        strip_port(host).eq_ignore_ascii_case(&self.host)
    }

    /// Resolve an asset-relative path (everything after `/assets/`) to a file.
    ///
    /// Per-script assets under the rules directory take precedence over shared
    /// assets for namespaced paths (`<script>/<file>`). Returns `None` when the
    /// path is unsafe or no file exists under either root.
    pub fn resolve(&self, rel_path: &str) -> Option<PathBuf> {
        let safe = sanitize_relative_path(rel_path)?;
        if is_denied(Path::new(&safe)) {
            tracing::debug!(asset = %safe, "refusing to serve a rule source file");
            return None;
        }

        // A namespaced reference may name a per-script folder; those win.
        if safe.contains('/')
            && let Some(path) = resolve_under(&self.scripts_root, &safe)
        {
            return Some(path);
        }

        resolve_under(&self.shared_root, &safe)
    }

    /// Read an asset and tag it with a MIME type.
    ///
    /// Returns `None` when the path does not resolve or the file cannot be read.
    pub async fn load(&self, rel_path: &str) -> Option<Asset> {
        let path = self.resolve(rel_path)?;
        let content_type = content_type_for(&path);
        match tokio::fs::read(&path).await {
            Ok(bytes) => Some(Asset {
                bytes,
                content_type,
            }),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read asset");
                None
            }
        }
    }

    /// Read an asset as UTF-8 text, for inlining into a template.
    ///
    /// Synchronous because Minijinja rendering runs on the blocking pool.
    pub fn read_text(&self, rel_path: &str) -> Option<String> {
        let path = self.resolve(rel_path)?;
        std::fs::read_to_string(&path).ok()
    }

    /// Decide the `Access-Control-Allow-Origin` value for a request.
    ///
    /// Returns `None` — meaning no CORS header, so same-origin only — unless
    /// the allowlist contains `*` or the request's `Origin` explicitly.
    pub fn cors_allow_origin(&self, origin: Option<&str>) -> Option<String> {
        if self.cors_allow_origins.iter().any(|o| o == "*") {
            return Some("*".to_string());
        }
        let origin = origin?;
        self.cors_allow_origins
            .iter()
            .find(|allowed| allowed.eq_ignore_ascii_case(origin))
            .map(|_| origin.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_with(shared: &Path, scripts: &Path, cors: Vec<String>) -> AssetServer {
        AssetServer::new(
            DEFAULT_ASSET_HOST.to_string(),
            shared.to_path_buf(),
            scripts.to_path_buf(),
            cors,
        )
    }

    // ─── strip_asset_prefix ───────────────────────────────────────────────

    #[test]
    fn test_strip_asset_prefix_matches() {
        assert_eq!(strip_asset_prefix("/assets/css/x.css"), Some("css/x.css"));
    }

    #[test]
    fn test_strip_asset_prefix_rejects_other_paths() {
        assert!(strip_asset_prefix("/index.html").is_none());
        assert!(strip_asset_prefix("/assets").is_none());
    }

    // ─── strip_port ───────────────────────────────────────────────────────

    #[test]
    fn test_strip_port_removes_numeric_port() {
        assert_eq!(strip_port("webprism.local:443"), "webprism.local");
        assert_eq!(strip_port("webprism.local"), "webprism.local");
    }

    #[test]
    fn test_strip_port_keeps_non_numeric_suffix() {
        assert_eq!(strip_port("host:notaport"), "host:notaport");
    }

    #[test]
    fn test_strip_port_handles_ipv6_literal() {
        assert_eq!(strip_port("[::1]:8080"), "[::1]");
        assert_eq!(strip_port("[::1]"), "[::1]");
    }

    // ─── percent_decode ───────────────────────────────────────────────────

    #[test]
    fn test_percent_decode_plain_and_escaped() {
        assert_eq!(percent_decode("a/b.css").as_deref(), Some("a/b.css"));
        assert_eq!(percent_decode("a%2Fb").as_deref(), Some("a/b"));
        assert_eq!(percent_decode("sp%20ace").as_deref(), Some("sp ace"));
    }

    #[test]
    fn test_percent_decode_rejects_malformed() {
        assert!(percent_decode("%2").is_none(), "truncated escape");
        assert!(percent_decode("%zz").is_none(), "non-hex escape");
    }

    // ─── sanitize_relative_path ───────────────────────────────────────────

    #[test]
    fn test_sanitize_accepts_normal_path() {
        assert_eq!(
            sanitize_relative_path("css/reader.css").as_deref(),
            Some("css/reader.css")
        );
    }

    #[test]
    fn test_sanitize_collapses_empty_and_dot_segments() {
        assert_eq!(
            sanitize_relative_path("css//./reader.css").as_deref(),
            Some("css/reader.css")
        );
    }

    #[test]
    fn test_sanitize_rejects_traversal() {
        assert!(sanitize_relative_path("../ca.key").is_none());
        assert!(sanitize_relative_path("css/../../ca.key").is_none());
    }

    #[test]
    fn test_sanitize_rejects_percent_encoded_traversal() {
        assert!(
            sanitize_relative_path("%2e%2e/ca.key").is_none(),
            "encoded .. must be rejected after decoding"
        );
        assert!(sanitize_relative_path("css/%2E%2E/ca.key").is_none());
    }

    #[test]
    fn test_sanitize_rejects_dotfiles() {
        assert!(sanitize_relative_path(".env").is_none());
        assert!(sanitize_relative_path("css/.secret").is_none());
    }

    #[test]
    fn test_sanitize_rejects_backslash_and_nul() {
        assert!(sanitize_relative_path("css\\..\\ca.key").is_none());
        assert!(sanitize_relative_path("css/%00x").is_none());
    }

    #[test]
    fn test_sanitize_rejects_empty() {
        assert!(sanitize_relative_path("").is_none());
        assert!(sanitize_relative_path("///").is_none());
    }

    // ─── content_type_for ─────────────────────────────────────────────────

    #[test]
    fn test_content_type_known_extensions() {
        assert_eq!(
            content_type_for(Path::new("a.css")),
            "text/css; charset=utf-8"
        );
        assert_eq!(
            content_type_for(Path::new("a.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(content_type_for(Path::new("a.woff2")), "font/woff2");
        assert_eq!(content_type_for(Path::new("a.svg")), "image/svg+xml");
        assert_eq!(content_type_for(Path::new("a.PNG")), "image/png");
    }

    #[test]
    fn test_content_type_unknown_is_octet_stream() {
        assert_eq!(
            content_type_for(Path::new("a.unknownext")),
            "application/octet-stream"
        );
        assert_eq!(
            content_type_for(Path::new("noext")),
            "application/octet-stream"
        );
    }

    // ─── matches_host ─────────────────────────────────────────────────────

    #[test]
    fn test_matches_host_ignores_case_and_port() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let server = server_with(tmp.path(), tmp.path(), Vec::new());
        assert!(server.matches_host("webprism.local"));
        assert!(server.matches_host("WebPrism.Local"));
        assert!(server.matches_host("webprism.local:443"));
        assert!(!server.matches_host("example.com"));
        assert!(!server.matches_host("sub.webprism.local"));
    }

    // ─── resolve ──────────────────────────────────────────────────────────

    #[test]
    fn test_resolve_finds_shared_asset() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        std::fs::create_dir_all(shared.path().join("css")).expect("mkdir");
        std::fs::write(shared.path().join("css/site.css"), "body{}").expect("write");

        let server = server_with(shared.path(), scripts.path(), Vec::new());
        let resolved = server.resolve("css/site.css").expect("resolve");
        assert!(resolved.ends_with("css/site.css"));
    }

    #[test]
    fn test_resolve_per_script_asset_wins_over_shared() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        std::fs::create_dir_all(shared.path().join("nyaa")).expect("mkdir shared");
        std::fs::write(shared.path().join("nyaa/style.css"), "SHARED").expect("write shared");
        std::fs::create_dir_all(scripts.path().join("nyaa")).expect("mkdir script");
        std::fs::write(scripts.path().join("nyaa/style.css"), "SCRIPT").expect("write script");

        let server = server_with(shared.path(), scripts.path(), Vec::new());
        let text = server.read_text("nyaa/style.css").expect("read");
        assert_eq!(text, "SCRIPT", "per-script asset must take precedence");
    }

    #[test]
    fn test_resolve_falls_back_to_shared_when_script_asset_absent() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        std::fs::create_dir_all(shared.path().join("nyaa")).expect("mkdir");
        std::fs::write(shared.path().join("nyaa/style.css"), "SHARED").expect("write");

        let server = server_with(shared.path(), scripts.path(), Vec::new());
        assert_eq!(
            server.read_text("nyaa/style.css").as_deref(),
            Some("SHARED")
        );
    }

    #[test]
    fn test_resolve_unnamespaced_path_skips_scripts_root() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        std::fs::write(scripts.path().join("loose.css"), "SCRIPT").expect("write");

        let server = server_with(shared.path(), scripts.path(), Vec::new());
        assert!(
            server.resolve("loose.css").is_none(),
            "a bare file name must not reach the rules directory"
        );
    }

    #[test]
    fn test_resolve_refuses_star_rule_sources() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        std::fs::create_dir_all(scripts.path().join("nyaa")).expect("mkdir");
        std::fs::write(
            scripts.path().join("nyaa/nyaa.star"),
            "webhook(\"http://localhost/?token=SECRET\", \"{}\")",
        )
        .expect("write rule");

        let server = server_with(shared.path(), scripts.path(), Vec::new());
        assert!(
            server.resolve("nyaa/nyaa.star").is_none(),
            "rule sources must not be downloadable"
        );
        assert!(
            server.resolve("nyaa/NYAA.STAR").is_none(),
            "match is case-insensitive"
        );
    }

    #[test]
    fn test_resolve_missing_file_is_none() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        let server = server_with(shared.path(), scripts.path(), Vec::new());
        assert!(server.resolve("css/absent.css").is_none());
    }

    #[test]
    fn test_resolve_directory_is_none() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        std::fs::create_dir_all(shared.path().join("css")).expect("mkdir");

        let server = server_with(shared.path(), scripts.path(), Vec::new());
        assert!(
            server.resolve("css").is_none(),
            "a directory must not be served"
        );
    }

    #[test]
    fn test_resolve_rejects_traversal_to_real_file() {
        let base = tempfile::tempdir().expect("base");
        let shared = base.path().join("data");
        let scripts = base.path().join("rules");
        std::fs::create_dir_all(&shared).expect("mkdir shared");
        std::fs::create_dir_all(&scripts).expect("mkdir scripts");
        // A genuinely sensitive sibling file that traversal would otherwise reach.
        std::fs::write(base.path().join("ca.key"), "SECRET").expect("write secret");

        let server = server_with(&shared, &scripts, Vec::new());
        assert!(server.resolve("../ca.key").is_none());
        assert!(server.resolve("%2e%2e/ca.key").is_none());
        assert!(server.read_text("../ca.key").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_rejects_symlink_escaping_root() {
        let base = tempfile::tempdir().expect("base");
        let shared = base.path().join("data");
        let scripts = base.path().join("rules");
        std::fs::create_dir_all(&shared).expect("mkdir shared");
        std::fs::create_dir_all(&scripts).expect("mkdir scripts");
        std::fs::write(base.path().join("ca.key"), "SECRET").expect("write secret");
        std::os::unix::fs::symlink(base.path().join("ca.key"), shared.join("leak.key"))
            .expect("symlink");

        let server = server_with(&shared, &scripts, Vec::new());
        assert!(
            server.resolve("leak.key").is_none(),
            "a symlink pointing outside the root must not be followed"
        );
    }

    // ─── load ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_load_returns_bytes_and_content_type() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        std::fs::create_dir_all(shared.path().join("js")).expect("mkdir");
        std::fs::write(shared.path().join("js/app.js"), "console.log(1)").expect("write");

        let server = server_with(shared.path(), scripts.path(), Vec::new());
        let asset = server.load("js/app.js").await.expect("load");
        assert_eq!(asset.bytes, b"console.log(1)");
        assert_eq!(asset.content_type, "text/javascript; charset=utf-8");
    }

    #[tokio::test]
    async fn test_load_missing_is_none() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        let server = server_with(shared.path(), scripts.path(), Vec::new());
        assert!(server.load("js/absent.js").await.is_none());
    }

    #[tokio::test]
    async fn test_load_reflects_edits_without_restart() {
        let shared = tempfile::tempdir().expect("shared");
        let scripts = tempfile::tempdir().expect("scripts");
        std::fs::create_dir_all(shared.path().join("css")).expect("mkdir");
        let path = shared.path().join("css/site.css");
        std::fs::write(&path, "v1").expect("write");

        let server = server_with(shared.path(), scripts.path(), Vec::new());
        assert_eq!(server.load("css/site.css").await.expect("v1").bytes, b"v1");

        std::fs::write(&path, "v2").expect("rewrite");
        assert_eq!(
            server.load("css/site.css").await.expect("v2").bytes,
            b"v2",
            "assets are read per request, so edits are live"
        );
    }

    // ─── cors_allow_origin ────────────────────────────────────────────────

    #[test]
    fn test_cors_default_is_same_origin_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let server = server_with(tmp.path(), tmp.path(), Vec::new());
        assert!(server.cors_allow_origin(None).is_none());
        assert!(
            server
                .cors_allow_origin(Some("https://example.com"))
                .is_none()
        );
    }

    #[test]
    fn test_cors_allowlisted_origin_is_echoed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let server = server_with(
            tmp.path(),
            tmp.path(),
            vec!["https://example.com".to_string()],
        );
        assert_eq!(
            server
                .cors_allow_origin(Some("https://example.com"))
                .as_deref(),
            Some("https://example.com")
        );
        assert!(
            server
                .cors_allow_origin(Some("https://evil.test"))
                .is_none(),
            "an origin outside the allowlist gets no CORS header"
        );
    }

    #[test]
    fn test_cors_wildcard_allows_any_origin() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let server = server_with(tmp.path(), tmp.path(), vec!["*".to_string()]);
        assert_eq!(server.cors_allow_origin(None).as_deref(), Some("*"));
        assert_eq!(
            server
                .cors_allow_origin(Some("https://any.test"))
                .as_deref(),
            Some("*")
        );
    }

    #[test]
    fn test_cors_origin_match_is_case_insensitive() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let server = server_with(
            tmp.path(),
            tmp.path(),
            vec!["https://Example.COM".to_string()],
        );
        assert_eq!(
            server
                .cors_allow_origin(Some("https://example.com"))
                .as_deref(),
            Some("https://example.com")
        );
    }
}
