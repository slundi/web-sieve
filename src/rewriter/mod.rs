//! Streaming HTML rewriting pipeline using lol-html.

use std::borrow::Cow;

pub use lol_html::errors::RewritingError;
use lol_html::html_content::{ContentType, Element};
use lol_html::{ElementContentHandlers, HtmlRewriter, Selector, Settings};

/// Operations that can be applied to an HTML document.
#[derive(Debug, Clone, PartialEq)]
pub enum RewriteOp {
    /// Remove all elements matching a CSS selector from the DOM.
    RemoveElement(String),
    /// Inject a `<style>` block into the document `<head>`.
    InjectStyle(String),
    /// Use CSS to hide all body children that do NOT match this selector.
    KeepOnly(String),
    /// Invoke the readability engine to extract the main article, replacing the
    /// entire document with a minimal reader-mode template.
    ReaderMode,
    /// Fire-and-forget HTTP POST webhook — sent as a side-effect; does not alter
    /// the document.
    Webhook { url: String, body: String },
    /// Block the page entirely; the proxy returns 403 instead of the content.
    /// Handled at the proxy layer — `apply` ignores this variant.
    BlockPage,
}

/// Apply a sequence of [`RewriteOp`]s to an HTML document in a single streaming pass.
///
/// Returns the rewritten bytes on success. If `ops` is empty, the input is
/// returned as-is without any rewriting overhead.
///
/// # Errors
///
/// Returns [`RewritingError`] if lol-html encounters a fatal parsing error.
pub fn apply(ops: &[RewriteOp], html: &[u8]) -> Result<Vec<u8>, RewritingError> {
    if ops.is_empty() {
        return Ok(html.to_vec());
    }

    // Reader mode optionally replaces the entire document.
    let reader_buf: Option<Vec<u8>> = if ops.iter().any(|o| matches!(o, RewriteOp::ReaderMode)) {
        let html_str = String::from_utf8_lossy(html);
        crate::reader::extract(&html_str).map(|a| crate::reader::render(&a))
    } else {
        None
    };
    let working: &[u8] = reader_buf.as_deref().unwrap_or(html);

    // Build lol-html element handlers (skip ReaderMode / Webhook / BlockPage).
    let mut output = Vec::with_capacity(working.len());
    let mut element_handlers: Vec<(Cow<'static, Selector>, ElementContentHandlers<'_>)> =
        Vec::new();

    for op in ops {
        match op {
            RewriteOp::ReaderMode | RewriteOp::Webhook { .. } | RewriteOp::BlockPage => {}
            RewriteOp::RemoveElement(sel) => {
                let selector: Selector = match sel.parse() {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(selector = %sel, error = %e, "invalid CSS selector in RemoveElement op, skipping");
                        continue;
                    }
                };
                let handler = ElementContentHandlers::default().element(|el: &mut Element| {
                    el.remove();
                    Ok(())
                });
                element_handlers.push((Cow::Owned(selector), handler));
            }
            RewriteOp::InjectStyle(css) => {
                let css_owned = css.clone();
                let selector: Selector = match "head".parse() {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "unexpected error parsing 'head' selector");
                        continue;
                    }
                };
                let handler = ElementContentHandlers::default().element(move |el: &mut Element| {
                    el.append(&format!("<style>{css_owned}</style>"), ContentType::Html);
                    Ok(())
                });
                element_handlers.push((Cow::Owned(selector), handler));
            }
            RewriteOp::KeepOnly(sel) => {
                let sel_owned = sel.clone();
                let selector: Selector = match "head".parse() {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = %e, "unexpected error parsing 'head' selector");
                        continue;
                    }
                };
                let handler = ElementContentHandlers::default().element(move |el: &mut Element| {
                    el.append(
                        &format!(
                            "<style>body>*:not({sel_owned}){{display:none!important}}</style>"
                        ),
                        ContentType::Html,
                    );
                    Ok(())
                });
                element_handlers.push((Cow::Owned(selector), handler));
            }
        }
    }

    if element_handlers.is_empty() {
        return Ok(working.to_vec());
    }

    {
        let mut settings = Settings::new();
        for (selector, handler) in element_handlers {
            settings = settings.append_element_content_handler((selector, handler));
        }

        let mut rewriter = HtmlRewriter::new(settings, |chunk: &[u8]| {
            output.extend_from_slice(chunk);
        });

        rewriter.write(working)?;
        rewriter.end()?;
    }

    Ok(output)
}

/// Send an HTTP POST webhook asynchronously. Errors are logged and swallowed.
///
/// Intended to be spawned with `tokio::spawn` so delivery never blocks the
/// proxy response path or its `spawn_blocking` thread pool.
pub async fn fire_webhook(url: String, body: String) {
    if let Err(e) = reqwest::Client::new()
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
    {
        tracing::warn!(url = %url, error = %e, "webhook delivery failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_empty_ops_returns_input() {
        let html = b"<html><body><p>hello</p></body></html>";
        let result = apply(&[], html).expect("apply");
        assert_eq!(result, html);
    }

    #[test]
    fn test_remove_element() {
        let html = b"<html><body><div class=\"ads\">x</div><p>keep</p></body></html>";
        let ops = vec![RewriteOp::RemoveElement("div.ads".to_string())];
        let result = apply(&ops, html).expect("apply");
        let output = String::from_utf8(result).expect("utf8");
        assert!(!output.contains("ads"), "ads div should be removed");
        assert!(
            output.contains("<p>keep</p>"),
            "keep paragraph should remain"
        );
    }

    #[test]
    fn test_inject_style() {
        let html = b"<html><head></head><body>hello</body></html>";
        let ops = vec![RewriteOp::InjectStyle("body{color:red}".to_string())];
        let result = apply(&ops, html).expect("apply");
        let output = String::from_utf8(result).expect("utf8");
        assert!(
            output.contains("<style>body{color:red}</style>"),
            "style should be injected: {output}"
        );
    }

    #[test]
    fn test_keep_only_injects_css() {
        let html = b"<html><head></head><body><div class=\"main\">content</div><div class=\"ads\">ads</div></body></html>";
        let ops = vec![RewriteOp::KeepOnly(".main".to_string())];
        let result = apply(&ops, html).expect("apply");
        let output = String::from_utf8(result).expect("utf8");
        assert!(
            output.contains("display:none"),
            "keep_only should inject display:none css: {output}"
        );
    }

    #[test]
    fn test_webhook_op_is_noop_in_apply() {
        let html = b"<html><body>hello</body></html>";
        let ops = vec![RewriteOp::Webhook {
            url: "http://example.com/hook".to_string(),
            body: r#"{"event":"test"}"#.to_string(),
        }];
        let result = apply(&ops, html).expect("apply");
        assert_eq!(result, html, "webhook op must not modify HTML");
    }

    #[tokio::test]
    async fn test_fire_webhook_sends_post() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}/hook");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            request
        });

        fire_webhook(url, r#"{"event":"test"}"#.to_string()).await;

        let request = server.await.unwrap();
        assert!(
            request.starts_with("POST /hook"),
            "expected POST /hook, got: {request}"
        );
        assert!(
            request.contains("application/json"),
            "missing Content-Type: {request}"
        );
        assert!(
            request.contains(r#"{"event":"test"}"#),
            "missing body: {request}"
        );
    }

    #[test]
    fn test_reader_mode_extracts_article() {
        let html = b"<html><head><title>My Post</title></head><body>\
        <article class=\"content\">\
        <h2>Hello</h2>\
        <p>This is a substantial article body with enough text to pass the scoring threshold \
        and be selected as the best candidate block by the readability algorithm.</p>\
        </article>\
        <aside class=\"sidebar\"><a href=\"/a\">a</a></aside>\
        </body></html>";
        let ops = vec![RewriteOp::ReaderMode];
        let result = apply(&ops, html).expect("apply");
        let output = String::from_utf8(result).expect("utf8");
        assert!(
            output.contains("<!DOCTYPE html>"),
            "should be full reader template: {output}"
        );
        assert!(
            output.contains("Hello"),
            "article content should be present: {output}"
        );
    }
}
