//! Streaming HTML rewriting pipeline using lol-html.

use std::borrow::Cow;

pub use lol_html::errors::RewritingError;
use lol_html::html_content::{ContentType, Element};
use lol_html::{ElementContentHandlers, HtmlRewriter, Selector, Settings};

use crate::templates::TemplateEngine;

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
    /// Replace the whole document with a Minijinja template rendered against a
    /// context object.
    ///
    /// `context` holds the JSON encoding of the Starlark dict passed to
    /// `render_template()`; keeping it as a string means a [`RewriteOp`] stays
    /// `Send` and comparable while Starlark values are neither.
    RenderTemplate {
        /// Template name — file name (`torrent-list.html`) or stem (`torrent-list`).
        name: String,
        /// JSON-encoded render context.
        context: String,
    },
}

/// Produce the replacement document for the whole-page ops, if any apply.
///
/// `RenderTemplate` takes precedence over `ReaderMode` because it is the more
/// specific instruction; when several templates are queued the last one wins,
/// mirroring "last writer wins" for the document as a whole. Any failure
/// (missing engine, unknown template, bad context, render error) is logged and
/// leaves the document untouched rather than serving a broken page.
fn replacement_document(
    ops: &[RewriteOp],
    html: &[u8],
    templates: Option<&TemplateEngine>,
) -> Option<Vec<u8>> {
    let last_template = ops.iter().rev().find_map(|op| match op {
        RewriteOp::RenderTemplate { name, context } => Some((name, context)),
        _ => None,
    });

    if let Some((name, context)) = last_template {
        match templates {
            None => tracing::warn!(
                template = %name,
                "render_template() ignored: no template engine configured"
            ),
            Some(engine) => match serde_json::from_str::<serde_json::Value>(context) {
                Ok(ctx) => match engine.render(name, &ctx) {
                    Ok(rendered) => return Some(rendered.into_bytes()),
                    Err(e) => {
                        tracing::warn!(template = %name, error = %e, "template render failed")
                    }
                },
                Err(e) => {
                    tracing::warn!(template = %name, error = %e, "invalid template context JSON")
                }
            },
        }
    }

    if ops.iter().any(|o| matches!(o, RewriteOp::ReaderMode)) {
        let html_str = String::from_utf8_lossy(html);
        return crate::reader::extract(&html_str).map(|a| crate::reader::render(&a));
    }

    None
}

/// Apply a sequence of [`RewriteOp`]s to an HTML document in a single streaming pass.
///
/// Equivalent to [`apply_with_templates`] without a template engine:
/// `RenderTemplate` ops are logged and skipped.
///
/// # Errors
///
/// Returns [`RewritingError`] if lol-html encounters a fatal parsing error.
pub fn apply(ops: &[RewriteOp], html: &[u8]) -> Result<Vec<u8>, RewritingError> {
    apply_with_templates(ops, html, None)
}

/// Apply a sequence of [`RewriteOp`]s, resolving `RenderTemplate` ops against
/// `templates`.
///
/// Returns the rewritten bytes on success. If `ops` is empty, the input is
/// returned as-is without any rewriting overhead.
///
/// # Errors
///
/// Returns [`RewritingError`] if lol-html encounters a fatal parsing error.
pub fn apply_with_templates(
    ops: &[RewriteOp],
    html: &[u8],
    templates: Option<&TemplateEngine>,
) -> Result<Vec<u8>, RewritingError> {
    if ops.is_empty() {
        return Ok(html.to_vec());
    }

    // Reader mode and template rendering optionally replace the whole document;
    // the DOM handlers below then run over the replacement.
    let replaced: Option<Vec<u8>> = replacement_document(ops, html, templates);
    let working: &[u8] = replaced.as_deref().unwrap_or(html);

    // Build lol-html element handlers (skip ReaderMode / Webhook / BlockPage).
    let mut output = Vec::with_capacity(working.len());
    let mut element_handlers: Vec<(Cow<'static, Selector>, ElementContentHandlers<'_>)> =
        Vec::new();

    for op in ops {
        match op {
            RewriteOp::ReaderMode
            | RewriteOp::Webhook { .. }
            | RewriteOp::BlockPage
            | RewriteOp::RenderTemplate { .. } => {}
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

    /// Build a [`TemplateEngine`] over a temp dir containing `files`.
    ///
    /// The tempdir is leaked so the engine's watcher keeps a live directory for
    /// the duration of the test.
    async fn engine_with(files: &[(&str, &str)]) -> std::sync::Arc<TemplateEngine> {
        let dir = tempfile::tempdir().expect("tempdir");
        for (name, body) in files {
            std::fs::write(dir.path().join(name), body).expect("write template");
        }
        let path = dir.path().to_path_buf();
        std::mem::forget(dir);
        TemplateEngine::new(path).await.expect("template engine")
    }

    #[tokio::test]
    async fn test_render_template_replaces_document() {
        let templates = engine_with(&[("page.html", "<main>{{ title }}</main>")]).await;
        let ops = vec![RewriteOp::RenderTemplate {
            name: "page".to_string(),
            context: r#"{"title":"Hello"}"#.to_string(),
        }];
        let result = apply_with_templates(
            &ops,
            b"<html><body>original</body></html>",
            Some(&templates),
        )
        .expect("apply");
        let output = String::from_utf8(result).expect("utf8");
        assert_eq!(output, "<main>Hello</main>");
    }

    #[tokio::test]
    async fn test_render_template_then_dom_ops_run_on_replacement() {
        let templates = engine_with(&[(
            "page.html",
            "<html><head></head><body><div class=\"x\">drop</div><p>keep</p></body></html>",
        )])
        .await;
        let ops = vec![
            RewriteOp::RenderTemplate {
                name: "page".to_string(),
                context: "{}".to_string(),
            },
            RewriteOp::RemoveElement("div.x".to_string()),
        ];
        let result = apply_with_templates(
            &ops,
            b"<html><body>original</body></html>",
            Some(&templates),
        )
        .expect("apply");
        let output = String::from_utf8(result).expect("utf8");
        assert!(
            !output.contains("drop"),
            "DOM op should run on the template output: {output}"
        );
        assert!(
            output.contains("<p>keep</p>"),
            "rest of template must survive: {output}"
        );
        assert!(
            !output.contains("original"),
            "original document must be gone: {output}"
        );
    }

    #[tokio::test]
    async fn test_render_template_takes_precedence_over_reader_mode() {
        let templates = engine_with(&[("page.html", "TEMPLATE")]).await;
        let ops = vec![
            RewriteOp::ReaderMode,
            RewriteOp::RenderTemplate {
                name: "page".to_string(),
                context: "{}".to_string(),
            },
        ];
        let html = b"<html><head><title>T</title></head><body><article><p>\
        A long article body with plenty of text so the readability engine would \
        happily select it as the main content candidate for the page.</p></article></body></html>";
        let result = apply_with_templates(&ops, html, Some(&templates)).expect("apply");
        assert_eq!(String::from_utf8(result).expect("utf8"), "TEMPLATE");
    }

    #[tokio::test]
    async fn test_render_template_last_op_wins() {
        let templates = engine_with(&[("a.html", "AAA"), ("b.html", "BBB")]).await;
        let ops = vec![
            RewriteOp::RenderTemplate {
                name: "a".to_string(),
                context: "{}".to_string(),
            },
            RewriteOp::RenderTemplate {
                name: "b".to_string(),
                context: "{}".to_string(),
            },
        ];
        let result = apply_with_templates(&ops, b"<html></html>", Some(&templates)).expect("apply");
        assert_eq!(String::from_utf8(result).expect("utf8"), "BBB");
    }

    #[tokio::test]
    async fn test_render_template_unknown_name_leaves_document_untouched() {
        let templates = engine_with(&[]).await;
        let html = b"<html><body>original</body></html>";
        let ops = vec![RewriteOp::RenderTemplate {
            name: "missing".to_string(),
            context: "{}".to_string(),
        }];
        let result = apply_with_templates(&ops, html, Some(&templates)).expect("apply");
        assert_eq!(result, html, "unknown template must not alter the page");
    }

    #[test]
    fn test_render_template_without_engine_is_noop() {
        let html = b"<html><body>original</body></html>";
        let ops = vec![RewriteOp::RenderTemplate {
            name: "page".to_string(),
            context: "{}".to_string(),
        }];
        let result = apply(&ops, html).expect("apply");
        assert_eq!(result, html, "no engine configured → document unchanged");
    }

    #[tokio::test]
    async fn test_render_template_invalid_context_json_is_noop() {
        let templates = engine_with(&[("page.html", "TEMPLATE")]).await;
        let html = b"<html><body>original</body></html>";
        let ops = vec![RewriteOp::RenderTemplate {
            name: "page".to_string(),
            context: "{not json".to_string(),
        }];
        let result = apply_with_templates(&ops, html, Some(&templates)).expect("apply");
        assert_eq!(result, html, "undecodable context must not alter the page");
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
