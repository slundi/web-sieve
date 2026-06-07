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

    let mut output = Vec::with_capacity(html.len());
    let mut element_handlers: Vec<(Cow<'static, Selector>, ElementContentHandlers<'_>)> =
        Vec::new();

    for op in ops {
        match op {
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

    {
        let mut settings = Settings::new();
        for (selector, handler) in element_handlers {
            settings = settings.append_element_content_handler((selector, handler));
        }

        let mut rewriter = HtmlRewriter::new(settings, |chunk: &[u8]| {
            output.extend_from_slice(chunk);
        });

        rewriter.write(html)?;
        rewriter.end()?;
    }

    Ok(output)
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
}
