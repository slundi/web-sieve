//! Text-density readability extraction — simplified Mozilla Readability concepts.

use scraper::{ElementRef, Html, Selector};

/// Extracted article from an HTML page.
pub struct Article {
    pub title: String,
    pub content_html: String,
}

/// Attempt to extract the main article content from raw HTML.
///
/// Returns `None` when no viable content block is found (score ≤ 0).
pub fn extract(html: &str) -> Option<Article> {
    let document = Html::parse_document(html);
    let title = extract_title(&document);
    let content_html = find_best_content(&document)?;
    Some(Article {
        title,
        content_html,
    })
}

/// Render an [`Article`] into a minimal, self-contained HTML document.
pub fn render(article: &Article) -> Vec<u8> {
    let title_escaped = html_escape(&article.title);
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
:root{{color-scheme:light dark;font-family:Georgia,serif;line-height:1.7;max-width:720px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;background:#fff}}
@media(prefers-color-scheme:dark){{:root{{color:#e0e0e0;background:#1a1a1a}}}}
h1{{font-size:1.8rem;margin-bottom:.5rem}}
img{{max-width:100%;height:auto}}
pre,code{{background:#f4f4f4;border-radius:3px;padding:.2em .4em;font-size:.9em;overflow:auto}}
@media(prefers-color-scheme:dark){{pre,code{{background:#2a2a2a}}}}
blockquote{{border-left:4px solid #ccc;margin:0;padding:0 1rem;color:#555}}
</style>
</head>
<body>
<article>
<h1>{title}</h1>
{content}
</article>
</body>
</html>"#,
        title = title_escaped,
        content = article.content_html,
    )
    .into_bytes()
}

// ─── Private helpers ──────────────────────────────────────────────────────────

fn extract_title(document: &Html) -> String {
    if let Ok(sel) = Selector::parse("title")
        && let Some(el) = document.select(&sel).next()
    {
        let t = el.text().collect::<String>().trim().to_owned();
        if !t.is_empty() {
            return t;
        }
    }
    if let Ok(sel) = Selector::parse("h1")
        && let Some(el) = document.select(&sel).next()
    {
        let t = el.text().collect::<String>().trim().to_owned();
        if !t.is_empty() {
            return t;
        }
    }
    String::new()
}

fn find_best_content(document: &Html) -> Option<String> {
    let Ok(candidate_sel) = Selector::parse("article, main, section, div, p, td, blockquote, pre")
    else {
        return None;
    };
    let Ok(link_sel) = Selector::parse("a") else {
        return None;
    };

    let mut best_score = 0.0_f64;
    let mut best_html: Option<String> = None;

    for element in document.select(&candidate_sel) {
        let score = score_element(&element, &link_sel);
        if score > best_score {
            best_score = score;
            best_html = Some(element.inner_html());
        }
    }

    best_html
}

fn score_element(element: &ElementRef<'_>, link_sel: &Selector) -> f64 {
    let mut score: f64 = match element.value().name() {
        "article" | "main" => 25.0,
        "section" => 10.0,
        "div" | "p" => 5.0,
        "td" | "pre" | "blockquote" => 3.0,
        _ => 0.0,
    };

    let class = element.value().attr("class").unwrap_or("");
    let id = element.value().attr("id").unwrap_or("");
    let attrs = format!("{class} {id}").to_lowercase();

    for kw in [
        "article", "content", "entry", "main", "post", "story", "text",
    ] {
        if attrs.contains(kw) {
            score += 25.0;
        }
    }
    for kw in [
        "sidebar", "comment", "nav", "footer", "ad", "banner", "widget", "social", "menu", "share",
        "related",
    ] {
        if attrs.contains(kw) {
            score -= 25.0;
        }
    }

    let text: String = element.text().collect();
    let text_len = text.trim().len();
    score += (text_len as f64).sqrt();

    let link_text: String = element.select(link_sel).flat_map(|e| e.text()).collect();
    if text_len > 0 {
        let density = link_text.len() as f64 / text_len as f64;
        if density > 0.25 {
            score -= 50.0 * density;
        }
    }

    score
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_HTML: &str = r#"<html><head><title>Test Article</title></head>
<body>
<nav><a href="/">Home</a><a href="/about">About</a></nav>
<article class="content">
<h2>Hello World</h2>
<p>This is a long article with plenty of meaningful text content that should score highly in the readability algorithm because it has good text density and low link density relative to the total word count of the article body.</p>
<p>More paragraph text to push the score even higher and demonstrate that the extraction algorithm works correctly on realistic HTML content structures.</p>
</article>
<aside class="sidebar"><a href="/ad1">Ad 1</a><a href="/ad2">Ad 2</a></aside>
</body></html>"#;

    #[test]
    fn test_extract_finds_article() {
        let article = extract(SIMPLE_HTML).expect("should extract");
        assert_eq!(article.title, "Test Article");
        assert!(article.content_html.contains("Hello World"));
    }

    #[test]
    fn test_render_produces_valid_html() {
        let article = Article {
            title: "My <Title>".into(),
            content_html: "<p>content</p>".into(),
        };
        let rendered = render(&article);
        let s = String::from_utf8(rendered).expect("utf8");
        assert!(s.contains("<!DOCTYPE html>"));
        assert!(s.contains("My &lt;Title&gt;"));
        assert!(s.contains("<p>content</p>"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(
            html_escape("a & b < c > d \"e\""),
            "a &amp; b &lt; c &gt; d &quot;e&quot;"
        );
    }
}
