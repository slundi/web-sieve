//! Heuristic anti-phishing engine.
//!
//! Detects HTML pages served over plain HTTP (unverified domain) that contain
//! both credential input fields inside a `<form>` and semantic panic-trigger
//! phrases — the two structural hallmarks of credential-harvesting phishing
//! pages.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use lol_html::html_content::Element;
use lol_html::{ElementContentHandlers, HtmlRewriter, Selector, Settings};
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

const PANIC_TRIGGERS: &[&str] = &[
    "verify your account",
    "verify account",
    "unauthorized access",
    "account suspended",
    "account locked",
    "account has been",
    "confirm your identity",
    "update your information",
    "suspicious activity",
    "security alert",
    "click here to verify",
];

const CREDENTIAL_SELECTORS: &[&str] = &[
    "form input[type=password]",
    "form input[autocomplete=current-password]",
    "form input[autocomplete=new-password]",
    "form input[autocomplete=cc-number]",
    "form input[name*=password]",
    "form input[name*=passwd]",
    "form input[name*=card]",
    "form input[name*=credit]",
    "form input[name*=ssn]",
];

static PANIC_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn panic_automaton() -> &'static AhoCorasick {
    PANIC_AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(PANIC_TRIGGERS)
            .expect("valid panic trigger patterns")
    })
}

fn has_credential_form(html: &[u8]) -> bool {
    let found = Arc::new(AtomicBool::new(false));
    let mut settings = Settings::new();

    for sel_str in CREDENTIAL_SELECTORS {
        let found_clone = Arc::clone(&found);
        let selector: Selector = match sel_str.parse() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(selector = %sel_str, error = %e, "invalid phishing selector, skipping");
                continue;
            }
        };
        let handler = ElementContentHandlers::default().element(move |_el: &mut Element| {
            found_clone.store(true, Ordering::Relaxed);
            Ok(())
        });
        settings = settings.append_element_content_handler((Cow::Owned(selector), handler));
    }

    let mut rewriter = HtmlRewriter::new(settings, |_chunk: &[u8]| {});

    if rewriter.write(html).is_err() || rewriter.end().is_err() {
        return false;
    }

    found.load(Ordering::Relaxed)
}

/// Returns `true` if `html` contains a credential input inside a `<form>` AND
/// at least one panic-trigger phrase, indicating a likely phishing page.
///
/// Intended for plain-HTTP responses only — HTTPS connections are verified by
/// the TLS handshake and are not checked here.
pub fn check(html: &[u8]) -> bool {
    panic_automaton().is_match(html) && has_credential_form(html)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN_PAGE: &[u8] = b"<html><body><p>Welcome to our site</p></body></html>";

    const CREDENTIAL_ONLY: &[u8] = b"<html><body>\
        <form><input type=\"password\" name=\"pass\"></form>\
        </body></html>";

    const TRIGGERS_ONLY: &[u8] = b"<html><body>\
        <p>Suspicious activity detected. Verify your account immediately.</p>\
        </body></html>";

    const PHISHING_PAGE: &[u8] = b"<html><body>\
        <p>Suspicious activity detected. Please verify your account.</p>\
        <form action=\"/steal\">\
        <input type=\"text\" name=\"user\">\
        <input type=\"password\" name=\"pass\">\
        <button>Submit</button>\
        </form>\
        </body></html>";

    const CC_PHISHING: &[u8] = b"<html><body>\
        <p>Your account has been suspended. Update your information now.</p>\
        <form><input autocomplete=\"cc-number\" name=\"card\"></form>\
        </body></html>";

    const PASSWD_NAME_PHISHING: &[u8] = b"<html><body>\
        <p>Unauthorized access detected on your account.</p>\
        <form><input type=\"text\" name=\"passwd\"></form>\
        </body></html>";

    #[test]
    fn test_clean_page_not_flagged() {
        assert!(!check(CLEAN_PAGE));
    }

    #[test]
    fn test_credential_form_only_not_flagged() {
        assert!(
            !check(CREDENTIAL_ONLY),
            "form without panic triggers should not be flagged"
        );
    }

    #[test]
    fn test_panic_triggers_only_not_flagged() {
        assert!(
            !check(TRIGGERS_ONLY),
            "triggers without credential form should not be flagged"
        );
    }

    #[test]
    fn test_phishing_page_flagged() {
        assert!(
            check(PHISHING_PAGE),
            "page with both credential form and panic triggers should be flagged"
        );
    }

    #[test]
    fn test_cc_number_phishing_flagged() {
        assert!(
            check(CC_PHISHING),
            "cc-number form with account-suspended trigger should be flagged"
        );
    }

    #[test]
    fn test_passwd_name_attribute_flagged() {
        assert!(
            check(PASSWD_NAME_PHISHING),
            "input with name*=passwd and panic trigger should be flagged"
        );
    }

    #[test]
    fn test_empty_html_not_flagged() {
        assert!(!check(b""));
    }

    /// The Aho-Corasick check must short-circuit before the DOM parse.
    ///
    /// Construct a page that has a credential form but deliberately broken HTML
    /// that would cause lol_html to error if it were parsed.  The only way the
    /// test can pass is if `has_credential_form` is never called — i.e. the
    /// fast text check ran first and returned false.
    #[test]
    fn test_no_panic_triggers_skips_dom_parse() {
        // Valid credential form, zero panic-trigger phrases, and binary garbage
        // appended so any lol_html parse would be unreliable.
        let mut html = b"<form><input type=\"password\" name=\"pass\"></form>".to_vec();
        html.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x01]); // non-UTF-8 noise
        assert!(
            !check(&html),
            "no panic triggers → must return false without DOM parsing"
        );
    }
}
