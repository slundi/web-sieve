//! Ad-blocking engine: domain-trie network matching and cosmetic CSS injection.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use tokio::sync::RwLock;

// ─── Private: Domain trie ────────────────────────────────────────────────────

/// One node in the reversed-label domain trie.
struct TrieNode {
    children: HashMap<String, TrieNode>,
    /// True when this node is the end of a blocking rule.
    is_terminal: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            is_terminal: false,
        }
    }
}

/// Suffix trie on reversed domain labels.
///
/// Inserting `"ads.example.com"` stores reversed labels `["com", "example", "ads"]`
/// so that a host lookup can short-circuit as soon as a terminal node is found,
/// making `||example.com^` match both `example.com` and `sub.example.com`.
struct DomainTrie {
    root: TrieNode,
}

impl DomainTrie {
    fn new() -> Self {
        Self {
            root: TrieNode::new(),
        }
    }

    /// Insert a domain (e.g. `"ads.example.com"`) into the trie.
    fn insert(&mut self, domain: &str) {
        let mut node = &mut self.root;
        for label in domain.split('.').rev() {
            node = node
                .children
                .entry(label.to_string())
                .or_insert_with(TrieNode::new);
        }
        node.is_terminal = true;
    }

    /// Return `true` if `host` is matched by any rule in the trie.
    ///
    /// A terminal node anywhere along the path counts as a match, so
    /// `||example.com^` matches both `example.com` and `sub.example.com`.
    fn matches(&self, host: &str) -> bool {
        let mut node = &self.root;
        for label in host.split('.').rev() {
            if node.is_terminal {
                return true;
            }
            match node.children.get(label) {
                Some(child) => node = child,
                None => return false,
            }
        }
        // Check the final node reached (exact match).
        node.is_terminal
    }
}

// ─── Private: Raw parse output ──────────────────────────────────────────────

/// Intermediate output of parsing a single block-list file.
struct RawRules {
    block_domains: Vec<String>,
    exception_domains: Vec<String>,
    url_patterns: Vec<String>,
    global_cosmetic_selectors: Vec<String>,
    /// host → selectors
    domain_cosmetic: HashMap<String, Vec<String>>,
}

impl RawRules {
    fn new() -> Self {
        Self {
            block_domains: Vec::new(),
            exception_domains: Vec::new(),
            url_patterns: Vec::new(),
            global_cosmetic_selectors: Vec::new(),
            domain_cosmetic: HashMap::new(),
        }
    }
}

// ─── Private: Compiled list state ───────────────────────────────────────────

/// Compiled state derived from all loaded block-list files.
struct ParsedLists {
    /// Domain trie for fast `||domain^` blocking.
    block_trie: DomainTrie,
    /// Domain trie for `@@||domain^` exceptions (checked before block_trie).
    exception_trie: DomainTrie,
    /// AhoCorasick automaton for substring/path URL patterns.
    url_patterns: Option<AhoCorasick>,
    /// CSS for global cosmetic rules (`##selector`), ready to inject.
    global_cosmetic_css: String,
    /// Host → CSS for domain-specific cosmetic rules (`host##selector`).
    domain_cosmetic: HashMap<String, String>,
}

// ─── Public: Ad-blocking engine ─────────────────────────────────────────────

/// Ad-blocking engine that parses EasyList/uBlock-format files and performs
/// both network-level blocking and cosmetic CSS injection.
///
/// The engine watches `lists_dir` for `*.txt` files and hot-reloads them
/// whenever a file is created, modified, or removed.
pub struct AdBlockEngine {
    lists: Arc<RwLock<ParsedLists>>,
    lists_dir: PathBuf,
    _watcher: Box<dyn notify::Watcher + Send + Sync>,
}

impl AdBlockEngine {
    /// Create a new [`AdBlockEngine`] that watches `lists_dir` for `*.txt` files.
    ///
    /// The directory is created if it does not exist.  All `*.txt` files found at
    /// startup are parsed immediately.  A background task watches for changes and
    /// re-parses all files atomically on any relevant event.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created, a file watcher cannot
    /// be set up, or initial parsing fails fatally.
    pub async fn new(lists_dir: PathBuf) -> anyhow::Result<Arc<Self>> {
        use notify::{RecursiveMode, Watcher, recommended_watcher};
        use tokio::sync::mpsc;

        // 1. Ensure the directory exists.
        tokio::fs::create_dir_all(&lists_dir).await?;

        // 2. Parse all existing *.txt files.
        let initial_lists = load_all_lists(&lists_dir).await;
        let lists = Arc::new(RwLock::new(initial_lists));

        // 3. Set up notify watcher with a tokio mpsc bridge.
        let (tx, mut rx) = mpsc::channel::<notify::Result<notify::Event>>(32);
        let mut watcher = recommended_watcher(move |res| {
            let _ = tx.blocking_send(res);
        })?;
        watcher.watch(&lists_dir, RecursiveMode::NonRecursive)?;

        // 4. Spawn background task for hot-reload.
        let lists_for_task = Arc::clone(&lists);
        let lists_dir_clone = lists_dir.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    Ok(ev) => {
                        let is_relevant = ev
                            .paths
                            .iter()
                            .any(|p| p.extension().and_then(|e| e.to_str()) == Some("txt"));
                        if is_relevant {
                            use notify::EventKind;
                            match ev.kind {
                                EventKind::Create(_)
                                | EventKind::Modify(_)
                                | EventKind::Remove(_) => {
                                    tracing::info!(
                                        dir = %lists_dir_clone.display(),
                                        "ad-block lists changed, reloading"
                                    );
                                    let new_lists = load_all_lists(&lists_dir_clone).await;
                                    *lists_for_task.write().await = new_lists;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => tracing::warn!("ad-block watcher error: {e}"),
                }
            }
        });

        let engine = Arc::new(AdBlockEngine {
            lists,
            lists_dir,
            _watcher: Box::new(watcher),
        });

        Ok(engine)
    }

    /// Return `true` if `url` / `host` should be blocked.
    ///
    /// Checks exception rules first; if the host is whitelisted, always returns
    /// `false`.  Otherwise checks the domain trie and the URL-pattern automaton.
    ///
    /// This method is async and acquires a shared read lock without blocking the
    /// executor.  Call it from an async context and `.await` the result.
    pub async fn is_blocked(&self, url: &str, host: &str) -> bool {
        let lists = self.lists.read().await;

        // 1. Exception whitelist takes priority.
        if lists.exception_trie.matches(host) {
            return false;
        }

        // 2. Domain trie block.
        if lists.block_trie.matches(host) {
            return true;
        }

        // 3. Substring URL pattern automaton.
        if let Some(ac) = &lists.url_patterns
            && ac.is_match(url)
        {
            return true;
        }

        false
    }

    /// Return the combined cosmetic CSS for `host`, or `None` if there are no
    /// applicable rules.
    ///
    /// Combines global rules with any host-specific rules.  Domain-specific
    /// rules are collected with suffix matching so that a rule stored under
    /// `example.com` also applies to `www.example.com`.
    ///
    /// This method is async and acquires a shared read lock without blocking the
    /// executor.  Call it from an async context and `.await` the result.
    pub async fn cosmetic_css_for(&self, host: &str) -> Option<String> {
        let lists = self.lists.read().await;

        let global = &lists.global_cosmetic_css;
        let domain_css = collect_domain_css(&lists.domain_cosmetic, host);

        if global.is_empty() && domain_css.is_empty() {
            return None;
        }

        let combined = match (global.is_empty(), domain_css.is_empty()) {
            (true, _) => domain_css,
            (_, true) => global.clone(),
            _ => format!("{global}\n{domain_css}"),
        };

        Some(combined)
    }

    /// Return the lists directory this engine watches.
    pub fn lists_dir(&self) -> &Path {
        &self.lists_dir
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

/// Collect domain-specific cosmetic CSS for `host` using suffix matching.
///
/// Iterates label suffixes from longest to shortest (`www.example.com` →
/// `example.com` → `com`) and joins all matching CSS blocks with a newline.
/// This ensures EasyList rules like `example.com##.ad` apply to all subdomains.
fn collect_domain_css(domain_cosmetic: &HashMap<String, String>, host: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    let mut remaining = host;
    loop {
        if let Some(css) = domain_cosmetic.get(remaining) {
            parts.push(css.as_str());
        }
        match remaining.find('.') {
            Some(dot) => remaining = &remaining[dot + 1..],
            None => break,
        }
    }
    parts.join("\n")
}

/// Read all `*.txt` files in `lists_dir` (non-recursive), parse each, and merge.
async fn load_all_lists(lists_dir: &Path) -> ParsedLists {
    let mut all_raw: Vec<RawRules> = Vec::new();

    match tokio::fs::read_dir(lists_dir).await {
        Ok(mut read_dir) => {
            while let Ok(Some(entry)) = read_dir.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("txt") {
                    match parse_file(&path).await {
                        Ok(raw) => all_raw.push(raw),
                        Err(e) => {
                            tracing::warn!(path = %path.display(), error = %e, "failed to parse list file");
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(dir = %lists_dir.display(), error = %e, "failed to read lists directory");
        }
    }

    merge_raw_rules(all_raw)
}

/// Strip ABP/uBlock option suffix from a rule string.
///
/// Finds the last `$` that is followed by an alphanumeric character or `~` and
/// returns the slice up to that position.  If no such `$` exists, the original
/// string is returned unchanged.
fn strip_options(rule: &str) -> &str {
    // Scan from the end for a '$' followed by a word-char or '~'.
    let bytes = rule.as_bytes();
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if bytes[i] == b'$' && i + 1 < bytes.len() {
            let next = bytes[i + 1];
            if next.is_ascii_alphanumeric() || next == b'~' {
                return &rule[..i];
            }
        }
    }
    rule
}

/// Parse a single ABP/uBlock-format block-list file.
///
/// # Errors
///
/// Returns an error if the file cannot be read.
async fn parse_file(path: &Path) -> anyhow::Result<RawRules> {
    let content = tokio::fs::read_to_string(path).await?;
    let mut rules = RawRules::new();

    for raw_line in content.lines() {
        let line = raw_line.trim();

        // Skip empty lines, comments, and header brackets.
        // Note: check for `##` cosmetic rules before the single-`#` comment guard,
        // because global cosmetic rules start with `##`.
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }

        // Skip cosmetic exceptions (too complex for Phase 4.1).
        if line.contains("#@#") {
            continue;
        }

        // Cosmetic rule: "domains##selector" or "##selector".
        if let Some(pos) = line.find("##") {
            let domains_part = &line[..pos];
            let selector = &line[pos + 2..];

            if selector.is_empty() {
                continue;
            }

            if domains_part.is_empty() {
                // Global cosmetic rule.
                rules.global_cosmetic_selectors.push(selector.to_string());
            } else {
                // Domain-specific cosmetic rules.
                for domain in domains_part.split(',') {
                    let d = domain.trim();
                    // Skip negation domains (too complex for Phase 4.1).
                    if !d.starts_with('~') && !d.is_empty() {
                        rules
                            .domain_cosmetic
                            .entry(d.to_string())
                            .or_default()
                            .push(selector.to_string());
                    }
                }
            }
            continue;
        }

        // Determine if this is an exception rule.
        let (is_exception, rule) = if let Some(stripped) = line.strip_prefix("@@") {
            (true, stripped)
        } else {
            (false, line)
        };

        // Strip option suffix (e.g. `$third-party,script`).
        let rule = strip_options(rule);

        if let Some(after_pipes) = rule.strip_prefix("||") {
            // Domain-anchor rule: `||domain^` or `||domain/path^`.
            let after = after_pipes.trim_end_matches('^');
            let domain_part = after
                .split(&['/', '?'][..])
                .next()
                .unwrap_or(after)
                .trim_end_matches('^');

            if domain_part.is_empty() {
                continue;
            }

            if !domain_part.contains('*') {
                // Pure domain: add to the appropriate trie.
                if is_exception {
                    rules.exception_domains.push(domain_part.to_string());
                } else {
                    rules.block_domains.push(domain_part.to_string());
                }
            } else if !is_exception {
                // Has wildcards: treat as a stripped substring pattern.
                let pattern = domain_part.replace('*', "");
                if !pattern.is_empty() {
                    rules.url_patterns.push(pattern);
                }
            }
        } else if !is_exception {
            // Generic pattern rule: treat as a substring match.
            let pattern = rule
                .trim_start_matches('/')
                .trim_end_matches('/')
                .replace(['^', '*'], "")
                .replace("||", "");

            // Minimum length guard to avoid excessive false positives.
            if pattern.len() >= 4 {
                rules.url_patterns.push(pattern);
            }
        }
    }

    Ok(rules)
}

/// Merge multiple [`RawRules`] sets into a single compiled [`ParsedLists`].
fn merge_raw_rules(rules: Vec<RawRules>) -> ParsedLists {
    let mut block_trie = DomainTrie::new();
    let mut exception_trie = DomainTrie::new();
    let mut all_url_patterns: Vec<String> = Vec::new();
    let mut all_global_selectors: Vec<String> = Vec::new();
    let mut merged_domain_cosmetic: HashMap<String, Vec<String>> = HashMap::new();

    for raw in rules {
        for domain in raw.block_domains {
            block_trie.insert(&domain);
        }
        for domain in raw.exception_domains {
            exception_trie.insert(&domain);
        }
        all_url_patterns.extend(raw.url_patterns);
        all_global_selectors.extend(raw.global_cosmetic_selectors);
        for (host, selectors) in raw.domain_cosmetic {
            merged_domain_cosmetic
                .entry(host)
                .or_default()
                .extend(selectors);
        }
    }

    // Build AhoCorasick automaton for URL patterns.
    let url_patterns = if all_url_patterns.is_empty() {
        None
    } else {
        // Deduplicate patterns before building the automaton.
        all_url_patterns.sort_unstable();
        all_url_patterns.dedup();
        match AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(&all_url_patterns)
        {
            Ok(ac) => Some(ac),
            Err(e) => {
                tracing::warn!(error = %e, "failed to build AhoCorasick automaton");
                None
            }
        }
    };

    // Build global cosmetic CSS.
    all_global_selectors.sort_unstable();
    all_global_selectors.dedup();
    let global_cosmetic_css = if all_global_selectors.is_empty() {
        String::new()
    } else {
        format!(
            "{}{{display:none!important}}",
            all_global_selectors.join(",")
        )
    };

    // Build per-domain cosmetic CSS.
    let domain_cosmetic = merged_domain_cosmetic
        .into_iter()
        .filter_map(|(host, mut selectors)| {
            selectors.sort_unstable();
            selectors.dedup();
            if selectors.is_empty() {
                None
            } else {
                let css = format!("{}{{display:none!important}}", selectors.join(","));
                Some((host, css))
            }
        })
        .collect();

    ParsedLists {
        block_trie,
        exception_trie,
        url_patterns,
        global_cosmetic_css,
        domain_cosmetic,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_tempfile(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(".txt")
            .tempfile()
            .expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    // ─── DomainTrie tests ─────────────────────────────────────────────────

    #[test]
    fn test_domain_trie_exact_match() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com");
        assert!(trie.matches("example.com"));
    }

    #[test]
    fn test_domain_trie_subdomain_match() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com");
        assert!(trie.matches("sub.example.com"));
    }

    #[test]
    fn test_domain_trie_no_match() {
        let mut trie = DomainTrie::new();
        trie.insert("example.com");
        assert!(!trie.matches("notexample.com"));
    }

    #[test]
    fn test_domain_trie_no_match_suffix() {
        let mut trie = DomainTrie::new();
        trie.insert("ample.com");
        // "example.com" shares a suffix of the *label* but is a different label.
        assert!(!trie.matches("example.com"));
    }

    // ─── parse_file tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_parse_file_block_domain() {
        let f = write_tempfile("||ads.example.com^\n");
        let raw = parse_file(f.path()).await.expect("parse");
        assert!(
            raw.block_domains.contains(&"ads.example.com".to_string()),
            "block_domains should contain ads.example.com"
        );
    }

    #[tokio::test]
    async fn test_parse_file_exception() {
        let f = write_tempfile("@@||safe.example.com^\n");
        let raw = parse_file(f.path()).await.expect("parse");
        assert!(
            raw.exception_domains
                .contains(&"safe.example.com".to_string()),
            "exception_domains should contain safe.example.com"
        );
    }

    #[tokio::test]
    async fn test_parse_file_cosmetic_global() {
        let f = write_tempfile("##.advertisement\n");
        let raw = parse_file(f.path()).await.expect("parse");
        assert!(
            raw.global_cosmetic_selectors
                .contains(&".advertisement".to_string()),
            "global_cosmetic_selectors should contain .advertisement"
        );
    }

    #[tokio::test]
    async fn test_parse_file_cosmetic_domain() {
        let f = write_tempfile("example.com##.ads\n");
        let raw = parse_file(f.path()).await.expect("parse");
        let selectors = raw
            .domain_cosmetic
            .get("example.com")
            .expect("entry for example.com");
        assert!(
            selectors.contains(&".ads".to_string()),
            "domain_cosmetic[example.com] should contain .ads"
        );
    }

    // ─── AdBlockEngine tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_adblocker_is_blocked() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let list_path = tmp.path().join("test.txt");
        std::fs::write(&list_path, "||tracker.example.com^\n").expect("write list");

        let engine = AdBlockEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");

        assert!(
            engine
                .is_blocked("http://tracker.example.com/", "tracker.example.com")
                .await,
            "tracker.example.com should be blocked"
        );
        assert!(
            !engine
                .is_blocked("http://safe.example.com/", "safe.example.com")
                .await,
            "safe.example.com should not be blocked"
        );
    }

    #[tokio::test]
    async fn test_adblocker_exception() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let list_path = tmp.path().join("test.txt");
        std::fs::write(&list_path, "||example.com^\n@@||safe.example.com^\n").expect("write list");

        let engine = AdBlockEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");

        assert!(
            !engine
                .is_blocked("http://safe.example.com/", "safe.example.com")
                .await,
            "safe.example.com is whitelisted and should not be blocked"
        );
        assert!(
            engine
                .is_blocked("http://other.example.com/", "other.example.com")
                .await,
            "other.example.com is covered by ||example.com^ and should be blocked"
        );
    }

    #[tokio::test]
    async fn test_adblocker_cosmetic_css() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let list_path = tmp.path().join("test.txt");
        std::fs::write(&list_path, "##.ad-banner\n##.sidebar-ad\n").expect("write list");

        let engine = AdBlockEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");

        let css = engine
            .cosmetic_css_for("any.com")
            .await
            .expect("should have CSS");

        assert!(
            css.contains("display:none"),
            "cosmetic CSS should include display:none: {css}"
        );
        assert!(
            css.contains(".ad-banner"),
            "cosmetic CSS should include .ad-banner: {css}"
        );
        assert!(
            css.contains(".sidebar-ad"),
            "cosmetic CSS should include .sidebar-ad: {css}"
        );
    }

    // ─── collect_domain_css / subdomain matching ──────────────────────────

    #[test]
    fn test_collect_domain_css_exact() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), ".ad{display:none}".to_string());
        assert_eq!(collect_domain_css(&map, "example.com"), ".ad{display:none}");
    }

    #[test]
    fn test_collect_domain_css_subdomain_inherits_parent() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), ".ad{display:none}".to_string());
        // www.example.com has no own entry but must pick up example.com's rule.
        assert_eq!(
            collect_domain_css(&map, "www.example.com"),
            ".ad{display:none}"
        );
    }

    #[test]
    fn test_collect_domain_css_deep_subdomain() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), ".ad{display:none}".to_string());
        assert_eq!(
            collect_domain_css(&map, "a.b.example.com"),
            ".ad{display:none}"
        );
    }

    #[test]
    fn test_collect_domain_css_multi_level_combined() {
        let mut map = HashMap::new();
        map.insert(
            "example.com".to_string(),
            ".parent{display:none}".to_string(),
        );
        map.insert(
            "www.example.com".to_string(),
            ".www{display:none}".to_string(),
        );
        let css = collect_domain_css(&map, "www.example.com");
        assert!(
            css.contains(".www{display:none}"),
            "own rule missing: {css}"
        );
        assert!(
            css.contains(".parent{display:none}"),
            "parent rule missing: {css}"
        );
    }

    #[test]
    fn test_collect_domain_css_no_false_match() {
        let mut map = HashMap::new();
        map.insert("example.com".to_string(), ".ad{display:none}".to_string());
        // evil-example.com is a different label — must not match.
        assert!(collect_domain_css(&map, "evil-example.com").is_empty());
        // notexample.com likewise.
        assert!(collect_domain_css(&map, "notexample.com").is_empty());
    }

    #[tokio::test]
    async fn test_engine_subdomain_gets_parent_cosmetic_css() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("test.txt"), "example.com##.ad-sidebar\n")
            .expect("write list");
        let engine = AdBlockEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");

        // Exact key — regression guard.
        assert!(
            engine.cosmetic_css_for("example.com").await.is_some(),
            "exact match must still work"
        );

        // Subdomain — was broken before this fix.
        let css = engine
            .cosmetic_css_for("www.example.com")
            .await
            .expect("subdomain must inherit parent domain cosmetic rules");
        assert!(
            css.contains(".ad-sidebar"),
            "expected .ad-sidebar in: {css}"
        );

        // Deep subdomain.
        assert!(
            engine.cosmetic_css_for("a.b.example.com").await.is_some(),
            "deep subdomain must inherit parent domain cosmetic rules"
        );
    }

    #[tokio::test]
    async fn test_engine_unrelated_domain_no_cosmetic_match() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("test.txt"), "example.com##.ad-unit\n").expect("write list");
        let engine = AdBlockEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");

        assert!(
            engine.cosmetic_css_for("evil-example.com").await.is_none(),
            "unrelated domain must not match"
        );
    }
}
