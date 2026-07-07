//! Starlark scripting engine with hot-reload support.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use glob::{MatchOptions, Pattern as GlobPattern};
use starlark::environment::{FrozenModule, GlobalsBuilder, Module};
use starlark::eval::Evaluator;
use starlark::starlark_module;
use starlark::syntax::{AstModule, Dialect};
use starlark::values::Value;
use starlark::values::dict::AllocDict;
use starlark::values::list::ListRef;
use starlark::values::none::NoneType;
use tokio::sync::RwLock;

use crate::rewriter::RewriteOp;
use crate::scanner::ScanMatch;

// ─── Thread-local accumulators ───────────────────────────────────────────────

const DEFAULT_DENSITY_THRESHOLD: f32 = 0.01;

thread_local! {
    static PENDING_OPS: RefCell<Vec<RewriteOp>> = const { RefCell::new(Vec::new()) };
    /// Scan context set once per `execute_rule` call and read by `scan_matches()`
    /// and `scan_content_length()` from within the Starlark process() function.
    static SCAN_CTX: RefCell<(Vec<ScanMatch>, usize)> = const { RefCell::new((Vec::new(), 0)) };
    /// Configured density threshold, set per `run_rules` call.
    static DENSITY_THRESHOLD: RefCell<f32> = const { RefCell::new(DEFAULT_DENSITY_THRESHOLD) };
}

// ─── URL pattern matching ─────────────────────────────────────────────────────

const URL_MATCH_OPTS: MatchOptions = MatchOptions {
    case_sensitive: false,
    require_literal_separator: false,
    require_literal_leading_dot: false,
};

/// Extract `host[/path]` from a full URL, stripping scheme, query, and fragment.
fn strip_host_path(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let without_fragment = without_scheme.split('#').next().unwrap_or(without_scheme);
    without_fragment
        .split('?')
        .next()
        .unwrap_or(without_fragment)
        .to_owned()
}

/// Return `true` if any pattern in `patterns` matches the given URL.
///
/// Patterns without a `/` are matched against the host only; patterns that
/// contain a `/` are matched against `host/path` (query and fragment stripped).
fn rule_matches_url(patterns: &[GlobPattern], url: &str, host: &str) -> bool {
    patterns.iter().any(|p| {
        let target = if p.as_str().contains('/') {
            strip_host_path(url)
        } else {
            host.to_owned()
        };
        p.matches_with(&target, URL_MATCH_OPTS)
    })
}

// ─── Starlark global functions ──────────────────────────────────────────────

#[starlark_module]
fn proxy_globals(builder: &mut GlobalsBuilder) {
    /// Remove all elements matching `selector` from the page.
    fn remove_element(selector: String) -> anyhow::Result<NoneType> {
        PENDING_OPS.with(|ops| ops.borrow_mut().push(RewriteOp::RemoveElement(selector)));
        Ok(NoneType)
    }

    /// Inject a `<style>` block with `css` into the document `<head>`.
    fn inject_style(css: String) -> anyhow::Result<NoneType> {
        PENDING_OPS.with(|ops| ops.borrow_mut().push(RewriteOp::InjectStyle(css)));
        Ok(NoneType)
    }

    /// Hide all body children that do NOT match `selector`.
    fn keep_only(selector: String) -> anyhow::Result<NoneType> {
        PENDING_OPS.with(|ops| ops.borrow_mut().push(RewriteOp::KeepOnly(selector)));
        Ok(NoneType)
    }

    /// Switch the page to reader mode (extracts main article, replaces document).
    fn enable_reader_mode() -> anyhow::Result<NoneType> {
        PENDING_OPS.with(|ops| ops.borrow_mut().push(RewriteOp::ReaderMode));
        Ok(NoneType)
    }

    /// Fire an HTTP POST webhook with `body` (JSON string). Side-effect only.
    fn webhook(url: String, body: String) -> anyhow::Result<NoneType> {
        PENDING_OPS.with(|ops| {
            ops.borrow_mut().push(RewriteOp::Webhook { url, body });
        });
        Ok(NoneType)
    }

    /// Block the page: the proxy returns 403 instead of this response.
    ///
    /// Intended for use in scoring rules — call only when the computed
    /// term density exceeds the configured threshold.
    fn block_page() -> anyhow::Result<NoneType> {
        PENDING_OPS.with(|ops| ops.borrow_mut().push(RewriteOp::BlockPage));
        Ok(NoneType)
    }

    /// Return a dict of `{category: hit_count}` for the current response.
    ///
    /// Only categories with at least one hit are included.  Use this together
    /// with `scan_content_length()` to compute a density and decide whether to
    /// call `block_page()`.
    ///
    /// Example:
    /// ```python
    /// def process(request):
    ///     m = scan_matches()
    ///     n = scan_content_length()
    ///     if n > 0 and m.get("violence", 0) / n > 0.001:
    ///         block_page()
    /// ```
    fn scan_matches<'v>(eval: &mut Evaluator<'v, '_, '_>) -> anyhow::Result<Value<'v>> {
        let pairs: Vec<(String, i64)> = SCAN_CTX.with(|ctx| {
            ctx.borrow()
                .0
                .iter()
                .map(|m| (m.category.clone(), m.count as i64))
                .collect()
        });
        Ok(eval.heap().alloc(AllocDict(pairs)))
    }

    /// Return the byte length of the response body being processed.
    ///
    /// Divide a category's hit count by this value to get hits-per-byte density.
    fn scan_content_length() -> anyhow::Result<i64> {
        Ok(SCAN_CTX.with(|ctx| ctx.borrow().1 as i64))
    }

    /// Return the configured hits-per-byte density threshold.
    ///
    /// Use this instead of a hard-coded literal so the threshold can be set
    /// globally via `--density-threshold` without editing each rule file.
    ///
    /// Example:
    /// ```python
    /// def process(request):
    ///     m = scan_matches()
    ///     n = scan_content_length()
    ///     if n > 0 and m.get("violence", 0) / n > density_threshold():
    ///         block_page()
    /// ```
    fn density_threshold() -> anyhow::Result<f64> {
        Ok(DENSITY_THRESHOLD.with(|t| *t.borrow() as f64))
    }
}

// ─── Public types ───────────────────────────────────────────────────────────

/// Contextual information about the current HTTP request/response.
pub struct RequestCtx {
    /// Full request URL.
    pub url: String,
    /// Host name (without port).
    pub host: String,
    /// Value of the `Content-Type` response header.
    pub content_type: String,
    /// Scan matches from the text scanner (category → hit count).
    pub scan_matches: Vec<ScanMatch>,
    /// Byte length of the response body.
    pub content_length: usize,
}

/// A compiled Starlark rule file ready for evaluation.
#[derive(Debug)]
struct LoadedRule {
    /// Source path, used for reload / eviction logic.
    path: PathBuf,
    /// The frozen module that results from evaluating the `.star` file.
    frozen: FrozenModule,
    /// Compiled glob patterns from the script's top-level `URLS` list.
    url_patterns: Vec<GlobPattern>,
}

/// The scripting engine that loads, hot-reloads, and executes Starlark rule files.
pub struct ScriptEngine {
    rules: Arc<RwLock<Vec<LoadedRule>>>,
    rules_dir: PathBuf,
    density_threshold: f32,
    _watcher: Box<dyn notify::Watcher + Send + Sync>,
}

impl ScriptEngine {
    /// Create a new [`ScriptEngine`] that watches `rules_dir` for `.star` files.
    ///
    /// The directory is created if it does not exist.  All `.star` files found
    /// at startup are compiled immediately.  A background task watches for
    /// changes and reloads / removes rules without a proxy restart.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created, a file watcher
    /// cannot be set up, or the initial rule compilation fails fatally.
    pub async fn new(rules_dir: PathBuf, density_threshold: f32) -> anyhow::Result<Arc<Self>> {
        use notify::{RecursiveMode, Watcher, recommended_watcher};
        use tokio::sync::mpsc;

        // 1. Ensure the directory exists.
        tokio::fs::create_dir_all(&rules_dir).await?;

        // 2. Load all existing .star files in sorted order for deterministic rule application.
        let mut star_paths: Vec<std::path::PathBuf> = Vec::new();
        let mut read_dir = tokio::fs::read_dir(&rules_dir).await?;
        while let Some(entry) = read_dir.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("star") {
                star_paths.push(path);
            }
        }
        star_paths.sort_unstable();
        let mut initial_rules: Vec<LoadedRule> = Vec::new();
        for path in &star_paths {
            match load_rule(path) {
                Ok(rule) => initial_rules.push(rule),
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "failed to load rule")
                }
            }
        }

        let rules = Arc::new(RwLock::new(initial_rules));

        // 3. Set up notify watcher with a tokio mpsc bridge.
        let (tx, mut rx) = mpsc::channel::<notify::Result<notify::Event>>(32);
        let mut watcher = recommended_watcher(move |res| {
            let _ = tx.blocking_send(res);
        })?;
        watcher.watch(&rules_dir, RecursiveMode::NonRecursive)?;

        // 4. Spawn background task for hot-reload.
        let rules_for_task = Arc::clone(&rules);
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    Ok(ev) => handle_notify_event(ev, &rules_for_task).await,
                    Err(e) => tracing::warn!("watcher error: {e}"),
                }
            }
        });

        let engine = Arc::new(ScriptEngine {
            rules,
            rules_dir,
            density_threshold,
            _watcher: Box::new(watcher),
        });

        Ok(engine)
    }

    /// Execute all loaded rules whose `URLS` match `ctx` and return the accumulated [`RewriteOp`]s.
    ///
    /// Rules whose URL patterns do not match `ctx.url` / `ctx.host` are skipped without
    /// entering the Starlark interpreter.  This method is synchronous and may be called
    /// from a `spawn_blocking` context.
    pub fn run_rules(&self, ctx: &RequestCtx) -> Vec<RewriteOp> {
        let rules = self.rules.blocking_read();
        DENSITY_THRESHOLD.with(|t| *t.borrow_mut() = self.density_threshold);
        let mut all_ops = Vec::new();
        for rule in rules.iter() {
            if !rule_matches_url(&rule.url_patterns, &ctx.url, &ctx.host) {
                continue;
            }
            let ops = execute_rule(&rule.frozen, ctx);
            all_ops.extend(ops);
        }
        DENSITY_THRESHOLD.with(|t| *t.borrow_mut() = DEFAULT_DENSITY_THRESHOLD);
        all_ops
    }

    /// Return the rules directory this engine watches.
    pub fn rules_dir(&self) -> &Path {
        &self.rules_dir
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

/// Compile a `.star` file into a [`LoadedRule`].
///
/// Returns an error if the file cannot be read, fails to parse or evaluate, is
/// missing the required top-level `URLS` list, or contains an invalid glob pattern.
fn load_rule(path: &Path) -> anyhow::Result<LoadedRule> {
    use anyhow::Context as _;

    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let filename = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());

    let ast = AstModule::parse(&filename, content, &Dialect::Standard)
        .map_err(|e| anyhow::anyhow!("parse error in {}: {}", filename, e))?;

    let globals = GlobalsBuilder::standard().with(proxy_globals).build();

    let frozen = Module::with_temp_heap(|module| -> anyhow::Result<FrozenModule> {
        {
            let mut eval = Evaluator::new(&module);
            eval.eval_module(ast, &globals)
                .map_err(|e| anyhow::anyhow!("eval error in {}: {}", filename, e))?;
        }
        module
            .freeze()
            .map_err(|e| anyhow::anyhow!("freeze error in {}: {:?}", filename, e))
    })?;

    let url_patterns = extract_url_patterns(&frozen, &filename)?;

    Ok(LoadedRule {
        path: path.to_path_buf(),
        frozen,
        url_patterns,
    })
}

/// Read the mandatory `URLS` list from a frozen module and compile each entry into
/// a [`GlobPattern`].
///
/// Returns an error if `URLS` is absent, is not a list of strings, is empty, or
/// contains a pattern that cannot be compiled.
fn extract_url_patterns(frozen: &FrozenModule, filename: &str) -> anyhow::Result<Vec<GlobPattern>> {
    let urls_val = frozen.get("URLS").map_err(|_| {
        anyhow::anyhow!(
            "'{}' is missing required top-level URLS list — add e.g. URLS = [\"*\"] to match all hosts",
            filename
        )
    })?;

    let strings: anyhow::Result<Vec<String>> = Module::with_temp_heap(|module| {
        let v = module.heap().access_owned_frozen_value(&urls_val);
        let list = ListRef::from_value(v)
            .ok_or_else(|| anyhow::anyhow!("URLS in '{}' must be a list of strings", filename))?;
        if list.is_empty() {
            return Err(anyhow::anyhow!(
                "URLS in '{}' must not be empty — use [\"*\"] to match all hosts",
                filename
            ));
        }
        list.iter()
            .map(|item| {
                item.unpack_str()
                    .ok_or_else(|| {
                        anyhow::anyhow!("URLS entries in '{}' must be strings", filename)
                    })
                    .map(str::to_owned)
            })
            .collect()
    });

    strings?
        .iter()
        .map(|s| {
            GlobPattern::new(s).map_err(|e| {
                anyhow::anyhow!("invalid URL pattern '{}' in '{}': {}", s, filename, e)
            })
        })
        .collect()
}

/// Call the `process(request)` function in a frozen module and collect the
/// [`RewriteOp`]s it emits via the thread-local accumulator.
fn execute_rule(frozen: &FrozenModule, ctx: &RequestCtx) -> Vec<RewriteOp> {
    let process_val = match frozen.get("process") {
        Ok(v) => v,
        Err(_) => {
            tracing::debug!("rule has no 'process' function, skipping");
            return Vec::new();
        }
    };

    // Clear any leftover ops and populate the scan context for this invocation.
    PENDING_OPS.with(|ops| ops.borrow_mut().clear());
    SCAN_CTX.with(|sc| {
        *sc.borrow_mut() = (ctx.scan_matches.clone(), ctx.content_length);
    });

    let result = Module::with_temp_heap(|call_module| -> anyhow::Result<()> {
        let mut eval = Evaluator::new(&call_module);

        // Bring the frozen process function value into the call module's heap scope.
        let process_fn = call_module.heap().access_owned_frozen_value(&process_val);

        // Build the request dict on the new module's heap.
        let request = call_module.heap().alloc(AllocDict([
            ("url", ctx.url.as_str()),
            ("host", ctx.host.as_str()),
            ("content_type", ctx.content_type.as_str()),
        ]));

        eval.eval_function(process_fn, &[request], &[])
            .map_err(|e| anyhow::anyhow!("process() error: {e}"))?;
        Ok(())
    });

    // Always clear the scan context after the rule runs.
    SCAN_CTX.with(|sc| *sc.borrow_mut() = (Vec::new(), 0));

    if let Err(e) = result {
        tracing::warn!(error = %e, "rule execution failed");
        return Vec::new();
    }

    PENDING_OPS.with(|ops| std::mem::take(&mut *ops.borrow_mut()))
}

/// Handle a filesystem event from the notify watcher.
async fn handle_notify_event(event: notify::Event, rules: &RwLock<Vec<LoadedRule>>) {
    use notify::EventKind;

    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
            for path in &event.paths {
                if path.extension().and_then(|e| e.to_str()) != Some("star") {
                    continue;
                }
                tracing::info!(path = %path.display(), "reloading rule");
                match load_rule(path) {
                    Ok(new_rule) => {
                        let mut locked = rules.write().await;
                        if let Some(existing) = locked.iter_mut().find(|r| r.path == *path) {
                            existing.frozen = new_rule.frozen;
                            existing.url_patterns = new_rule.url_patterns;
                        } else {
                            locked.push(new_rule);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = %e, "failed to reload rule");
                    }
                }
            }
        }
        EventKind::Remove(_) => {
            for path in &event.paths {
                if path.extension().and_then(|e| e.to_str()) != Some("star") {
                    continue;
                }
                tracing::info!(path = %path.display(), "removing rule");
                let mut locked = rules.write().await;
                locked.retain(|r| r.path != *path);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_tempfile(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new()
            .suffix(".star")
            .tempfile()
            .expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        f
    }

    fn ctx(url: &str) -> RequestCtx {
        RequestCtx {
            url: url.into(),
            host: "example.com".into(),
            content_type: "text/html".into(),
            scan_matches: Vec::new(),
            content_length: 0,
        }
    }

    #[test]
    fn test_load_rule_with_valid_script() {
        let f = write_tempfile("URLS = [\"example.com\"]\ndef process(request):\n    pass\n");
        let rule = load_rule(f.path()).expect("load_rule should succeed");
        assert_eq!(rule.path, f.path());
    }

    #[test]
    fn test_load_rule_missing_process_fn() {
        let f = write_tempfile("URLS = [\"example.com\"]\nx = 1\n");
        let rule = load_rule(f.path()).expect("load succeeds even without process");
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        assert!(ops.is_empty());
    }

    #[test]
    fn test_load_rule_missing_urls_fails() {
        let f = write_tempfile("def process(request):\n    pass\n");
        let err = load_rule(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("URLS"),
            "error should mention URLS: {err}"
        );
    }

    #[test]
    fn test_load_rule_empty_urls_fails() {
        let f = write_tempfile("URLS = []\ndef process(request):\n    pass\n");
        let err = load_rule(f.path()).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "error should mention empty: {err}"
        );
    }

    #[test]
    fn test_execute_rule_collects_ops() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    remove_element("div.foo")
"#,
        );
        let rule = load_rule(f.path()).expect("load");
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], RewriteOp::RemoveElement("div.foo".into()));
    }

    #[test]
    fn test_execute_rule_enable_reader_mode() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    enable_reader_mode()
"#,
        );
        let rule = load_rule(f.path()).expect("load");
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], RewriteOp::ReaderMode));
    }

    #[test]
    fn test_execute_rule_block_page() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], RewriteOp::BlockPage));
    }

    #[test]
    fn test_execute_rule_scan_matches_empty() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    m = scan_matches()
    if len(m) != 0:
        remove_element("should-not-happen")
"#,
        );
        let rule = load_rule(f.path()).expect("load");
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        assert!(ops.is_empty(), "no matches in ctx → no ops: {ops:?}");
    }

    #[test]
    fn test_execute_rule_scan_matches_with_data() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    m = scan_matches()
    if m.get("violence", 0) > 5:
        block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.scan_matches = vec![ScanMatch {
            category: "violence".into(),
            count: 10,
        }];
        c.content_length = 1000;

        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], RewriteOp::BlockPage));
    }

    #[test]
    fn test_execute_rule_density_threshold_not_reached() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    m = scan_matches()
    n = scan_content_length()
    if n > 0 and m.get("spam", 0) / n > 0.01:
        block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.scan_matches = vec![ScanMatch {
            category: "spam".into(),
            count: 2,
        }];
        c.content_length = 10_000; // density = 0.0002, below 0.01

        let ops = execute_rule(&rule.frozen, &c);
        assert!(
            ops.is_empty(),
            "density below threshold → no block: {ops:?}"
        );
    }

    #[test]
    fn test_execute_rule_density_threshold_reached() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    m = scan_matches()
    n = scan_content_length()
    if n > 0 and m.get("spam", 0) / n > 0.01:
        block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.scan_matches = vec![ScanMatch {
            category: "spam".into(),
            count: 200,
        }];
        c.content_length = 1_000; // density = 0.2, above 0.01

        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], RewriteOp::BlockPage));
    }

    #[test]
    fn test_execute_rule_density_threshold_function() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    t = density_threshold()
    if t > 0.005:
        block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        // Set the thread-local to 0.02 to simulate a custom CLI threshold.
        DENSITY_THRESHOLD.with(|t| *t.borrow_mut() = 0.02_f32);
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        DENSITY_THRESHOLD.with(|t| *t.borrow_mut() = DEFAULT_DENSITY_THRESHOLD);

        assert_eq!(ops.len(), 1, "threshold 0.02 > 0.005 → block_page: {ops:?}");
        assert!(matches!(ops[0], RewriteOp::BlockPage));
    }

    #[tokio::test]
    async fn test_script_engine_loads_rules_in_sorted_order() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Write files in reverse alphabetical order to verify sorting.
        for (name, selector) in [
            ("c.star", "\"c\""),
            ("a.star", "\"a\""),
            ("b.star", "\"b\""),
        ] {
            std::fs::write(
                tmp.path().join(name),
                format!(
                    "URLS = [\"example.com\"]\ndef process(request):\n    remove_element({})\n",
                    selector
                ),
            )
            .expect("write");
        }

        let engine = ScriptEngine::new(tmp.path().to_path_buf(), 0.01)
            .await
            .expect("ScriptEngine::new");

        let c = ctx("http://example.com/");
        let ops = tokio::task::spawn_blocking(move || engine.run_rules(&c))
            .await
            .expect("spawn_blocking");
        assert_eq!(ops.len(), 3, "expected 3 ops: {ops:?}");
        assert_eq!(
            ops[0],
            RewriteOp::RemoveElement("a".into()),
            "first op must come from a.star"
        );
        assert_eq!(
            ops[1],
            RewriteOp::RemoveElement("b".into()),
            "second op must come from b.star"
        );
        assert_eq!(
            ops[2],
            RewriteOp::RemoveElement("c".into()),
            "third op must come from c.star"
        );
    }

    // ─── URL scoping tests ─────────────────────────────────────────────────────

    #[test]
    fn test_rule_matches_url_exact_host() {
        let p = GlobPattern::new("example.com").unwrap();
        assert!(rule_matches_url(
            &[p.clone()],
            "http://example.com/",
            "example.com"
        ));
        assert!(!rule_matches_url(
            &[p],
            "http://www.example.com/",
            "www.example.com"
        ));
    }

    #[test]
    fn test_rule_matches_url_subdomain_wildcard() {
        let p = GlobPattern::new("*.example.com").unwrap();
        assert!(rule_matches_url(
            &[p.clone()],
            "http://www.example.com/",
            "www.example.com"
        ));
        assert!(rule_matches_url(
            &[p.clone()],
            "http://old.example.com/page",
            "old.example.com"
        ));
        assert!(!rule_matches_url(
            &[p],
            "http://example.com/",
            "example.com"
        ));
    }

    #[test]
    fn test_rule_matches_url_catch_all() {
        let p = GlobPattern::new("*").unwrap();
        assert!(rule_matches_url(
            &[p.clone()],
            "http://anything.io/",
            "anything.io"
        ));
        assert!(rule_matches_url(
            &[p],
            "https://reddit.com/r/rust",
            "reddit.com"
        ));
    }

    #[test]
    fn test_rule_matches_url_path_glob() {
        let p = GlobPattern::new("example.com/r/*").unwrap();
        assert!(rule_matches_url(
            &[p.clone()],
            "http://example.com/r/rust",
            "example.com"
        ));
        assert!(!rule_matches_url(
            &[p],
            "http://example.com/other/page",
            "example.com"
        ));
    }

    #[test]
    fn test_rule_matches_url_multiple_patterns() {
        let patterns: Vec<GlobPattern> = ["reddit.com", "*.reddit.com"]
            .iter()
            .map(|s| GlobPattern::new(s).unwrap())
            .collect();
        assert!(rule_matches_url(
            &patterns,
            "http://reddit.com/",
            "reddit.com"
        ));
        assert!(rule_matches_url(
            &patterns,
            "http://old.reddit.com/",
            "old.reddit.com"
        ));
        assert!(!rule_matches_url(
            &patterns,
            "http://other.com/",
            "other.com"
        ));
    }

    #[test]
    fn test_strip_host_path_strips_scheme_query_fragment() {
        assert_eq!(
            strip_host_path("https://example.com/r/rust?sort=new#top"),
            "example.com/r/rust"
        );
        assert_eq!(
            strip_host_path("http://example.com/path"),
            "example.com/path"
        );
        assert_eq!(strip_host_path("example.com/path"), "example.com/path");
    }

    #[tokio::test]
    async fn test_run_rules_skips_non_matching_url() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("rule.star"),
            "URLS = [\"other.com\"]\ndef process(request):\n    block_page()\n",
        )
        .expect("write");

        let engine = ScriptEngine::new(tmp.path().to_path_buf(), 0.01)
            .await
            .expect("ScriptEngine::new");

        let c = ctx("http://example.com/");
        let ops = tokio::task::spawn_blocking(move || engine.run_rules(&c))
            .await
            .expect("spawn_blocking");
        assert!(
            ops.is_empty(),
            "non-matching URL must produce no ops: {ops:?}"
        );
    }

    #[tokio::test]
    async fn test_run_rules_applies_matching_url() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("rule.star"),
            "URLS = [\"example.com\"]\ndef process(request):\n    block_page()\n",
        )
        .expect("write");

        let engine = ScriptEngine::new(tmp.path().to_path_buf(), 0.01)
            .await
            .expect("ScriptEngine::new");

        let c = ctx("http://example.com/");
        let ops = tokio::task::spawn_blocking(move || engine.run_rules(&c))
            .await
            .expect("spawn_blocking");
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], RewriteOp::BlockPage));
    }

    #[tokio::test]
    async fn test_run_rules_wildcard_matches_all_hosts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            tmp.path().join("rule.star"),
            "URLS = [\"*\"]\ndef process(request):\n    block_page()\n",
        )
        .expect("write");

        let engine = ScriptEngine::new(tmp.path().to_path_buf(), 0.01)
            .await
            .expect("ScriptEngine::new");

        for host in ["example.com", "reddit.com", "news.ycombinator.com"] {
            let url = format!("http://{host}/");
            let c = RequestCtx {
                url: url.clone(),
                host: host.to_owned(),
                content_type: "text/html".into(),
                scan_matches: Vec::new(),
                content_length: 0,
            };
            let e = engine.clone();
            let ops = tokio::task::spawn_blocking(move || e.run_rules(&c))
                .await
                .expect("spawn_blocking");
            assert_eq!(ops.len(), 1, "wildcard should match {host}: {ops:?}");
        }
    }

    #[tokio::test]
    async fn test_run_rules_resets_density_threshold_to_default() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let engine = ScriptEngine::new(tmp.path().to_path_buf(), 0.5)
            .await
            .expect("ScriptEngine::new");

        let c = ctx("http://example.com/");
        // run_rules must run on a blocking thread; read back the thread-local from that same thread.
        let threshold_after = tokio::task::spawn_blocking(move || {
            engine.run_rules(&c);
            DENSITY_THRESHOLD.with(|t| *t.borrow())
        })
        .await
        .expect("spawn_blocking");

        assert_eq!(
            threshold_after, DEFAULT_DENSITY_THRESHOLD,
            "threshold must be reset to DEFAULT_DENSITY_THRESHOLD after run_rules"
        );
    }

    #[tokio::test]
    async fn test_script_engine_new_creates_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let rules_dir = tmp.path().join("rules");
        assert!(!rules_dir.exists());

        let engine = ScriptEngine::new(rules_dir.clone(), 0.01)
            .await
            .expect("ScriptEngine::new");
        assert!(rules_dir.exists(), "rules dir should be created");
        assert_eq!(engine.rules_dir(), rules_dir);
    }
}
