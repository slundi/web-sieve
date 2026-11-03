//! Starlark scripting engine with hot-reload support.

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use glob::{MatchOptions, Pattern as GlobPattern};
use starlark::environment::{FrozenModule, GlobalsBuilder, Module};
use starlark::eval::Evaluator;
use starlark::starlark_module;
use starlark::syntax::{AstModule, Dialect};
use starlark::values::Value;
use starlark::values::dict::{AllocDict, DictRef};
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
    /// HTTP response status code for the current `execute_rule` call, read by `status_code()`.
    static STATUS_CODE: Cell<i64> = const { Cell::new(0) };
    /// Forwarded request headers as `(lowercased-name, value)` pairs, read by `request_headers()`.
    static REQUEST_HEADERS: RefCell<Vec<(String, String)>> = const { RefCell::new(Vec::new()) };
    /// Response headers as `(lowercased-name, value)` pairs, read by `response_headers()`.
    static RESPONSE_HEADERS: RefCell<Vec<(String, String)>> = const { RefCell::new(Vec::new()) };
    /// Raw response body for the current `execute_rule` call. Used only for lazy
    /// HTML metadata extraction — never touched unless a metadata global is called.
    static PAGE_BODY: RefCell<Bytes> = const { RefCell::new(Bytes::new()) };
    /// Memoized HTML metadata parse. `None` until the first of `page_title()`,
    /// `meta_description()`, or `meta_tags()` is called within a rule invocation,
    /// so rules that read no metadata pay no parsing cost.
    static PAGE_META: RefCell<Option<PageMeta>> = const { RefCell::new(None) };
}

/// HTML metadata extracted lazily from the response body and memoized per rule
/// invocation via the [`PAGE_META`] thread-local.
#[derive(Debug, Default, Clone)]
struct PageMeta {
    /// Text content of the `<title>` element (empty if absent).
    title: String,
    /// Content of `<meta name="description">` (empty if absent).
    description: String,
    /// All `<meta name|property="…" content="…">` pairs, deduplicated (last wins).
    tags: Vec<(String, String)>,
}

/// Parse the `<title>` and `<meta>` tags out of an HTML body.
///
/// Both the `name` and `property` attributes are treated as meta-tag keys so
/// OpenGraph tags (`property="og:type"`) are exposed alongside standard ones.
fn parse_page_meta(body: &[u8]) -> PageMeta {
    let html = String::from_utf8_lossy(body);
    let doc = scraper::Html::parse_document(&html);

    let title_sel = scraper::Selector::parse("title").expect("static selector");
    let meta_sel = scraper::Selector::parse("meta").expect("static selector");

    let title = doc
        .select(&title_sel)
        .next()
        .map(|e| e.text().collect::<String>().trim().to_owned())
        .unwrap_or_default();

    let mut description = String::new();
    let mut tags: Vec<(String, String)> = Vec::new();
    for el in doc.select(&meta_sel) {
        let key = el
            .value()
            .attr("name")
            .or_else(|| el.value().attr("property"));
        if let (Some(key), Some(content)) = (key, el.value().attr("content")) {
            if key.eq_ignore_ascii_case("description") {
                description = content.to_owned();
            }
            tags.push((key.to_owned(), content.to_owned()));
        }
    }

    PageMeta {
        title,
        description,
        tags: dedup_last(tags),
    }
}

/// Run `f` against the memoized [`PageMeta`], parsing the body on first access.
fn with_page_meta<R>(f: impl FnOnce(&PageMeta) -> R) -> R {
    PAGE_META.with(|cell| {
        if cell.borrow().is_none() {
            let parsed = PAGE_BODY.with(|b| parse_page_meta(&b.borrow()));
            *cell.borrow_mut() = Some(parsed);
        }
        f(cell.borrow().as_ref().expect("just populated"))
    })
}

/// Deduplicate `(key, value)` pairs by key, keeping the last value and preserving
/// first-seen order. Guards the dict allocators against duplicate keys.
fn dedup_last(pairs: Vec<(String, String)>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        if let Some(existing) = out.iter_mut().find(|(ek, _)| *ek == k) {
            existing.1 = v;
        } else {
            out.push((k, v));
        }
    }
    out
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

    /// Replace the page with the Minijinja template `name`, rendered against
    /// `context`.
    ///
    /// `context` must be a dict; it is JSON-encoded here and decoded by the
    /// rewriter, so every value in it must be JSON-representable (str, int,
    /// float, bool, None, list, dict).
    ///
    /// Example:
    /// ```python
    /// def process(request):
    ///     render_template("torrent-list", {"title": page_title()})
    /// ```
    fn render_template<'v>(name: String, context: Value<'v>) -> anyhow::Result<NoneType> {
        if DictRef::from_value(context).is_none() {
            return Err(anyhow::anyhow!(
                "render_template('{name}'): context must be a dict, got {}",
                context.get_type()
            ));
        }
        let encoded = serde_json::to_string(&context).map_err(|e| {
            anyhow::anyhow!("render_template('{name}'): context is not JSON-serialisable: {e}")
        })?;
        PENDING_OPS.with(|ops| {
            ops.borrow_mut().push(RewriteOp::RenderTemplate {
                name,
                context: encoded,
            });
        });
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

    /// Return the HTTP response status code, e.g. `200` or `404`.
    fn status_code() -> anyhow::Result<i64> {
        Ok(STATUS_CODE.with(|s| s.get()))
    }

    /// Return the text content of the page `<title>` element, or `""` if absent.
    ///
    /// Parses the HTML body on first call (memoized per rule invocation), so
    /// rules that never read metadata incur no parsing cost.
    fn page_title() -> anyhow::Result<String> {
        Ok(with_page_meta(|m| m.title.clone()))
    }

    /// Return the `<meta name="description">` content, or `""` if absent.
    fn meta_description() -> anyhow::Result<String> {
        Ok(with_page_meta(|m| m.description.clone()))
    }

    /// Return a dict of every `<meta name|property="…" content="…">` pair.
    ///
    /// OpenGraph tags (`property="og:type"`) are keyed alongside standard
    /// `name` meta tags. Duplicate keys keep the last value.
    fn meta_tags<'v>(eval: &mut Evaluator<'v, '_, '_>) -> anyhow::Result<Value<'v>> {
        let pairs = with_page_meta(|m| m.tags.clone());
        Ok(eval.heap().alloc(AllocDict(pairs)))
    }

    /// Return a dict of response headers with lower-cased names.
    ///
    /// Duplicate header names keep the last value seen.
    fn response_headers<'v>(eval: &mut Evaluator<'v, '_, '_>) -> anyhow::Result<Value<'v>> {
        let pairs = RESPONSE_HEADERS.with(|h| h.borrow().clone());
        Ok(eval.heap().alloc(AllocDict(pairs)))
    }

    /// Return a dict of forwarded request headers with lower-cased names.
    ///
    /// Duplicate header names keep the last value seen.
    fn request_headers<'v>(eval: &mut Evaluator<'v, '_, '_>) -> anyhow::Result<Value<'v>> {
        let pairs = REQUEST_HEADERS.with(|h| h.borrow().clone());
        Ok(eval.heap().alloc(AllocDict(pairs)))
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
    /// HTTP response status code.
    pub status_code: u16,
    /// Forwarded request headers as `(lowercased-name, value)` pairs.
    pub request_headers: Vec<(String, String)>,
    /// Response headers as `(lowercased-name, value)` pairs.
    pub response_headers: Vec<(String, String)>,
    /// Scan matches from the text scanner (category → hit count).
    pub scan_matches: Vec<ScanMatch>,
    /// Byte length of the response body.
    pub content_length: usize,
    /// Raw response body, used for lazy HTML metadata extraction.
    pub body: Bytes,
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
        let mut star_paths = collect_star_files(&rules_dir).await?;
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
        // Recursive so a community script shipped as `rules/<script>/<name>.star`
        // alongside its assets hot-reloads like a top-level rule.
        watcher.watch(&rules_dir, RecursiveMode::Recursive)?;

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

/// Collect every `.star` file in `rules_dir` and in its immediate
/// subdirectories.
///
/// One level of nesting is enough for the per-script layout
/// (`rules/<script>/<script>.star` next to that script's `css`, `js`, and
/// `icon`), and bounding the depth keeps a deep or looping directory tree from
/// stalling startup.
async fn collect_star_files(rules_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    fn is_star(path: &Path) -> bool {
        path.extension().and_then(|e| e.to_str()) == Some("star")
    }

    let mut found: Vec<PathBuf> = Vec::new();
    let mut read_dir = tokio::fs::read_dir(rules_dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let path = entry.path();
        let Ok(file_type) = entry.file_type().await else {
            continue;
        };

        if file_type.is_file() {
            if is_star(&path) {
                found.push(path);
            }
            continue;
        }

        if !file_type.is_dir() {
            continue;
        }
        let Ok(mut nested) = tokio::fs::read_dir(&path).await else {
            tracing::warn!(path = %path.display(), "cannot read script folder, skipping");
            continue;
        };
        while let Some(nested_entry) = nested.next_entry().await? {
            let nested_path = nested_entry.path();
            if nested_path.is_file() && is_star(&nested_path) {
                found.push(nested_path);
            }
        }
    }
    Ok(found)
}

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

    // Clear any leftover ops and populate the per-invocation context read by the
    // content-inspection globals. HTML metadata is parsed lazily on first access,
    // so we only stash the raw body and reset the memo here.
    PENDING_OPS.with(|ops| ops.borrow_mut().clear());
    SCAN_CTX.with(|sc| {
        *sc.borrow_mut() = (ctx.scan_matches.clone(), ctx.content_length);
    });
    STATUS_CODE.with(|s| s.set(ctx.status_code as i64));
    REQUEST_HEADERS.with(|h| *h.borrow_mut() = dedup_last(ctx.request_headers.clone()));
    RESPONSE_HEADERS.with(|h| *h.borrow_mut() = dedup_last(ctx.response_headers.clone()));
    PAGE_BODY.with(|b| *b.borrow_mut() = ctx.body.clone());
    PAGE_META.with(|m| *m.borrow_mut() = None);

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

    // Always clear the per-invocation context after the rule runs.
    SCAN_CTX.with(|sc| *sc.borrow_mut() = (Vec::new(), 0));
    STATUS_CODE.with(|s| s.set(0));
    REQUEST_HEADERS.with(|h| h.borrow_mut().clear());
    RESPONSE_HEADERS.with(|h| h.borrow_mut().clear());
    PAGE_BODY.with(|b| *b.borrow_mut() = Bytes::new());
    PAGE_META.with(|m| *m.borrow_mut() = None);

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
            status_code: 200,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            scan_matches: Vec::new(),
            content_length: 0,
            body: Bytes::new(),
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
    fn test_execute_rule_render_template_queues_op() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    render_template("torrent-list", {"title": "Hi", "count": 2})
"#,
        );
        let rule = load_rule(f.path()).expect("load");
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        assert_eq!(ops.len(), 1, "expected one op: {ops:?}");
        let RewriteOp::RenderTemplate { name, context } = &ops[0] else {
            panic!("expected RenderTemplate, got {:?}", ops[0]);
        };
        assert_eq!(name, "torrent-list");
        let parsed: serde_json::Value = serde_json::from_str(context).expect("context is JSON");
        assert_eq!(parsed["title"], "Hi");
        assert_eq!(parsed["count"], 2);
    }

    #[test]
    fn test_execute_rule_render_template_nested_context() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    render_template("list", {"items": [{"name": "a"}, {"name": "b"}], "ok": True})
"#,
        );
        let rule = load_rule(f.path()).expect("load");
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        let RewriteOp::RenderTemplate { context, .. } = &ops[0] else {
            panic!("expected RenderTemplate, got {:?}", ops[0]);
        };
        let parsed: serde_json::Value = serde_json::from_str(context).expect("context is JSON");
        assert_eq!(parsed["items"][1]["name"], "b");
        assert_eq!(parsed["ok"], true);
    }

    #[test]
    fn test_execute_rule_render_template_rejects_non_dict_context() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    render_template("list", "not a dict")
"#,
        );
        let rule = load_rule(f.path()).expect("load");
        // The error aborts process(); no ops survive the failed invocation.
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        assert!(
            ops.is_empty(),
            "a non-dict context must abort the rule: {ops:?}"
        );
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
        let p = vec![GlobPattern::new("example.com").unwrap()];
        assert!(rule_matches_url(&p, "http://example.com/", "example.com"));
        assert!(!rule_matches_url(
            &p,
            "http://www.example.com/",
            "www.example.com"
        ));
    }

    #[test]
    fn test_rule_matches_url_subdomain_wildcard() {
        let p = vec![GlobPattern::new("*.example.com").unwrap()];
        assert!(rule_matches_url(
            &p,
            "http://www.example.com/",
            "www.example.com"
        ));
        assert!(rule_matches_url(
            &p,
            "http://old.example.com/page",
            "old.example.com"
        ));
        assert!(!rule_matches_url(&p, "http://example.com/", "example.com"));
    }

    #[test]
    fn test_rule_matches_url_catch_all() {
        let p = vec![GlobPattern::new("*").unwrap()];
        assert!(rule_matches_url(&p, "http://anything.io/", "anything.io"));
        assert!(rule_matches_url(
            &p,
            "https://reddit.com/r/rust",
            "reddit.com"
        ));
    }

    #[test]
    fn test_rule_matches_url_path_glob() {
        let p = vec![GlobPattern::new("example.com/r/*").unwrap()];
        assert!(rule_matches_url(
            &p,
            "http://example.com/r/rust",
            "example.com"
        ));
        assert!(!rule_matches_url(
            &p,
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
    async fn test_collect_star_files_finds_top_level_and_nested() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("top.star"), "x").expect("write top");
        std::fs::create_dir_all(tmp.path().join("nyaa")).expect("mkdir");
        std::fs::write(tmp.path().join("nyaa/nyaa.star"), "x").expect("write nested");
        // Non-star files and nested assets must be ignored.
        std::fs::write(tmp.path().join("notes.txt"), "x").expect("write txt");
        std::fs::write(tmp.path().join("nyaa/style.css"), "x").expect("write css");

        let mut found = collect_star_files(tmp.path()).await.expect("collect");
        found.sort_unstable();
        assert_eq!(found.len(), 2, "expected 2 .star files: {found:?}");
        assert!(found.iter().any(|p| p.ends_with("top.star")));
        assert!(found.iter().any(|p| p.ends_with("nyaa/nyaa.star")));
    }

    #[tokio::test]
    async fn test_collect_star_files_ignores_second_level_nesting() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("a/b")).expect("mkdir");
        std::fs::write(tmp.path().join("a/b/deep.star"), "x").expect("write deep");

        let found = collect_star_files(tmp.path()).await.expect("collect");
        assert!(
            found.is_empty(),
            "only one level of nesting is scanned: {found:?}"
        );
    }

    #[tokio::test]
    async fn test_script_engine_loads_rule_from_per_script_folder() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("nyaa")).expect("mkdir");
        std::fs::write(
            tmp.path().join("nyaa/nyaa.star"),
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
        assert_eq!(ops.len(), 1, "rule in rules/<script>/ must load: {ops:?}");
        assert!(matches!(ops[0], RewriteOp::BlockPage));
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
                status_code: 200,
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                scan_matches: Vec::new(),
                content_length: 0,
                body: Bytes::new(),
            };
            let e = engine.clone();
            let ops = tokio::task::spawn_blocking(move || e.run_rules(&c))
                .await
                .expect("spawn_blocking");
            assert_eq!(ops.len(), 1, "wildcard should match {host}: {ops:?}");
        }
    }

    // ─── Content-access global tests ────────────────────────────────────────────

    #[test]
    fn test_dedup_last_keeps_last_value_and_order() {
        let pairs = vec![
            ("a".to_owned(), "1".to_owned()),
            ("b".to_owned(), "2".to_owned()),
            ("a".to_owned(), "3".to_owned()),
        ];
        assert_eq!(
            dedup_last(pairs),
            vec![
                ("a".to_owned(), "3".to_owned()),
                ("b".to_owned(), "2".to_owned())
            ]
        );
    }

    #[test]
    fn test_parse_page_meta_extracts_title_description_and_tags() {
        let html = br#"<html><head>
            <title>  Hello World  </title>
            <meta name="description" content="A test page">
            <meta property="og:type" content="article">
            <meta name="keywords" content="a,b,c">
        </head><body>x</body></html>"#;
        let meta = parse_page_meta(html);
        assert_eq!(meta.title, "Hello World");
        assert_eq!(meta.description, "A test page");
        assert_eq!(
            meta.tags
                .iter()
                .find(|(k, _)| k == "og:type")
                .map(|(_, v)| v.as_str()),
            Some("article")
        );
        assert_eq!(
            meta.tags
                .iter()
                .find(|(k, _)| k == "keywords")
                .map(|(_, v)| v.as_str()),
            Some("a,b,c")
        );
    }

    #[test]
    fn test_parse_page_meta_absent_fields_are_empty() {
        let meta = parse_page_meta(b"<html><body>no head</body></html>");
        assert!(meta.title.is_empty());
        assert!(meta.description.is_empty());
        assert!(meta.tags.is_empty());
    }

    #[test]
    fn test_status_code_global() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    if status_code() == 404:
        block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.status_code = 404;
        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1, "404 → block_page: {ops:?}");
        assert!(matches!(ops[0], RewriteOp::BlockPage));

        // A 200 response must not trigger the rule.
        let ops = execute_rule(&rule.frozen, &ctx("http://example.com/"));
        assert!(ops.is_empty(), "200 → no ops: {ops:?}");
    }

    #[test]
    fn test_page_title_global() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    if page_title() == "Breaking News":
        enable_reader_mode()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.body = Bytes::from_static(
            b"<html><head><title>Breaking News</title></head><body>x</body></html>",
        );
        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1, "title match → reader mode: {ops:?}");
        assert!(matches!(ops[0], RewriteOp::ReaderMode));
    }

    #[test]
    fn test_meta_description_global() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    if "sponsored" in meta_description():
        block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.body = Bytes::from_static(
            b"<html><head><meta name=\"description\" content=\"this is sponsored content\"></head><body>x</body></html>",
        );
        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1, "description match → block: {ops:?}");
        assert!(matches!(ops[0], RewriteOp::BlockPage));
    }

    #[test]
    fn test_meta_tags_global() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    if meta_tags().get("og:type") == "article":
        enable_reader_mode()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.body = Bytes::from_static(
            b"<html><head><meta property=\"og:type\" content=\"article\"></head><body>x</body></html>",
        );
        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1, "og:type=article → reader mode: {ops:?}");
        assert!(matches!(ops[0], RewriteOp::ReaderMode));
    }

    #[test]
    fn test_response_headers_global() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    h = response_headers()
    if h.get("x-frame-options") == "DENY":
        block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.response_headers = vec![("x-frame-options".into(), "DENY".into())];
        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1, "header match → block: {ops:?}");
        assert!(matches!(ops[0], RewriteOp::BlockPage));
    }

    #[test]
    fn test_request_headers_global() {
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    ua = request_headers().get("user-agent", "")
    if "curl" in ua:
        block_page()
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.request_headers = vec![("user-agent".into(), "curl/8.0".into())];
        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1, "user-agent match → block: {ops:?}");
        assert!(matches!(ops[0], RewriteOp::BlockPage));
    }

    #[test]
    fn test_metadata_not_parsed_when_unused() {
        // A rule that never calls a metadata global must run fine even when the
        // body is not valid HTML — proving no eager parse occurs.
        let f = write_tempfile(
            r#"
URLS = ["example.com"]
def process(request):
    remove_element("div.ad")
"#,
        );
        let rule = load_rule(f.path()).expect("load");

        let mut c = ctx("http://example.com/");
        c.body = Bytes::from_static(b"\xff\xfe not html at all");
        let ops = execute_rule(&rule.frozen, &c);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0], RewriteOp::RemoveElement("div.ad".into()));
    }

    #[test]
    fn test_execute_rule_clears_status_code_after_run() {
        let f = write_tempfile("URLS = [\"example.com\"]\ndef process(request):\n    pass\n");
        let rule = load_rule(f.path()).expect("load");
        let mut c = ctx("http://example.com/");
        c.status_code = 500;
        execute_rule(&rule.frozen, &c);
        assert_eq!(
            STATUS_CODE.with(|s| s.get()),
            0,
            "status code thread-local must be reset after execute_rule"
        );
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
