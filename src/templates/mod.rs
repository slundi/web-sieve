//! Minijinja template engine with hot-reload support.
//!
//! Users author display templates in the XDG data directory under
//! `templates/` (default `~/.local/share/web-sieve/templates/`). Starlark
//! rules reference them by name through the `render_template(name, context)`
//! binding, which queues a [`crate::rewriter::RewriteOp::RenderTemplate`]
//! operation; the rewriter then resolves the name here and renders it.
//!
//! Templates are shared: several rules may reference the same template, and
//! templates may inherit from one another with Minijinja's `{% extends %}` /
//! `{% block %}` tags.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use minijinja::Environment;

/// Files whose name starts with `.` or ends with `~` are editor artefacts and
/// are never registered as templates.
fn is_template_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| !name.starts_with('.') && !name.ends_with('~'))
}

/// Names a template file is registered under.
///
/// A file is always available under its full file name (`base.html`) so
/// `{% extends "base.html" %}` resolves, and additionally under its stem
/// (`base`) so `render_template("base", …)` works without an extension.
///
/// Two files sharing a stem (`a.html` and `a.txt`) collide on the stem entry;
/// the alphabetically last one wins. Give templates distinct stems.
fn template_names(path: &Path) -> Vec<String> {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return Vec::new();
    };
    let mut names = vec![file_name.to_owned()];
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        && stem != file_name
    {
        names.push(stem.to_owned());
    }
    names
}

/// Read every template file in `dir` and compile it into a fresh
/// [`Environment`].
///
/// A template that cannot be read or fails to parse is logged and skipped so a
/// single broken file never takes the whole template set down.
async fn build_environment(dir: &Path) -> std::io::Result<Environment<'static>> {
    let mut env = Environment::new();

    let mut paths: Vec<PathBuf> = Vec::new();
    let mut read_dir = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let path = entry.path();
        let is_file = entry
            .file_type()
            .await
            .map(|ft| ft.is_file())
            .unwrap_or(false);
        if is_file && is_template_file(&path) {
            paths.push(path);
        }
    }
    paths.sort_unstable();

    for path in &paths {
        let source = match tokio::fs::read_to_string(path).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "failed to read template");
                continue;
            }
        };
        for name in template_names(path) {
            if let Err(e) = env.add_template_owned(name.clone(), source.clone()) {
                tracing::warn!(template = %name, error = %e, "failed to compile template");
            }
        }
    }

    Ok(env)
}

/// Loads, hot-reloads, and renders Minijinja templates from a directory.
///
/// # Examples
///
/// ```no_run
/// # async fn demo() -> anyhow::Result<()> {
/// use std::path::PathBuf;
/// use web_sieve::templates::TemplateEngine;
///
/// let engine = TemplateEngine::new(PathBuf::from("/tmp/templates")).await?;
/// let html = engine.render("torrent-list", &serde_json::json!({ "title": "x" }))?;
/// # let _ = html;
/// # Ok(())
/// # }
/// ```
pub struct TemplateEngine {
    /// Compiled template set, swapped wholesale on every reload.
    ///
    /// A `std` lock is used rather than a `tokio` one because rendering runs on
    /// the blocking pool inside the rewriter; no critical section ever awaits.
    env: Arc<RwLock<Environment<'static>>>,
    /// Directory the templates were loaded from.
    templates_dir: PathBuf,
    /// Kept alive for the lifetime of the engine; dropping it stops hot-reload.
    _watcher: Box<dyn notify::Watcher + Send + Sync>,
}

impl TemplateEngine {
    /// Create a [`TemplateEngine`] that watches `templates_dir` for changes.
    ///
    /// The directory is created if it does not exist. Every file in it is
    /// compiled at startup; a background task rebuilds the whole template set
    /// whenever a file is created, modified, or removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or read, or if a
    /// filesystem watcher cannot be installed.
    pub async fn new(templates_dir: PathBuf) -> anyhow::Result<Arc<Self>> {
        use notify::{RecursiveMode, Watcher, recommended_watcher};
        use tokio::sync::mpsc;

        tokio::fs::create_dir_all(&templates_dir).await?;

        let env = Arc::new(RwLock::new(build_environment(&templates_dir).await?));

        let (tx, mut rx) = mpsc::channel::<notify::Result<notify::Event>>(32);
        let mut watcher = recommended_watcher(move |res| {
            let _ = tx.blocking_send(res);
        })?;
        watcher.watch(&templates_dir, RecursiveMode::NonRecursive)?;

        let env_for_task = Arc::clone(&env);
        let dir_for_task = templates_dir.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    Ok(ev) => handle_notify_event(ev, &dir_for_task, &env_for_task).await,
                    Err(e) => tracing::warn!("template watcher error: {e}"),
                }
            }
        });

        Ok(Arc::new(TemplateEngine {
            env,
            templates_dir,
            _watcher: Box::new(watcher),
        }))
    }

    /// Render the template called `name` against `context`.
    ///
    /// `name` may be the template's file name (`torrent-list.html`) or its
    /// stem (`torrent-list`).
    ///
    /// # Errors
    ///
    /// Returns an error if no template is registered under `name` or if
    /// rendering fails (undefined filter, failing `{% extends %}`, …).
    pub fn render(&self, name: &str, context: &serde_json::Value) -> anyhow::Result<String> {
        let env = self.env.read().unwrap_or_else(|e| e.into_inner());
        let template = env
            .get_template(name)
            .map_err(|e| anyhow::anyhow!("template '{name}': {e}"))?;
        template
            .render(minijinja::value::Serde(context))
            .map_err(|e| anyhow::anyhow!("rendering template '{name}': {e}"))
    }

    /// Return the directory this engine watches.
    pub fn templates_dir(&self) -> &Path {
        &self.templates_dir
    }

    /// Return `true` if a template is registered under `name`.
    pub fn has_template(&self, name: &str) -> bool {
        let env = self.env.read().unwrap_or_else(|e| e.into_inner());
        env.get_template(name).is_ok()
    }
}

/// Rebuild the whole template set when a watched file changes.
///
/// A full rebuild (rather than a per-file patch) keeps removals and stem
/// collisions consistent; template directories are small enough that the extra
/// reads are irrelevant next to a page render.
async fn handle_notify_event(event: notify::Event, dir: &Path, env: &RwLock<Environment<'static>>) {
    use notify::EventKind;

    if !matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    ) {
        return;
    }
    if !event.paths.iter().any(|p| is_template_file(p)) {
        return;
    }

    match build_environment(dir).await {
        Ok(new_env) => {
            *env.write().unwrap_or_else(|e| e.into_inner()) = new_env;
            tracing::info!(dir = %dir.display(), "templates reloaded");
        }
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "failed to reload templates");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_template(dir: &Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("write template");
    }

    #[test]
    fn test_template_names_includes_file_name_and_stem() {
        assert_eq!(
            template_names(Path::new("/t/base.html")),
            vec!["base.html".to_owned(), "base".to_owned()]
        );
    }

    #[test]
    fn test_template_names_without_extension_is_single_entry() {
        assert_eq!(
            template_names(Path::new("/t/plain")),
            vec!["plain".to_owned()]
        );
    }

    #[test]
    fn test_is_template_file_rejects_hidden_and_backup() {
        assert!(is_template_file(Path::new("/t/page.html")));
        assert!(!is_template_file(Path::new("/t/.page.html.swp")));
        assert!(!is_template_file(Path::new("/t/page.html~")));
    }

    #[tokio::test]
    async fn test_new_creates_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("templates");
        assert!(!dir.exists());

        let engine = TemplateEngine::new(dir.clone()).await.expect("engine");
        assert!(dir.exists(), "templates dir should be created");
        assert_eq!(engine.templates_dir(), dir);
    }

    #[tokio::test]
    async fn test_render_substitutes_context() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(tmp.path(), "greet.html", "<h1>{{ title }}</h1>");

        let engine = TemplateEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");
        let out = engine
            .render("greet", &serde_json::json!({ "title": "Hello" }))
            .expect("render");
        assert_eq!(out, "<h1>Hello</h1>");
    }

    #[tokio::test]
    async fn test_render_by_file_name_and_by_stem() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(tmp.path(), "page.html", "{{ value }}");

        let engine = TemplateEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");
        let ctx = serde_json::json!({ "value": "x" });
        assert_eq!(engine.render("page.html", &ctx).expect("by name"), "x");
        assert_eq!(engine.render("page", &ctx).expect("by stem"), "x");
    }

    #[tokio::test]
    async fn test_render_unknown_template_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let engine = TemplateEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");
        let err = engine
            .render("nope", &serde_json::json!({}))
            .expect_err("unknown template must error");
        assert!(
            err.to_string().contains("nope"),
            "error should name the template: {err}"
        );
    }

    #[tokio::test]
    async fn test_render_iterates_over_list_context() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(
            tmp.path(),
            "list.html",
            "{% for item in items %}<li>{{ item.name }}</li>{% endfor %}",
        );

        let engine = TemplateEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");
        let out = engine
            .render(
                "list",
                &serde_json::json!({ "items": [{ "name": "a" }, { "name": "b" }] }),
            )
            .expect("render");
        assert_eq!(out, "<li>a</li><li>b</li>");
    }

    #[tokio::test]
    async fn test_render_supports_template_inheritance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(
            tmp.path(),
            "base.html",
            "<html><body>{% block content %}{% endblock %}</body></html>",
        );
        write_template(
            tmp.path(),
            "child.html",
            "{% extends \"base.html\" %}{% block content %}{{ msg }}{% endblock %}",
        );

        let engine = TemplateEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");
        let out = engine
            .render("child", &serde_json::json!({ "msg": "hi" }))
            .expect("render");
        assert_eq!(out, "<html><body>hi</body></html>");
    }

    #[tokio::test]
    async fn test_broken_template_is_skipped_others_still_load() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(tmp.path(), "broken.html", "{% for x in %}");
        write_template(tmp.path(), "ok.html", "fine");

        let engine = TemplateEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");
        assert!(
            !engine.has_template("broken"),
            "a template with a syntax error must not register"
        );
        assert_eq!(
            engine.render("ok", &serde_json::json!({})).expect("ok"),
            "fine"
        );
    }

    #[tokio::test]
    async fn test_hidden_and_backup_files_are_not_registered() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(tmp.path(), ".hidden.html", "nope");
        write_template(tmp.path(), "page.html~", "nope");

        let engine = TemplateEngine::new(tmp.path().to_path_buf())
            .await
            .expect("engine");
        assert!(!engine.has_template(".hidden.html"));
        assert!(!engine.has_template("page.html~"));
        assert!(!engine.has_template("page.html"));
    }

    #[tokio::test]
    async fn test_handle_notify_event_reloads_modified_template() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(tmp.path(), "page.html", "v1");

        let env = RwLock::new(build_environment(tmp.path()).await.expect("build"));
        write_template(tmp.path(), "page.html", "v2");

        let event = notify::Event {
            kind: notify::EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Any,
            )),
            paths: vec![tmp.path().join("page.html")],
            attrs: Default::default(),
        };
        handle_notify_event(event, tmp.path(), &env).await;

        let guard = env.read().expect("read");
        let rendered = guard
            .get_template("page")
            .expect("template")
            .render(minijinja::value::Serde(&serde_json::json!({})))
            .expect("render");
        assert_eq!(rendered, "v2", "watcher must pick up the modified source");
    }

    #[tokio::test]
    async fn test_handle_notify_event_drops_removed_template() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(tmp.path(), "page.html", "v1");

        let env = RwLock::new(build_environment(tmp.path()).await.expect("build"));
        std::fs::remove_file(tmp.path().join("page.html")).expect("remove");

        let event = notify::Event {
            kind: notify::EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![tmp.path().join("page.html")],
            attrs: Default::default(),
        };
        handle_notify_event(event, tmp.path(), &env).await;

        let guard = env.read().expect("read");
        assert!(
            guard.get_template("page").is_err(),
            "removed template must be unregistered"
        );
    }

    #[tokio::test]
    async fn test_handle_notify_event_ignores_unrelated_kinds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_template(tmp.path(), "page.html", "v1");

        let env = RwLock::new(build_environment(tmp.path()).await.expect("build"));
        write_template(tmp.path(), "page.html", "v2");

        let event = notify::Event {
            kind: notify::EventKind::Access(notify::event::AccessKind::Read),
            paths: vec![tmp.path().join("page.html")],
            attrs: Default::default(),
        };
        handle_notify_event(event, tmp.path(), &env).await;

        let guard = env.read().expect("read");
        let rendered = guard
            .get_template("page")
            .expect("template")
            .render(minijinja::value::Serde(&serde_json::json!({})))
            .expect("render");
        assert_eq!(rendered, "v1", "access events must not trigger a reload");
    }
}
