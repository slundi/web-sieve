//! High-speed multi-dictionary text scanner using aho-corasick.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use tokio::sync::RwLock;

// ─── Private: Compiled dictionary ───────────────────────────────────────────

struct Dictionary {
    category: String,
    automaton: AhoCorasick,
}

// ─── Public types ────────────────────────────────────────────────────────────

/// Match result from a single dictionary category.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanMatch {
    /// Category name derived from the dictionary filename stem.
    pub category: String,
    /// Number of pattern occurrences found in the scanned payload.
    pub count: usize,
}

// ─── Public: Text scanner ────────────────────────────────────────────────────

/// Multi-dictionary text scanner backed by Aho-Corasick automata.
///
/// Each `*.txt` file in `dicts_dir` defines one category. The file stem
/// becomes the category name. Each non-empty, non-comment (`#`) line is a
/// case-insensitive search pattern.
///
/// The scanner watches `dicts_dir` for changes and hot-reloads dictionaries
/// on any create, modify, or remove event.
///
/// # Examples
///
/// ```no_run
/// use std::path::PathBuf;
/// use web_sieve::scanner::TextScanner;
///
/// # tokio_test::block_on(async {
/// let scanner = TextScanner::new(PathBuf::from("/tmp/dicts")).await.unwrap();
/// let matches = scanner.scan(b"some page text");
/// # })
/// ```
pub struct TextScanner {
    dicts: Arc<RwLock<Vec<Dictionary>>>,
    dicts_dir: PathBuf,
    _watcher: Box<dyn notify::Watcher + Send + Sync>,
}

impl TextScanner {
    /// Create a new [`TextScanner`] watching `dicts_dir` for `*.txt` dictionary files.
    ///
    /// The directory is created if it does not exist. All `*.txt` files present
    /// at startup are loaded immediately. A background task hot-reloads the
    /// dictionaries whenever a file is created, modified, or removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created or a file watcher
    /// cannot be initialised.
    pub async fn new(dicts_dir: PathBuf) -> anyhow::Result<Arc<Self>> {
        use notify::{RecursiveMode, Watcher, recommended_watcher};
        use tokio::sync::mpsc;

        tokio::fs::create_dir_all(&dicts_dir).await?;

        let initial_dicts = load_all_dicts(&dicts_dir).await;
        let dicts = Arc::new(RwLock::new(initial_dicts));

        let (tx, mut rx) = mpsc::channel::<notify::Result<notify::Event>>(32);
        let mut watcher = recommended_watcher(move |res| {
            let _ = tx.blocking_send(res);
        })?;
        watcher.watch(&dicts_dir, RecursiveMode::NonRecursive)?;

        let dicts_for_task = Arc::clone(&dicts);
        let dicts_dir_clone = dicts_dir.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    Ok(ev) => {
                        let relevant = ev
                            .paths
                            .iter()
                            .any(|p| p.extension().and_then(|e| e.to_str()) == Some("txt"));
                        if relevant {
                            use notify::EventKind;
                            match ev.kind {
                                EventKind::Create(_)
                                | EventKind::Modify(_)
                                | EventKind::Remove(_) => {
                                    tracing::info!(
                                        dir = %dicts_dir_clone.display(),
                                        "dictionaries changed, reloading"
                                    );
                                    let new_dicts = load_all_dicts(&dicts_dir_clone).await;
                                    *dicts_for_task.write().await = new_dicts;
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => tracing::warn!("scanner watcher error: {e}"),
                }
            }
        });

        Ok(Arc::new(Self {
            dicts,
            dicts_dir,
            _watcher: Box::new(watcher),
        }))
    }

    /// Scan `text` against all loaded dictionaries.
    ///
    /// Returns one [`ScanMatch`] per category that has at least one hit.
    /// Categories with zero matches are omitted. Matching is case-insensitive.
    pub async fn scan(&self, text: &[u8]) -> Vec<ScanMatch> {
        let dicts = self.dicts.read().await;
        let mut results = Vec::new();
        for dict in dicts.iter() {
            let count = dict.automaton.find_iter(text).count();
            if count > 0 {
                results.push(ScanMatch {
                    category: dict.category.clone(),
                    count,
                });
            }
        }
        results
    }

    /// Return the dictionaries directory this scanner watches.
    pub fn dicts_dir(&self) -> &Path {
        &self.dicts_dir
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

async fn load_all_dicts(dicts_dir: &Path) -> Vec<Dictionary> {
    let mut result = Vec::new();

    match tokio::fs::read_dir(dicts_dir).await {
        Ok(mut read_dir) => {
            while let Ok(Some(entry)) = read_dir.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("txt") {
                    match load_dict(&path).await {
                        Ok(dict) => result.push(dict),
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                error = %e,
                                "failed to load dictionary"
                            );
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                dir = %dicts_dir.display(),
                error = %e,
                "failed to read dicts directory"
            );
        }
    }

    result
}

async fn load_dict(path: &Path) -> anyhow::Result<Dictionary> {
    let category = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();

    let content = tokio::fs::read_to_string(path).await?;
    let patterns: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();

    anyhow::ensure!(
        !patterns.is_empty(),
        "dictionary '{category}' has no patterns"
    );

    let automaton = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .build(&patterns)
        .map_err(|e| anyhow::anyhow!("failed to build automaton for '{category}': {e}"))?;

    Ok(Dictionary {
        category,
        automaton,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_dict(dir: &Path, name: &str, content: &str) {
        let path = dir.join(format!("{name}.txt"));
        let mut f = std::fs::File::create(path).expect("create dict file");
        f.write_all(content.as_bytes()).expect("write dict");
    }

    #[tokio::test]
    async fn test_scanner_creates_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dicts_dir = tmp.path().join("dicts");
        assert!(!dicts_dir.exists());
        let scanner = TextScanner::new(dicts_dir.clone()).await.expect("scanner");
        assert!(dicts_dir.exists());
        assert_eq!(scanner.dicts_dir(), dicts_dir);
    }

    #[tokio::test]
    async fn test_scanner_empty_dir_no_matches() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scanner = TextScanner::new(tmp.path().to_path_buf())
            .await
            .expect("scanner");
        let results = scanner.scan(b"anything at all").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_scanner_no_match() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_dict(tmp.path(), "violence", "blood\nkill\nweapon\n");
        let scanner = TextScanner::new(tmp.path().to_path_buf())
            .await
            .expect("scanner");
        let results = scanner.scan(b"a completely safe page about flowers").await;
        assert!(results.is_empty(), "unexpected matches: {results:?}");
    }

    #[tokio::test]
    async fn test_scanner_single_category_hit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_dict(tmp.path(), "violence", "blood\nkill\nweapon\n");
        let scanner = TextScanner::new(tmp.path().to_path_buf())
            .await
            .expect("scanner");
        let results = scanner.scan(b"this page discusses blood and weapons").await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].category, "violence");
        assert_eq!(results[0].count, 2);
    }

    #[tokio::test]
    async fn test_scanner_case_insensitive() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_dict(tmp.path(), "drugs", "cocaine\nheroin\n");
        let scanner = TextScanner::new(tmp.path().to_path_buf())
            .await
            .expect("scanner");
        let results = scanner
            .scan(b"COCAINE and Heroin are dangerous substances")
            .await;
        assert_eq!(
            results.len(),
            1,
            "should match case-insensitively: {results:?}"
        );
        assert_eq!(results[0].count, 2);
    }

    #[tokio::test]
    async fn test_scanner_multiple_categories() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_dict(tmp.path(), "violence", "kill\nattack\n");
        write_dict(tmp.path(), "adult", "explicit\nsex\n");
        let scanner = TextScanner::new(tmp.path().to_path_buf())
            .await
            .expect("scanner");
        let results = scanner.scan(b"explicit violence and kill").await;
        assert_eq!(
            results.len(),
            2,
            "both categories should match: {results:?}"
        );
    }

    #[tokio::test]
    async fn test_scanner_comment_lines_ignored() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_dict(tmp.path(), "test", "# this is a comment\nactualterm\n");
        let scanner = TextScanner::new(tmp.path().to_path_buf())
            .await
            .expect("scanner");
        let no_match = scanner.scan(b"this is a comment").await;
        assert!(no_match.is_empty(), "comment should not be a pattern");
        let hit = scanner.scan(b"page with actualterm inside").await;
        assert_eq!(hit.len(), 1);
    }

    #[tokio::test]
    async fn test_scanner_empty_dict_skipped() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_dict(tmp.path(), "empty", "# only comments\n\n  \n");
        let scanner = TextScanner::new(tmp.path().to_path_buf())
            .await
            .expect("scanner");
        let results = scanner.scan(b"any text").await;
        assert!(results.is_empty(), "empty dict should produce no matches");
    }

    #[tokio::test]
    async fn test_scanner_count_multiple_occurrences() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_dict(tmp.path(), "spam", "buy now\n");
        let scanner = TextScanner::new(tmp.path().to_path_buf())
            .await
            .expect("scanner");
        let results = scanner.scan(b"buy now buy now buy now great deal").await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].count, 3);
    }
}
