# AI Content Detector — Roadmap

Standalone module that detects AI-generated web content and acts on it at two interception points:

- **Search Engine Results Pages (SERP):** suppress result entries whose domain is flagged as AI-heavy.
- **Visited pages:** inject a visible warning badge when the page's textual score exceeds the suspicion threshold.

Badge injection is applied on the **next load** of the same URL; the proxy rewrites the HTML stream via `lol-html` once the score is stored.

---

## Architecture Overview

```
[ Browser ] ──(request)──> [ web-sieve proxy ]
                                    │
          ┌─────────────────────────┴──────────────────────────────┐
          ▼  Synchronous fast path                                  ▼  Async worker (opt-in, off by default)
[ Forward response to browser ]                          [ Background prefetch pipeline ]
[ lol-html: inject badge / remove SERP entry            [ Download & analyse linked URLs ]
  if domain/URL already scored in redb ]                [ Feed scores into redb ]
```

**Pipeline order** (fail-fast, cheapest check first):

1. Check domain against `IS_AI_SLOP` flag in the domain store (redb, xxh3_64 key) — if flagged, score is maximum, skip textual analysis.
2. _(opt-in)_ Check `ai.txt` / `robots.txt` at domain root — treat as a supporting signal, not a conclusive one.
3. Textual analysis (STTR + sentence variance + Aho-Corasick) — only if text length ≥ `min_word_threshold` (default: 1000 words).
4. Compute weighted score and persist in redb.

---

## Phase 1 — Domain-Level Scoring

**Objective:** Flag domains that predominantly serve AI-generated content and act on that signal in real time.

### Step 1.1 — Domain Store (redb)

- Key: `xxh3_64(domain)` (same scheme as [dgaard](https://codeberg.org/slundi/dgaard)).
- Value: `DomainRecord { flags: DomainFlags, score: f32, analysed_at: i64 }`.
- No TTL; invalidation is manual only (CLI command or future UI).
- `DomainFlags::IS_AI_SLOP` already defined — reuse it.
- Add `DomainFlags::AI_SCORE_CACHED` to distinguish "never analysed" from "analysed, clean".

### Step 1.2 — Domain Blocklist Ingestion

- At startup, parse the [uBlockOrigin-HUGE-AI-Blocklist](https://github.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist) and similar lists.
- Insert entries into redb with `IS_AI_SLOP` set and score at maximum — no textual analysis needed for known domains.
- Hot-reload on file change via the existing `notify` watcher.

### Step 1.3 — Lexical Diversity Score (STTR)

- Segment the page text into fixed blocks of 100 words.
- Compute TTR per block (lowercased, punctuation stripped); average across blocks → STTR.
- A low, stable STTR across blocks is the AI signature.
- Skip analysis entirely if total word count < `min_word_threshold` (TOML config, default: 1000).

### Step 1.4 — Sentence Length Variance Score

- Tokenise text into sentences via `unicode-segmentation`.
- Compute standard deviation of sentence word-counts.
- Low variance (sentences of uniform length) raises the suspicion score.

### Step 1.5 — Aho-Corasick Expression Density Score

- Load expression patterns at startup from an external file.
- Two bundled lists provided: `lists/ai-expressions-fr.txt` and `lists/ai-expressions-en.txt`.
- Users may point config to a custom file path instead.
- Scan lowercased page text in a single pass; compute density per 1000 words.

### Step 1.6 — Weighted Scoring Engine

```rust
struct AiScoreboard {
    expression_density: f64,  // Aho-Corasick (high weight)
    sttr:               f64,  // Lexical diversity (medium weight)
    sentence_variance:  f64,  // Sentence length SD (medium weight)
    infrastructure:     f64,  // Blocklist / ai.txt signal (critical weight)
}
```

All weights and the suspicion threshold are defined in TOML config — no Starlark involved:

```toml
[ai_detector]
enabled = true
min_word_threshold = 1000
background_prefetch = false # opt-in
ai_txt_signal = false # opt-in

# path to a custom expression list; leave empty to use the bundled list
expression_list = "" # "" | "fr" | "en" | "/path/to/file.txt"

[ai_detector.weights]
expression_density = 1.5
sttr = 1.0
sentence_variance = 1.2
infrastructure = 10.0

[ai_detector.thresholds]
suspicion_score = 75.0
expression_density_per_1000 = 25.0
```

### Step 1.7 — SERP Interception

- Detect SERP responses by matching the upstream host against a configurable list of search engine domains (Google, Bing, DuckDuckGo, Brave Search, Qwant…).
- For each result entry in the SERP HTML, extract the linked domain and look it up in redb via `lol-html`.
- If `IS_AI_SLOP` is set: remove the result `<div>` surgically.
- If score is above threshold but below maximum: inject a small inline badge next to the result title.

### Step 1.8 — Visited Page Badge Injection

- On every proxied response, check redb for the URL's domain score.
- If score ≥ suspicion threshold: `lol-html` injects a `<div id="ws-ai-badge">` at the top of `<body>`.
- Badge text and style are user-configurable (template in XDG data dir, consistent with Phase 6.4 minijinja templates).
- If the domain has never been analysed and background prefetch is disabled, no badge is shown on first load; the synchronous analysis runs inline only when the page text is already available in the response stream.

---

## Phase 2 — Per-Page Scoring & Domain Averaging

**Objective:** Increase precision for mixed-content domains (Medium, Substack, WordPress blogs) where domain-level scoring produces too many false positives.

### Step 2.1 — URL-Level Score Storage

- Extend the redb schema: separate `UrlRecord { url_hash: u64, score: f32, analysed_at: i64 }` bucket alongside the domain bucket.
- Key: `xxh3_64(canonical_url)`.

### Step 2.2 — Domain Score Aggregation

- When N ≥ `min_pages_for_average` (TOML config, default: 5) URL scores exist for a domain, recompute the domain score as the weighted average of per-page scores.
- This replaces the initial domain-level heuristic for known-visited domains.

### Step 2.3 — Background Prefetch Worker (opt-in)

- When `background_prefetch = true`, the worker triggers on SERP interception.
- Extracts the top N linked URLs (TOML config, default: 10).
- Downloads each URL asynchronously (respects `robots.txt` if `ai_txt_signal = true`).
- Extracts text via the existing Reader Mode pipeline (`src/reader`).
- Runs the Phase 1 scoring engine; stores the result in the URL and domain buckets.

---

## Configuration Reference (complete diff from base config)

```toml
[ai_detector]
enabled = true
min_word_threshold = 1000
min_pages_for_average = 5
background_prefetch = false
ai_txt_signal = false
expression_list = "" # "" | "fr" | "en" | "/absolute/path"

[ai_detector.weights]
expression_density = 1.5
sttr = 1.0
sentence_variance = 1.2
infrastructure = 10.0

[ai_detector.thresholds]
suspicion_score = 75.0
expression_density_per_1000 = 25.0
```

---

## Module Layout (`src/ai_detector/`)

```
src/ai_detector/
├── mod.rs          — public API, feature flag gate
├── scoring.rs      — STTR, sentence variance, Aho-Corasick density
├── pipeline.rs     — synchronous inline path + async worker task
├── storage.rs      — redb read/write helpers (domain + URL buckets)
└── lists.rs        — bundled list loading, custom file parsing
```

---

## Open Questions (deferred to implementation)

- **SERP domain extraction:** `lol-html` must locate the result anchor `href` and parse the domain — which CSS selector covers Google, Bing, and DDG simultaneously? Will likely need per-engine selector config.
- **Inline synchronous analysis:** if background prefetch is off, should the proxy buffer the full response body to run scoring before forwarding, or only score on the second load? Buffering adds latency; second-load-only means the first visit is never badged.
