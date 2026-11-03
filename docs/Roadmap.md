# Roadmap

## Phase 0 — Project Setup

- [x] Rename project from template placeholder to `web-sieve` in `README.md`, `Cargo.toml`, `justfile`, `AGENT.md`, `docs/Nix.md`
- [ ] Add GPLv3 `LICENSE` file
- [x] Update `deny.toml` — adjusted `[licenses] allow` list
- [x] Update `SECURITY.md` — contact email filled in
- [x] Update `Cargo.toml` — repository URL, description, license identifier
- [ ] Set repository description and topics on Codeberg
- [x] Add keywords and categories in `Cargo.toml`
- [x] Complete `CONTRIBUTING.md` — merge request process, conventional commits, quality gate
- [x] Select and add core crates to `[dependencies]`
- [x] Update `AGENT.md` to match project vision (architecture, module layout, knowledge base)
- [ ] Enable Renovate Bot on Codeberg (`renovate.json` is ready)

## Phase 1 — Core Network Infrastructure & MITM ✅

**Objective:** Establish a high-throughput async local HTTP(S) proxy capable of decrypting secure traffic transparently.

### Step 1.1 — Async TCP & HTTP Proxy Server ✅

- Set up the core networking stack using `tokio` and `hyper`.
- Handle `CONNECT` requests for HTTPS tunneling.
- Implement basic HTTP proxying (pass-through for non-intercepted hosts).

### Step 1.2 — MITM & Certificate Authority ✅

- Use `rcgen` to generate a persistent local Root CA certificate.
- Generate leaf certificates on-the-fly per intercepted domain.
- TLS termination and re-encryption via `tokio-rustls`.

### Step 1.3 — Client Certificate Trust ✅

- Document and script the process to install the Root CA into OS and browser trust stores (NSS store for Firefox/Chromium).

## Phase 2 — Stealth & Anti-Bot Evasion ✅

**Objective:** Prevent upstream security systems (Cloudflare, Akamai) from fingerprinting and blocking the proxy.

### Step 2.1 — TLS Fingerprint Spoofing (JA3/JA4) ✅

- Replace the standard TLS backend for outgoing connections with one that can mimic browser handshakes.
- Match the outgoing TLS signature to the user's active browser `User-Agent`.

### Step 2.2 — Header & Cookie Forwarding ✅

- Transparent forwarding of upstream headers, session cookies, and state to guarantee seamless authentication on intercepted sites.

## Phase 3 — Starlark Scripting Engine & HTML Pipeline

**Objective:** Embed a scripting engine and build a low-latency streaming HTML modification pipeline.

### Step 3.1 — Starlark Integration ✅

- Embed `starlark-rust` into the proxy core.
- Define Rust-to-Starlark bindings exposing request URL, response headers, and HTML context wrappers.

### Step 3.2 — Streaming HTML Parsing via lol-html ✅

- Integrate `lol-html` for low-overhead, byte-stream HTML rewriting.
- Expose safe macro-operations to Starlark scripts: `remove_element()`, `keep_only()`, `inject_style()`, etc.

### Step 3.3 — Dynamic Script Hot-Reloading ✅

- Use the `notify` crate to watch rule files and reload Starlark scripts on modification without restarting the proxy.

### Step 3.4 — Mandatory URL Scoping

- Require every `.star` file to declare a top-level `URLS` list of glob patterns (host and optional path).
- Engine reads `URLS` from the frozen module at load time; rules with a missing or empty `URLS` fail to load with a clear error.
- `run_rules` skips the Starlark interpreter entirely for non-matching hosts — no per-request overhead.
- Supported patterns: exact host (`"reddit.com"`), subdomain wildcard (`"*.reddit.com"`), path glob (`"example.com/r/*"`), catch-all (`"*"`).

### Step 3.5 — Content-Access Globals ✅

- Expose globals for reading the current response before applying DOM operations:
  - `status_code()` → `int` — HTTP response status code
  - `page_title()` → `str` — text content of `<title>`
  - `meta_description()` → `str` — `<meta name="description">` content
  - `meta_tags()` → `dict` — all `<meta name|property="…" content="…">` pairs
  - `response_headers()` → `dict` — response headers (lower-cased names)
  - `request_headers()` → `dict` — forwarded request headers (lower-cased names)
- Scalar globals (`status_code()`) and headers are cheap and always available; the
  HTML metadata globals (`page_title()`, `meta_description()`, `meta_tags()`) parse
  the body lazily on first call and memoize the result, so rules that never invoke
  them pay no parsing cost.

## Phase 4 — Core Feature Implementation

**Objective:** Leverage the Starlark + Rust pipeline to implement the primary structural use cases.

### Step 4.1 — Ad-blocking & Global Style Injection ✅

- Parse standard network blocking lists (EasyList, uBlock Origin) using a Trie/Prefix-tree engine.
- Cosmetic filtering via `lol-html`: inject global `<style>` blocks to hide ad classes without breaking SPA hydration.

### Step 4.2 — Universal Reader Mode ✅

- Integrate a text-density extraction engine (Rust port of Mozilla Readability).
- Wrap extracted content in a minimal, uniform HTML/CSS template.
- Starlark hook to forward saved URLs to read-later services (Shiori, Pocket) via webhook.

### Step 4.3 — Manga/Manhwa Pipeline & Image Proxying

- Starlark schemas targeting continuous-scroll image containers on scanlation sites.
- Internal image proxy endpoint (`/proxy-media?url=…`) that spoofs `Referer` and `Origin` to bypass hotlinking.

### Step 4.4 — Download Directory Simplification

- Starlark recipes to scrape torrent/DDL sites into structured datasets.
- Re-render as clean tabular HTML with webhook buttons (e.g. send magnet links directly to qBittorrent on click).

### Step 4.5 — Weather Forecast Homogenisation

- Starlark schemas extracting forecast data (temperature, conditions, hourly/daily series) from popular weather providers.
- Re-render into a single uniform, low-clutter forecast template inspired by minimalist clients like Breezy Weather.

### Step 4.6 — Web Radio Handling

- Detect and extract stream endpoints and station metadata (now-playing, bitrate, genre) from web radio directories and player pages.
- Expose a consistent lightweight player UI and forward stream URLs to external players/webhooks.

### Step 4.7 — Homogeneous Shopping UI

- Starlark schemas normalising product listings (title, price, availability, ratings, images) across heterogeneous e-commerce sites.
- Re-render into a uniform product/catalogue template, stripping tracking widgets and promotional clutter.

### Step 4.8 — Homogeneous Wiki UI

- Extract article body, table of contents, and metadata from wiki engines (MediaWiki, DokuWiki, etc.).
- Present a consistent, distraction-free reading template with unified typography and navigation.

### Step 4.9 — Homogeneous Social Network UI

- Starlark schemas targeting feed/post structures (author, content, timestamp, media, engagement) across social platforms.
- Re-render into a uniform timeline template, removing algorithmic clutter and non-content chrome.

### Step 4.10 — Git Platform Homogenisation

- Schemas for Gitea, Forgejo, GitHub, Codeberg, and similar forges covering repository views, file trees, commits, issues, and pull requests.
- Re-render into a single consistent repository-browsing template regardless of the upstream forge.

### Step 4.11 — Search Engine Homogenisation

- Extract organic result sets (title, URL, snippet) from Google, DuckDuckGo, Bing, and others.
- Re-render into a uniform results template, discarding ads, trackers, and interstitial clutter.

## Phase 5 — Content Inspection & Safety Controls ✅

**Objective:** Deep semantic inspection for parental controls and anti-phishing.

### Step 5.1 — High-Speed Text Scanning ✅

- `aho-corasick` multi-pattern search on raw text payloads against configurable dictionary matrices.

### Step 5.2 — Weighted Semantic Filtering ✅

- Starlark scoring rules: block a page only when a configurable density threshold of flagged terms is reached, preventing false positives.

### Step 5.3 — Heuristic Anti-Phishing Engine ✅

- Intercept `<form>` elements containing credential or PII inputs.
- Flag forms served on unverified domains that also contain semantic panic triggers ("verify account", "unauthorized access").

## Phase 6 — User Interface & Optimisation

**Objective:** Finalise routing options, user experience, and performance targets.

### Step 6.1 — Proxy Routing & Activation Triggers ✅

- Auto-detect target sites via URL patterns or subdomains (e.g. `reader.https.example.com`).
- Optional lightweight browser extension that injects activation headers (`X-Proxy-Control: reader`).
- Subdomain triggers follow the fixed `<mode>.<proto>.<host…>` form; `<proto>`
  must be `http` or `https`. The proxy rewrites the effective upstream target,
  keeps serving a leaf certificate for the trigger authority, and queues the
  mode's `RewriteOp` alongside those from Starlark rules.
- `X-Proxy-Control` accepts a comma-separated list of modes; subdomain and
  header modes are merged additively and de-duplicated in first-seen order.
  The header is stripped before forwarding upstream.
- Modes shipped: `reader` → `RewriteOp::ReaderMode`, `block` →
  `RewriteOp::BlockPage`, and `raw` (pass-through — skip Starlark rules,
  cosmetic filtering, scanning, and HTML rewriting).

### Step 6.2 — Performance Benchmarking

- Target: less than 15 ms added latency overhead.
- Ensure large binary assets (images, video streams) bypass the heavy processing pipeline entirely.
- Profile memory mapping and async task scheduling; optimise only after profiling.

### Step 6.3 — HTTP/2 Browser↔Proxy Protocol ✅

- HTTP/2 on the browser→proxy leg only (`hyper`); proxy→upstream remains independent.
- Advertise `h2` in ALPN on the listening `tokio-rustls` socket; negotiate HTTP/1.1 as fallback.
- Each concurrent HTTP/2 stream is dispatched as its own `tokio` task; `lol-html` rewriting runs per-stream in parallel.
- MITM leaf `ServerConfig` sets `alpn_protocols = ["h2", "http/1.1"]`. After
  TLS termination in `do_mitm`, `hyper_util::server::conn::auto::Builder`
  picks h2 or h1 from the negotiated ALPN in a single call site; the
  `TokioExecutor` drives hyper's per-stream dispatch.
- Per-request logic moved out of the service closure into a top-level
  `handle_mitm_request`, so both protocol drivers share one implementation.
- CONNECT requests inside the MITM'd stream (nested MITM, extended-CONNECT
  for WebSockets-over-h2, MASQUE, …) are answered with `501 Not Implemented`.

### Step 6.4 — Minijinja Template Engine ✅

- Users author display templates in the XDG data directory under `templates/` using `minijinja`.
  Default `~/.local/share/web-sieve/templates/`, overridable with `--templates-dir`.
- Covers re-rendered views: torrent/download list, weather forecast, news feed, manga/webnovel reader, git repository.
- Starlark scripts call `render_template(name, context_dict)`; the binding JSON-encodes
  the dict into a `RewriteOp::RenderTemplate`, and `rewriter::apply_with_templates`
  resolves the name against the `TemplateEngine` and renders via `minijinja`.
- Each file is registered under both its file name (`base.html`) and its stem
  (`base`), so `{% extends "base.html" %}` and `render_template("base", …)` both
  resolve. Templates are shared: multiple Starlark scripts may reference the same
  one by name.
- `RenderTemplate` replaces the whole document and takes precedence over
  `ReaderMode`; the last queued template wins. Remaining DOM ops
  (`remove_element()`, `inject_style()`, …) then run over the rendered output.
- Any failure — unknown template, syntax error, bad context — is logged and the
  upstream page is served unchanged rather than a broken document.
- A dedicated `notify` watcher on the templates directory rebuilds the whole
  template set on create/modify/remove.

### Step 6.5 — Static Asset Serving & Local Proxy Endpoint ✅

- Proxy intercepts requests to `webprism.local` by hostname match — no DNS or `/etc/hosts` entry required.
  Matching ignores case and port. Overridable with `--asset-host`.
  Both legs work: plain HTTP (`forward_http` answers before any upstream connect)
  and HTTPS, where a CONNECT to the asset host is terminated locally by
  `do_local_mitm` with a leaf certificate and never opens an upstream socket.
- Two asset sources, both served under `webprism.local`:
  - **Shared assets** (`css`, `js`, `fonts`, `scripts`, `templates`) live in the XDG data directory so users can add or override files, served at `webprism.local/assets/…`.
    The root is `--data-dir` (default `~/.local/share/web-sieve`).
  - **Per-script assets** ship alongside a community script in its own folder (e.g. `rules/<script>/` containing the `.star` plus `icon`, `css`, `js`), served under a namespaced path `webprism.local/assets/<script>/…`.
  - Per-script assets take precedence over shared assets for namespaced references.
  - `ScriptEngine` now also loads `rules/<script>/<name>.star`, one level deep, so
    a script shipped in its own folder is active — without this the layout above
    would serve assets for a rule that never ran.
- Prefer inlining assets into templates to avoid extra round-trips; both directories are also served for files that cannot be inlined.
  Templates get `inline_asset(path)` (splices the file in, marked safe so CSS/JS
  is not escaped) and `asset_url(path)` for files too large to inline.
- Extend the `notify` watcher to cover both the XDG asset directory and per-script asset folders under the rules directory.
  The rules watcher is now recursive, so per-script folders hot-reload.
  **Deviation:** assets themselves are _not_ watched or cached — they are read
  from disk per request, so an edit is live on the next request with no
  staleness window. A watcher would only have served to invalidate a cache that
  does not exist.
- CORS: default same-origin (`webprism.local` only); configurable `Access-Control-Allow-Origin` allowlist for cross-origin use.
  `--cors-allow-origin` is repeatable and accepts `*`. With no flag, no
  `Access-Control-Allow-Origin` header is emitted at all. Allowlisted responses
  also carry `Vary: Origin`. `OPTIONS` preflights are answered `204`; anything
  other than `GET`/`HEAD`/`OPTIONS` gets `405`.
- Path safety: request paths are percent-decoded, then `..`, dotfiles,
  backslashes, and NUL bytes are rejected; the resolved path is canonicalised
  and must stay under its root, so a symlink cannot escape.
- `.star` files are never served even though they sit inside a served per-script
  folder — rule sources are logic and may embed webhook tokens.
- Refactor: the five content engines moved into a `proxy::Pipeline` struct, so
  the per-connection call chain stays at four arguments instead of needing
  `#[allow(clippy::too_many_arguments)]` on every hop.

> **Naming:** the host is `webprism.local` as specified here, while the crate is
> `web-sieve`. Kept as written and made configurable; rename the default in
> `assets::DEFAULT_ASSET_HOST` if the discrepancy was unintended.

## Phase 7 — REST Control & Extraction API

**Objective:** Expose the proxy's engines over an optional local HTTP API, so non-browser clients
(scripts, dashboards, LLM agents, other hosts) can use them, and so rule authoring stops being log
archaeology.

Entirely optional and **disabled by default**: `--api=off|readonly|rw` (plus `--api-listen`,
default `127.0.0.1:8737`). Built on `axum`, reusing the existing `tokio` runtime.

This phase introduces the project's **first configuration file**. Config is CLI flags only today,
and tokens cannot be flags — `--api-token=…` is visible in `ps aux` to every user on the machine,
and leaks into shell history and systemd unit files. The file lives in the XDG config directory and
is read with `toml-span`: parsing happens once at load, and byte-offset spans point at the offending
client entry on error.

### Step 7.1 — Rule Authoring & Introspection

Highest priority: this is the dev loop for every remaining Phase 4 schema. Hot-reload (3.3) tells
you a rule _loaded_; nothing today tells you what it _did_.

- `GET /v1/rules` — loaded scripts, their `URLS` globs, load errors, last reload timestamp.
  Answers "why isn't my rule firing" in one call (usually: the glob).
- `POST /v1/rules/validate` — parse and freeze a `.star` without installing it; return the declared
  `URLS` and any error with its span.
- `POST /v1/preview` `{url, rule?}` — run the rule set against a live URL; return before/after HTML,
  a diff, and the queued `RewriteOp` list.
- `POST /v1/templates/render` `{name, context}` — surface minijinja errors that 6.4 currently only
  writes to the log while silently serving the upstream page.
- `PUT /v1/rules/{name}`, `POST /v1/rules/{name}/{enable,disable}` — install or toggle a rule
  without deleting the file. Write-mode only, and gated behind its own flag (see 7.6).
- Secondary payoff: community rule repos can CI-test against a disposable instance — POST the
  `.star` plus a fixture URL, assert the extracted JSON.

### Step 7.2 — Content Extraction as a Service

The differentiator is not "fetch a URL" — it is the Phase 2 stealth stack. A plain `reqwest` client
gets a Cloudflare interstitial; this one does not.

- `POST /v1/fetch` `{url, mode: raw|reader|markdown}` — cleaned body plus the ops that were applied.
- `POST /v1/extract` `{url|html, rule}` — structured JSON from a rule's schema, which turns the
  Phase 4.3–4.11 schemas (weather, product, torrent list, SERP, forge, wiki) into a data API.
- `POST /v1/readability` `{html}` — title, byline, text, images, with no network access at all.
- `mode: markdown` makes the MCP server trivial: three tools (`fetch_clean_page`,
  `extract_structured`, `check_safety`) wrapping three endpoints.
- Other consumers: RSS generation for sites without feeds, read-later ingestion (Shiori, Pocket),
  archival, terminal readers.

### Step 7.3 — Safety Scoring as a Service

Decouples Phase 5 from the in-band proxy path, so clients that are not a browser can get a verdict.

- `POST /v1/scan` — category scores, matched terms, density against the configured threshold,
  final verdict.
- `POST /v1/phishing/check` — heuristic verdict plus the triggering form fields and panic phrases.
- Consumers: mail-client link checking, Home Assistant, another host on the LAN, SIEM enrichment
  ("what was actually on that page").

### Step 7.4 — Observability

- `GET /v1/stats` — requests proxied, bytes saved, ads blocked, per-rule hit counts and time spent,
  latency histogram. The histogram is how the <15 ms target in 6.2 gets held in production rather
  than only in benchmarks.
- `GET /metrics` — same counters in Prometheus format, for Grafana.
- `GET /v1/flows?since=…` — recent requests: host, modes applied, rules hit, size delta.
  mitmproxy's flow list without the UI; a `ratatouille` TUI or a waybar/polybar widget is the obvious
  client.
- `GET /v1/health` — systemd/container readiness; confirms the CA is loaded.

### Step 7.5 — Runtime Overrides, Profiles & Configuration

The extension (6.1) injects `X-Proxy-Control` per request but cannot hold state. The API can.

- `POST /v1/overrides` `{host, mode: raw, ttl: 10m}` — "show me the real page for ten minutes",
  from a hotkey script, with no config edit and no restart.
- `POST /v1/overrides` `{host, allow, ttl: 30m}` — parental temporary unblock.
- `POST /v1/unblock-requests` + `GET` + approve — the block page gets a "request access" button;
  a parent approves from a phone. Turns a dead end into a workflow.
- `PUT /v1/clients/{ip}/profile` — per-device policy when one instance serves a LAN (strict
  scanning on a child's tablet, permissive on a laptop). Without it, LAN deployment is
  one-size-fits-all.
- `GET /v1/ca.crt` — certificate, fingerprint, per-OS install hints. Onboarding a phone becomes
  "open this URL" instead of "scp a file".
- `GET`/`PUT /v1/config` — CORS allowlist, scoring thresholds, blocklist URLs.
- `POST /v1/filters/update` — refresh EasyList/uBlock lists without a restart.
- Makes headless deployment viable (router, homelab box, container): there is no browser on that
  host, so the API _is_ the UI, and a dashboard served from `webprism.local` becomes a pure client.

### Step 7.6 — Clients, Scopes & Security Boundary

Authorisation is two layers: `--api` is the operator's **ceiling**, per-client scopes are the
**grant**. A client holding `rules:write` gets nothing in `readonly` mode.

- `off` (default) — no listener bound, zero added attack surface.
- `readonly` — GET only: stats, flows, rules, config dump, CA cert, health. Enough for dashboards,
  TUIs and monitoring; cannot change policy.
- `rw` — write endpoints reachable, subject to each client's scopes.

Named clients in the config file, identified by what they _are_ (an integration, a device) rather
than by who owns them — that keeps revocation granular, so the dashboard token can be rotated
without breaking the agent:

```toml
[api]
mode = "rw"
listen = "127.0.0.1:8737"

[[api.clients]]
id = "grafana"
token_sha256 = "9f86d081884c7d65…"
scopes = ["stats:read", "flows:read"]

[[api.clients]]
id = "mcp-agent"
token_sha256 = "…"
scopes = ["fetch", "extract", "scan"]
rate_limit = "60/min"

[[api.clients]]
id = "jessica"
token_sha256 = "…"
role = "parent"
scopes = ["*"]
```

- Scopes: `stats:read`, `flows:read`, `rules:read`, `rules:write`, `config:read`, `config:write`,
  `overrides:write`, `fetch`, `extract`, `scan`. They replace the `--api-allow-fetch` flag from the
  first draft of this phase — the network-touching POSTs are gated per client rather than per
  process.
- `role` matters only where the principal is a _human_: the approve-unblock flow in 7.5 requires
  `role = "parent"`. On a machine the child can read, pair it with a PIN on the approval itself —
  file permissions alone are not the boundary there.
- Per-client `rate_limit`, because `/v1/fetch` is an open-proxy primitive.
- Every request logs `client=<id> scope=<granted>`; token material is never logged.

**No loopback exemption.** Authentication is required even for `127.0.0.1`. Any page in the browser
can issue `fetch('http://127.0.0.1:8737/v1/rules/evil', {method:'PUT', …})`; CORS prevents the page
from _reading_ the response but not from _executing_ the request, so an unauthenticated loopback API
is a CSRF target for every site visited — through this very proxy. Also validate the `Host` header
against the configured listen address, which blocks DNS rebinding.

Remaining boundary rules:

- **Keep the API off `webprism.local`.** That host is reachable from any intercepted page's
  JavaScript. Separate port, bound to loopback by default, CORS denied outright (not the asset
  host's allowlist from 6.5), `Origin` checked.
- `/v1/fetch` is an SSRF primitive: never forward the user's cookie jar by default (opt-in per
  request), and deny loopback/link-local/RFC1918/cloud-metadata targets.
- `PUT /v1/rules/{name}` is remote code upload. Starlark is sandboxed but can still fire webhooks,
  so it needs an explicit `rules:write` scope — never `*` for an unattended integration.
- Refuse to start if the config file is group- or world-readable, as `ssh` does; it will end up in a
  dotfiles repository otherwise.
- Support `token_file = "…"` indirection so the secret can come from a password manager or a
  systemd credential rather than the config file.

### Step 7.7 — Token Generation CLI

Tokens are generated by the tool, never chosen by the user. That choice is what makes a fast hash
the correct one.

```sh
$ web-sieve api token create mcp-agent --scopes fetch,extract
wsv_mcp-agent_8Kj2nQ…        # shown once, then only its hash is stored
```

- 256 bits from the OS RNG, stored as `sha256` (`sha2`). **Not `argon2`:** a KDF's slowness only
  buys security against low-entropy human-chosen secrets, and at 50–100 ms per request it would
  dwarf the <15 ms latency target of 6.2 on any client that loops.
- Verification keys a `HashMap<[u8; 32], Client>` by the SHA-256 of the presented token, so the
  lookup never performs a secret-dependent byte comparison — constant-time by construction, with no
  extra crate.
- The `wsv_<id>_<secret>` form carries a non-secret client id, so logs and errors can name the
  caller without ever touching secret material.
- Companion subcommands: `token list` (id, scopes, created, last used), `token revoke <id>`,
  `token rotate <id>`. Revocation takes effect on config reload — reuse the existing `notify`
  watcher, but only for a file that passed the permission check above.

## Ideas

- REST service — promoted to Phase 7 above.
