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

## Phase 3 — Starlark Scripting Engine & HTML Pipeline ✅

**Objective:** Embed a scripting engine and build a low-latency streaming HTML modification pipeline.

### Step 3.1 — Starlark Integration ✅

- Embed `starlark-rust` into the proxy core.
- Define Rust-to-Starlark bindings exposing request URL, response headers, and HTML context wrappers.

### Step 3.2 — Streaming HTML Parsing via lol-html ✅

- Integrate `lol-html` for low-overhead, byte-stream HTML rewriting.
- Expose safe macro-operations to Starlark scripts: `remove_element()`, `keep_only()`, `inject_style()`, etc.

### Step 3.3 — Dynamic Script Hot-Reloading ✅

- Use the `notify` crate to watch rule files and reload Starlark scripts on modification without restarting the proxy.

## Phase 4 — Core Feature Implementation

**Objective:** Leverage the Starlark + Rust pipeline to implement the primary structural use cases.

### Step 4.1 — Ad-blocking & Global Style Injection ✅

- Parse standard network blocking lists (EasyList, uBlock Origin) using a Trie/Prefix-tree engine.
- Cosmetic filtering via `lol-html`: inject global `<style>` blocks to hide ad classes without breaking SPA hydration.

### Step 4.2 — Universal Reader Mode ✅

- [x] Integrate a text-density extraction engine (Rust port of Mozilla Readability).
- [x] Wrap extracted content in a minimal, uniform HTML/CSS template.
- [x] Starlark hook to forward saved URLs to read-later services (Shiori, Pocket) via webhook.

### Step 4.3 — Manga/Manhwa Pipeline & Image Proxying

- Starlark schemas targeting continuous-scroll image containers on scanlation sites.
- Internal image proxy endpoint (`/proxy-media?url=…`) that spoofs `Referer` and `Origin` to bypass hotlinking.

### Step 4.4 — Download Directory Simplification

- Starlark recipes to scrape torrent/DDL sites into structured datasets.
- Re-render as clean tabular HTML with webhook buttons (e.g. send magnet links directly to qBittorrent on click).

## Phase 5 — Content Inspection & Safety Controls

**Objective:** Deep semantic inspection for parental controls and anti-phishing.

### Step 5.1 — High-Speed Text Scanning

- `aho-corasick` multi-pattern search on raw text payloads against configurable dictionary matrices.

### Step 5.2 — Weighted Semantic Filtering

- Starlark scoring rules: block a page only when a configurable density threshold of flagged terms is reached, preventing false positives.

### Step 5.3 — Heuristic Anti-Phishing Engine

- Intercept `<form>` elements containing credential or PII inputs.
- Flag forms served on unverified domains that also contain semantic panic triggers ("verify account", "unauthorized access").

## Phase 6 — User Interface & Optimisation

**Objective:** Finalise routing options, user experience, and performance targets.

### Step 6.1 — Proxy Routing & Activation Triggers

- Auto-detect target sites via URL patterns or subdomains (e.g. `reader.https.example.com`).
- Optional lightweight browser extension that injects activation headers (`X-Proxy-Control: reader`).

### Step 6.2 — Performance Benchmarking

- Target: less than 15 ms added latency overhead.
- Ensure large binary assets (images, video streams) bypass the heavy processing pipeline entirely.
- Profile memory mapping and async task scheduling; optimise only after profiling.

### Step 6.3 — HTTP/2 Browser↔Proxy Protocol

- HTTP/2 on the browser→proxy leg only (`hyper`); proxy→upstream remains independent.
- Advertise `h2` in ALPN on the listening `tokio-rustls` socket; negotiate HTTP/1.1 as fallback.
- Each concurrent HTTP/2 stream is dispatched as its own `tokio` task; `lol-html` rewriting runs per-stream in parallel.

### Step 6.4 — Minijinja Template Engine

- Users author display templates in the XDG data directory under `templates/` using `minijinja`.
- Covers re-rendered views: torrent/download list, weather forecast, news feed, manga/webnovel reader, git repository.
- Starlark scripts call `render_template(name, context_dict)` binding; Rust resolves the template name and renders via `minijinja`.
- Templates are shared: multiple Starlark scripts may reference the same template by name.
- Extend the existing `notify` file watcher to hot-reload templates on modification.

### Step 6.5 — Static Asset Serving & Local Proxy Endpoint

- Proxy intercepts requests to `webprism.local` by hostname match — no DNS or `/etc/hosts` entry required.
- Assets (`css`, `js`, `fonts`, `scripts`, `templates`) live in the XDG data directory so users can add or override files.
- Prefer inlining assets into templates to avoid extra round-trips; the XDG directory is also served for files that cannot be inlined.
- Extend the `notify` watcher to cover the full XDG asset directory.
- CORS: default same-origin (`webprism.local` only); configurable `Access-Control-Allow-Origin` allowlist for cross-origin use.
