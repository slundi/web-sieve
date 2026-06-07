# web-sieve

[![CI](https://ci.codeberg.org/api/badges/slundi/web-sieve/status.svg)](https://ci.codeberg.org/slundi/web-sieve)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](#license)

**web-sieve** is a programmable, high-performance HTTPS MITM proxy written in Rust. It intercepts, sanitizes, and structurally rewrites web content before it reaches your browser — controlled by Starlark scripts you write and hot-reload without restarting the proxy.

By operating at the stream level, web-sieve drops tracker scripts, ads, and heavy payloads before the browser layout engine ever sees them, bypassing the limitations of traditional browser extensions entirely.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Streaming HTML Rewriter** — built on Cloudflare's [`lol-html`](https://github.com/cloudflare/lol-html), byte-stream modification with sub-millisecond overhead and bounded memory use.
- **Starlark Scripting Engine** — write filtering and rewriting rules in Google's Pythonic configuration language; rules hot-reload on save with no proxy restart.
- **TLS Fingerprint Spoofing (JA3/JA4)** — upstream TLS handshakes mimic real browser signatures, preventing false positives from anti-bot systems such as Cloudflare or Akamai.
- **Reader Mode** — strips articles down to raw text and images, wrapped in a minimal uniform template.
- **Manga/Manhwa Reader** — extracts continuous-scroll image strips and proxies image URLs to bypass hotlinking protections.
- **Download Directory Simplification** — converts ad-ridden torrent/DDL pages into clean, searchable HTML tables with webhook integration (e.g. send magnet links straight to qBittorrent).
- **Content Safety & Parental Controls** — high-speed multi-pattern scanning via [`aho-corasick`](https://github.com/BurntSushi/aho-corasick) with a weighted scoring threshold to minimise false positives.
- **Heuristic Anti-Phishing** — flags credential-harvesting forms by correlating DOM structure with semantic panic triggers on untrusted domains.

## Architecture

```
Browser → web-sieve (local proxy)
              │
              ├─ CONNECT intercept → on-the-fly leaf cert (rcgen Root CA)
              │                      TLS termination (tokio-rustls)
              │
              ├─ Request pipeline → Starlark rules → upstream fetch
              │                     (TLS fingerprint spoofing)
              │
              └─ Response pipeline → lol-html byte-stream rewriter
                                     aho-corasick content scanner
                                     → clean response to browser
```

web-sieve generates a local Root CA on first run. Install its certificate once in your OS/browser trust store and all HTTPS traffic is transparently intercepted and cleaned.

## Installation

### Pre-built binaries

Download the latest binary for your platform from the [releases page](https://codeberg.org/slundi/web-sieve/releases).

### From source

Requires Rust 1.85+ (edition 2024):

```sh
git clone https://codeberg.org/slundi/web-sieve.git
cd web-sieve
cargo install --path .
```

### With Nix

```sh
nix run git+https://codeberg.org/slundi/web-sieve.git
```

Or add it to your NixOS / home-manager configuration:

```nix
inputs.web-sieve.url = "git+https://codeberg.org/slundi/web-sieve.git";
```

See [docs/Nix.md](docs/Nix.md) for full setup instructions.

## Usage

```sh
web-sieve --help
```

> **Note:** web-sieve is under active development. See [docs/Roadmap.md](docs/Roadmap.md) for the current status.

## Roadmap

See [docs/Roadmap.md](docs/Roadmap.md).

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting issues, feature requests, and merge requests.

```sh
nix develop        # enter the dev shell (all tools included)
just ci-all        # run the full pipeline before opening a MR
```

## License

Copyright (C) 2026 Sébastien LUNDI — GNU General Public License v3.0 only. See [LICENSE](LICENSE).
