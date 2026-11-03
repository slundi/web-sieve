# Writing Starlark Scripts and Templates for web-sieve

This guide walks through how to author `.star` rule files and Minijinja templates
that customise, filter, or block web pages as they flow through the proxy.

## How scripts are loaded

web-sieve watches a directory for `*.star` files and runs every loaded rule against
each intercepted HTML response. The default directory is
`$XDG_CONFIG_HOME/web-sieve/rules/` (usually `~/.config/web-sieve/rules/`).
You can override it with `--rules-dir`.

- Files are loaded in **alphabetical order**; that order is preserved when multiple
  rules apply to the same response.
- The engine **hot-reloads** on any create, modify, or remove event — no proxy
  restart needed.
- A broken file emits a warning and is skipped; healthy rules keep running.

## Anatomy of a rule file

Every rule file must define two things:

```python
# 1. Which URLs this rule applies to (required).
URLS = ["reddit.com", "*.reddit.com"]

# 2. The process function that runs on every matching response.
def process(request):
    remove_element("shreddit-ad-post")
    remove_element(".promotedlink")
```

`URLS` is evaluated once at load time so the engine can skip the rule entirely for
non-matching hosts without entering the Starlark interpreter. Omitting `URLS` is
a hard error — every rule must declare its scope.

### URL pattern syntax

Each entry in `URLS` is a glob pattern matched against the request host (and
optionally path).

| Pattern                      | Matches                                             |
| ---------------------------- | --------------------------------------------------- |
| `"reddit.com"`               | exactly `reddit.com`                                |
| `"*.reddit.com"`             | any subdomain: `old.reddit.com`, `www.reddit.com` … |
| `"reddit.com, *.reddit.com"` | both of the above                                   |
| `"example.com/r/*"`          | any path under `/r/` on `example.com`               |

List as many patterns as needed:

```python
URLS = [
    "news.ycombinator.com",
    "lobste.rs",
]
```

## The `request` object

`process(request)` receives a dict populated before the rule runs:

| Key                       | Type  | Description                                                |
| ------------------------- | ----- | ---------------------------------------------------------- |
| `request["url"]`          | `str` | Full request URL, e.g. `"https://reddit.com/r/rust"`       |
| `request["host"]`         | `str` | Hostname without port, e.g. `"reddit.com"`                 |
| `request["content_type"]` | `str` | Response `Content-Type`, e.g. `"text/html; charset=utf-8"` |

Use these fields to branch on URL structure or content type:

```python
URLS = ["example.com", "*.example.com"]

def process(request):
    if status_code() != 200:
        return
    if "text/html" not in request["content_type"]:
        return
    if "/article/" in request["url"]:
        enable_reader_mode()
```

## Content-inspection globals

These functions are called inside `process()` to read the page being processed.
The scalar globals (`status_code()`) are always cheap; the HTML metadata globals
(`page_title()`, `meta_description()`, `meta_tags()`) parse the response body
lazily on first call and memoize the result, so rules that never call them incur
no parsing cost.

```python
status_code()       # → int   — HTTP response status code, e.g. 200
page_title()        # → str   — <title> element text, empty string if absent
meta_description()  # → str   — content of <meta name="description">, empty if absent
meta_tags()         # → dict  # all <meta name|property="…" content="…"> as {name: content}
response_headers()  # → dict  # response headers, lower-cased names
request_headers()   # → dict  # forwarded request headers, lower-cased names
```

Example — only enable reader mode when the page signals it is an article:

```python
URLS = ["*.medium.com"]

def process(request):
    tags = meta_tags()
    if tags.get("og:type") == "article":
        enable_reader_mode()
```

### Scan globals (content-safety pipeline)

These globals are populated by the Aho-Corasick text scanner that runs before
`process()` is called. They are only meaningful when dictionary files are
present under `--dicts-dir`.

```python
scan_matches()        # → dict  # {category: hit_count} — only categories with ≥1 hit
scan_content_length() # → int   # byte length of the response body
density_threshold()   # → float # configured --density-threshold value (default 0.01)
```

## Action functions

Calling an action function queues an operation; all queued operations are applied
to the document after `process()` returns. Multiple actions can be queued in a
single call.

### DOM manipulation

```python
remove_element(selector)  # Remove every element matching a CSS selector.
inject_style(css)         # Append a <style> block to <head>.
keep_only(selector)       # Hide every direct child of <body> that does NOT match.
enable_reader_mode()      # Extract the main article and replace the page with the
                          # reader template.
```

### Templates

```python
render_template(name, context)
# Replace the page with a Minijinja template rendered against `context` (a dict).
# Templates live in $XDG_DATA_HOME/web-sieve/templates/ and are hot-reloaded.
```

`name` may be the template's file name (`"torrent-list.html"`) or its stem
(`"torrent-list"`). `context` must be a dict whose values are JSON-representable
(`str`, `int`, `float`, `bool`, `None`, `list`, `dict`) — anything else aborts
the rule with an error in the log.

If the template is missing, fails to parse, or errors while rendering, the
proxy logs a warning and serves the **upstream page unchanged** — a broken
template never produces a broken page.

See [Template authoring](#template-authoring) below.

### Control flow

```python
block_page()            # Return 403 to the browser instead of the page.
webhook(url, body)      # POST `body` (JSON string) to `url` asynchronously.
                        # Does not modify the document; delivery is fire-and-forget.
```

## Examples

### Remove ads and promoted posts

```python
# rules/reddit-clean.star
URLS = ["reddit.com", "*.reddit.com"]

def process(request):
    remove_element("shreddit-ad-post")
    remove_element(".promotedlink")
    remove_element("[data-testid='promoted-post']")
```

### Reader mode for news sites

```python
# rules/reader-news.star
URLS = [
    "theguardian.com",
    "*.theguardian.com",
    "nytimes.com",
    "arstechnica.com",
]

def process(request):
    if "text/html" not in request["content_type"]:
        return
    if status_code() != 200:
        return
    enable_reader_mode()
```

### Send articles to a read-later service

```python
# rules/save-to-shiori.star
URLS = ["*.theguardian.com", "arstechnica.com"]

import json

def process(request):
    if meta_tags().get("og:type") != "article":
        return
    payload = json.encode({
        "url": request["url"],
        "title": page_title(),
    })
    webhook("http://localhost:8090/api/v1/bookmarks", payload)
```

### Semantic content blocking

```python
# rules/block-adult.star
URLS = ["*"]  # apply to every site

def process(request):
    if "text/html" not in request["content_type"]:
        return
    m = scan_matches()
    n = scan_content_length()
    if n > 0 and m.get("adult", 0) / n > density_threshold():
        block_page()
```

### Conditional style injection

```python
# rules/dark-github.star
URLS = ["github.com", "*.github.com"]

_CSS = """
  body { background: #0d1117 !important; color: #c9d1d9 !important; }
"""

def process(request):
    if status_code() == 200:
        inject_style(_CSS)
```

### Custom template rendering

```python
# rules/torrent-list.star
URLS = ["nyaa.si", "www.nyaa.si"]

def process(request):
    if "/user/" in request["url"]:
        return
    render_template("torrent-list", {
        "title": page_title(),
        "host": request["host"],
    })
```

## Template authoring

Templates live in `$XDG_DATA_HOME/web-sieve/templates/` (usually
`~/.local/share/web-sieve/templates/`); override the location with
`--templates-dir`. Each file is a [Minijinja](https://docs.rs/minijinja)
template that receives the context dict passed to `render_template()`.

Every file is registered under two names — its file name (`base.html`) and its
stem (`base`) — so `{% extends "base.html" %}` and `render_template("base", …)`
both resolve. Give templates distinct stems; two files sharing one (`a.html`
and `a.txt`) collide on the stem entry.

The whole template set is rebuilt whenever a file in the directory is created,
modified, or removed. Dotfiles and `~` backups are ignored, and a template with
a syntax error is skipped with a warning while the others keep working.

A minimal template:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{{ title }}</title>
  <style>
    body { font-family: sans-serif; max-width: 80ch; margin: 2rem auto; }
  </style>
</head>
<body>
  <h1>{{ title }}</h1>
  {% block content %}{% endblock %}
</body>
</html>
```

Templates can inherit from each other with Minijinja's `{% extends %}` and
`{% block %}` tags. A shared `base.html` in the templates directory keeps
common styles in one place.

## Execution order and rule interaction

1. Rules are applied in alphabetical filename order.
2. All rules whose `URLS` match the request run; they are not mutually exclusive.
3. Operations are accumulated across all matching rules and applied in a single
   streaming pass over the document.
4. `block_page()` is handled before the HTML pipeline runs — if any rule emits
   a `block_page()`, the other operations are discarded and the browser receives
   a 403.
5. `enable_reader_mode()` and `render_template()` replace the entire document;
   `remove_element()` / `inject_style()` / `keep_only()` calls — from any rule,
   regardless of order — then operate on the _replaced_ content.
6. If both are queued, `render_template()` wins over `enable_reader_mode()`.
   When several rules queue a template, the last one in load order is rendered.

## Tips

**Guard on `content_type`** — scripts run on every matching response, including
JSON, CSS, and image URLs. Always check `"text/html" in request["content_type"]`
before DOM operations.

**Guard on `status_code()`** — avoid modifying error pages inadvertently; check
`status_code() == 200` for rules that assume a valid document.

**Keep rules focused** — one rule file per site or concern. The alphabetical
load order lets you control sequencing with numeric prefixes
(`10-reddit-clean.star`, `20-reddit-theme.star`).

**Use `webhook()` for side effects** — webhooks are dispatched asynchronously
and never block the response. They are fire-and-forget; if delivery fails, a
warning is logged.

**Check proxy logs** — the proxy logs rule load errors, reload events, and
runtime failures at the `warn` level. Set `RUST_LOG=web_sieve=debug` for
verbose output including which rules were skipped for a given URL.
