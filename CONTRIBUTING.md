# How to Contribute to web-sieve

Thank you for your interest in contributing! Please follow these guidelines to submit your contributions effectively.

## Submitting Changes via Merge Requests

For any change (bug fixes, features, documentation), use a **Merge Request** on Codeberg.

1. **Fork the repository** (if you are not a direct collaborator).
2. **Create a dedicated branch** with a clear name:
   ```bash
   git checkout -b fix-login-bug
   git checkout -b feat-new-feature
   ```
3. **Make your changes** and commit following the convention below.
4. **Push your branch**:
   ```bash
   git push origin my-descriptive-branch
   ```
5. **Open a Merge Request** targeting `master`. In the description:
   - Explain the problem you are solving or the feature you are adding.
   - Include steps to reproduce (for bugs) or steps to test (for features).
   - Reference any related issue numbers.

The project team will review your MR, may request changes, and merge it once approved.

## Conventional Commits

All commits must follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification:

```
<type>(<scope>): <short description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | When to use                              |
| ---------- | ---------------------------------------- |
| `feat`     | A new feature                            |
| `fix`      | A bug fix                                |
| `refactor` | Code change with no behaviour difference |
| `test`     | Adding or updating tests                 |
| `docs`     | Documentation only                       |
| `chore`    | Maintenance (deps, CI, tooling)          |
| `perf`     | Performance improvement                  |

### Examples

```
feat(proxy): add CONNECT tunnel support for HTTPS
fix(tls): correct leaf cert SAN field for wildcard domains
docs(readme): update installation instructions
chore(deps): bump tokio to 1.38
```

Breaking changes must include `BREAKING CHANGE:` in the footer or a `!` after the type:

```
feat(api)!: rename ProxyConfig fields to snake_case
```

## Development Setup

```sh
nix develop        # enter the dev shell (all tools included)
```

No Nix? Install Rust via [rustup](https://rustup.rs/) and the tools listed in `flake.nix`, then the `just` recipes work the same way.

### Quality gate before opening a MR

```sh
just ci-all        # fmt + lint + test + health-check + secret scan
```

All of the following must pass:

- `cargo fmt --check` — no formatting differences
- `cargo clippy -- -D warnings` — zero warnings
- `cargo nextest run` — all tests green
- `cargo deny check` — no license/advisory violations
- `gitleaks detect` — no secrets leaked

### Coverage

Line coverage must stay at or above **80%**:

```sh
just coverage-check
```

## Code Standards

- **No `unsafe`** without a written justification comment.
- **No `unwrap()` / `expect()`** in library code — propagate errors with `?`.
- **No `println!` / `eprintln!`** in library code — use `tracing` macros.
- Every public item must have a `///` doc comment.
- Keep files under ~500 lines; split into modules if they grow larger.
- Follow the module layout described in [AGENT.md](AGENT.md).

## Commit Signing

Commits on this repository are not required to be signed, but GPG-signed commits are welcomed.

## Reporting Security Issues

Do **not** open a public issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for the private reporting process.
