# Build, test, and CI

## Local commands

```sh
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## GitHub Actions workflows

| Workflow | Trigger | Role |
|----------|---------|------|
| `.github/workflows/ci.yml` | Push and pull request | Format, clippy (`-D warnings`), workspace tests |
| `.github/workflows/integration.yml` | As configured in-repo | PostgreSQL 18 and Valkey 9 service containers, migrations, `cargo test --workspace` with `DATABASE_URL` for Postgres-backed API tests |
| `.github/workflows/release.yml` | Version tags `v*` | Release build verification (`cargo build --release --workspace`) |
| `.github/workflows/docs.yml` | Push to `main` touching `docs/` or the workflow; `workflow_dispatch` | Builds VitePress and deploys to GitHub Pages |

`sipora-api` includes HTTP e2e tests in `bins/sipora-api/tests/api_http_e2e.rs`. Postgres-backed API tests live in `bins/sipora-api/tests/api_postgres_e2e.rs` and run when **`DATABASE_URL`** is set (integration job sets this).

## Matching CI strictly

To mirror the `Check` job’s warning policy:

```sh
RUSTFLAGS=-Dwarnings cargo clippy --workspace --all-targets -- -D warnings
```

## HTTP API tests

`sipora-api` is structured as a library plus binary. In-process tests import `sipora_api::router` to exercise the real Axum application without spawning a separate process. Keep shared API test helpers in **`tests/support/mod.rs`** only (avoid duplicate `mod support` paths).

## Integration and SIPp

See [qualification](/qualification) for SIPp usage, load script notes, and DNS considerations on Docker or WSL. SIP scenarios and helper scripts live under **`tests/sipp/`**.

## Releases and changelog

Process and tagging: [releasing](/RELEASING). Per-release notes: [changelog](/project/changelog).

## Editing this documentation site

See [documentation site](/developer/documentation-site).
