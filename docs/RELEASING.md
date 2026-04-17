# Releasing

## Version source

The workspace version lives in the root [`Cargo.toml`](../Cargo.toml) under `[workspace.package].version`. Bump it on a dedicated commit before tagging.

## Pre-release checks

Run the same commands as CI locally:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Optional: run [qualification](qualification.md) with Postgres, Redis, and SIP tooling. Apply schema changes with `cargo run -p sipora-migrate -- --database-url "$DATABASE_URL"` before or between releases.

## Tagging

1. Update `CHANGELOG.md`: move items from **Unreleased** to a dated section for the new version.
2. Commit the version bump and changelog.
3. Create an annotated tag: `git tag -a v0.1.1 -m "Release v0.1.1"` (example).
4. Push the tag: `git push origin v0.1.1`.

## Automation

- **CI** (`.github/workflows/ci.yml`) runs on every push and pull request.
- **Release** (`.github/workflows/release.yml`) runs on `v*` tags and performs a full release build (`cargo build --release --workspace`) to verify the tree is releasable.

Crates.io publishing is not configured; add `cargo publish` steps per crate if you begin publishing libraries.

## Container images

Dockerfiles live under `deploy/docker/`. CI builds images without pushing; wire your registry and `docker push` in your deployment pipeline when ready.
