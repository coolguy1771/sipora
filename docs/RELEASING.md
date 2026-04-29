# Releasing

Release steps and tagging expectations below are **authoritative**; keep automation and contributor docs aligned with this file when processes change.

## Version source

The workspace version lives in the root `Cargo.toml` (one level above `docs/`) under `[workspace.package].version`. Bump it on a dedicated commit before tagging.

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
- **Integration** (`.github/workflows/integration.yml`) runs migrations and `cargo test` against Postgres and Valkey.
- **Dependency Review** (`.github/workflows/dependency-review.yml`) runs on pull requests.
- **Release** (`.github/workflows/release.yml`) runs on `v*.*.*` tags and:
  - Verifies fmt, clippy, tests, and a release build.
  - Publishes a **GitHub Release** with per-binary `tar.gz` archives, `SHA256SUMS`, and release notes.
  - Attaches **SLSA Level 3 generic provenance** (OpenSSF `slsa-github-generator`) for those assets.
  - Builds and pushes **OCI images** to **GHCR** (`ghcr.io/<owner>/<repo>/<binary>:<tag>` and `:latest`) with BuildKit **SBOM** and **provenance** attestations, then **keyless Cosign** signatures.

First-time GHCR users: ensure the repository (or org) allows **GitHub Actions** to publish packages (Settings > Actions > General > Workflow permissions, and package visibility for each image if the repo is private).

Crates.io publishing is not configured; add `cargo publish` steps per crate if you begin publishing libraries.

## Container images

Dockerfiles live under `deploy/docker/`. **Tag pushes** publish to GHCR via the release workflow. **CI** still builds images without pushing for pull requests and `main` pushes.
