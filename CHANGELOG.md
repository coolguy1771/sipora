# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `sipora-migrate` binary: applies embedded PostgreSQL migrations from `migrations/` via SQLx.
- `SiporaConfig::load_from_config_input`: `--config` / `SIPORA_CONFIG` now selects config stem, path, or filename (see `docs/configuration.md`).
- `sipora-b2bua` UDP signaling: binds `general.sip_udp_port`, relays to `[b2bua].downstream`, applies codec policy to INVITE SDP, relays responses by `Call-ID` (same pattern as `sipora-lb`).
- `[b2bua]` config section with required `downstream` (`crates/sipora-core/src/config.rs`).
- Documentation for versioning scope (`docs/stability.md`), release process (`docs/RELEASING.md`), and manual integration qualification (`docs/qualification.md`).
- `#[non_exhaustive]` on public error enums and `TransportType` for semver-friendly extension.
- GitHub Actions workflow for integration checks with Postgres and Redis (`integration.yml`).
- GitHub Actions workflow for release verification on version tags (`release.yml`).

### Changed

- `sipora-b2bua` is part of the v1 GA surface per `docs/stability.md`; startup requires `[b2bua].downstream`.

## [0.1.0] - TBD

Initial tracked release baseline (workspace version `0.1.0` in `Cargo.toml`). Set the date when the first git tag is published. Add compare links here once the repository URL is fixed.
