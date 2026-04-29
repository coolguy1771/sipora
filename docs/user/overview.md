# User overview

Sipora is a Rust workspace for a SIP platform: libraries for SIP messaging, SDP, transports, authentication, media, and data access, plus runnable network services. The project is **0.x** until an explicit **1.0** release; see [stability and versioning](/stability) for GA targets and semver expectations.

**This documentation site is the canonical source** for operators and integrators. Use the sections below instead of duplicating notes in wikis or README fragments.

## Requirements

- **Rust** toolchain (edition **2024**; stable Rust with the workspace `Cargo.lock`).
- **PostgreSQL 18** and **Valkey 9** for production-style deployments (client configuration still uses **`redis://`** URLs where applicable because Valkey speaks the Redis protocol).
- Optional: **Docker** and **`tests/docker-compose.yml`** for local Postgres, Valkey, and Grafana-related stacks (Mimir, Tempo, Loki, Alloy).

## Where to read next

1. [Quickstart](/user/quickstart) — clone, build, minimal API and migrate path.
2. [Services and binaries](/user/services-and-binaries) — ports, HTTP routes, SIP roles.
3. [Configuration files](/user/configuration-files) — example TOML paths and `SIPORA__` overrides.
4. [Configuration](/configuration) — full `SiporaConfig` reference.
5. [Database](/user/database) — migrations with `sipora-migrate`.
6. [Observability](/user/observability) — OpenTelemetry and local Grafana assets.
7. [Deployment](/user/deployment) — Helm and Docker layouts.
8. [Qualification](/qualification) — Postgres, Valkey, SIPp, and integration job scope.

Contributors should also read the [developer workspace](/developer/workspace) layout and [architecture](/developer/architecture) notes.
