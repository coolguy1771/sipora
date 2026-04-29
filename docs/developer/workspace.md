# Workspace layout

The repository is a Cargo workspace. Published-style binaries live under **`bins/`**; shared crates live under **`crates/`**. Version and packaging metadata for the workspace live in the root **`Cargo.toml`** (`[workspace.package]`).

Authoritative **runtime behavior** (ports, HTTP paths, SIP roles) is documented under [services and binaries](/user/services-and-binaries); this page maps **source paths**.

## Binaries (`bins/`)

| Path | Purpose |
|------|---------|
| `bins/sipora-api` | Axum HTTP server: health, OpenAPI/Swagger, provisioning routes under `/api/v1/*` |
| `bins/sipora-b2bua` | UDP B2BUA; downstream target from `[b2bua].downstream`; INVITE SDP codec filtering |
| `bins/sipora-edge` | Edge entry (TLS/TCP paths); firewall and Redis-backed rate limits |
| `bins/sipora-lb` | UDP SIP load balancer and warm-up selection |
| `bins/sipora-migrate` | SQLx-embedded migration runner for `migrations/` |
| `bins/sipora-proxy` | UDP SIP proxy/registrar/redirect-oriented path |

## Crates (`crates/`)

| Crate | Responsibility |
|-------|----------------|
| `sipora-core` | Shared configuration, telemetry, health, Redis key helpers |
| `sipora-sip` | SIP parsing, serialization, transaction/dialog scaffolding |
| `sipora-sdp` | SDP session handling |
| `sipora-transport` | TCP, TLS, WebSocket transport pieces |
| `sipora-auth` | Digest, JWT, nonce, TURN-related helpers |
| `sipora-data` | PostgreSQL and CDR-oriented data access |
| `sipora-media` | SRTP and RTPengine-oriented helpers |
| `sipora-location` | Location service glue |
| `sipora-edge` | Firewall and rate-limit building blocks |

## Other important paths

- **`migrations/`** — PostgreSQL schema and data migrations consumed by `sipora-migrate`.
- **`tests/`** — Integration helpers, Docker Compose, SIPp scenarios (`tests/sipp/`).
- **`deploy/helm/`** — Kubernetes chart and environment values.
- **`deploy/docker/`** — Per-binary Dockerfiles used in CI builds.
- **`examples/config/`** — Example TOML stems for each binary (see [configuration files](/user/configuration-files)).

The root **`Cargo.toml`** defines workspace members and shared metadata.
