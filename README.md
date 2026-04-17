# Sipora

Sipora is a Rust workspace for a SIP platform: libraries for SIP messaging, SDP, transports, authentication, media, and data access, plus runnable services (proxy, B2BUA, edge, load balancer, REST API). The codebase is under active development. **[Versioning and 1.0 scope](docs/stability.md)** describe which binaries and crates are intended to be GA versus experimental.

## Requirements

- Rust toolchain (edition 2024; stable with current `Cargo.lock`)
- PostgreSQL and Redis for production-style deployments (see configuration)
- Optional: Docker Compose under `tests/` for local Postgres, Redis, and Grafana stack (Mimir, Tempo, Loki, Alloy)

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs these checks on push and pull requests (see `.github/workflows/ci.yml`). Integration checks with Postgres and Redis run via `.github/workflows/integration.yml`. Release tags trigger `.github/workflows/release.yml`. See [CHANGELOG.md](CHANGELOG.md) and [docs/RELEASING.md](docs/RELEASING.md).

## Workspace layout

| Path | Role |
|------|------|
| `bins/sipora-proxy` | SIP proxy, registrar, and redirect-oriented logic |
| `bins/sipora-b2bua` | UDP B2BUA toward `[b2bua].downstream`; INVITE SDP codec filter; optional CDR export; see [stability](docs/stability.md) |
| `bins/sipora-edge` | Edge-oriented entrypoint (TLS, rate limiting, firewall primitives in `sipora-edge`) |
| `bins/sipora-lb` | SIP-aware load balancer warm-up and selection logic |
| `bins/sipora-api` | HTTP REST API for provisioning-style endpoints |
| `bins/sipora-migrate` | Applies embedded PostgreSQL migrations from `migrations/` |
| `crates/sipora-core` | Shared configuration, telemetry, health, Redis key helpers |
| `crates/sipora-sip` | SIP parsing, serialization, transactions, dialog types |
| `crates/sipora-sdp` | SDP session handling |
| `crates/sipora-transport` | TCP, TLS, WebSocket transport pieces |
| `crates/sipora-auth` | Digest, JWT, nonce, TURN-related auth helpers |
| `crates/sipora-location` | Location service glue |
| `crates/sipora-data` | PostgreSQL and CDR-related data access |
| `crates/sipora-media` | SRTP and RTPengine-oriented helpers |
| `crates/sipora-edge` | Firewall and rate-limit building blocks |

## Runnable binaries

Each binary reads the same configuration type (`sipora_core::config::SiporaConfig`). Details and environment overrides are in [docs/configuration.md](docs/configuration.md).

| Binary | Purpose (current code) |
|--------|-------------------------|
| `sipora-proxy` | UDP SIP on `sip_udp_port`, Redis-backed registrar/redirect; health on `health_port` |
| `sipora-b2bua` | UDP SIP on `sip_udp_port` toward `[b2bua].downstream`; INVITE applies codec policy to SDP; health on `health_port` |
| `sipora-edge` | SIP over TLS/TCP on `sips_port` with firewall and Redis rate limits; health on `health_port` |
| `sipora-lb` | UDP SIP load balancer to upstream proxies; health on `health_port` |
| `sipora-api` | Axum HTTP server: `GET /health`, `GET|POST /api/v1/users`, `GET /api/v1/users/{id}`, `GET /api/v1/cdrs` |
| `sipora-migrate` | Applies SQL in `migrations/` to Postgres (`--database-url` or `postgres.url`) |

`sipora-api` listens on `0.0.0.0` and port from `--port` or `SIPORA_API_PORT` (default `8080`). By default it uses an **in-memory mock store** (`--mock-store` / `SIPORA_API_MOCK_STORE` default true) so it starts without Postgres; pass `false` to use `postgres.url`. Provisioning routes under `/api/*` require `Authorization: Bearer <token>` when `auth.api_bearer_token` is set; if it is unset, `/api/*` returns 403 (fail closed). `/health` is unauthenticated.

## Configuration examples

Per-binary example TOML files live in `examples/config/`:

- `sipora-proxy.example.toml`
- `sipora-b2bua.example.toml`
- `sipora-edge.example.toml`
- `sipora-lb.example.toml`
- `sipora-api.example.toml`

Use `sipora.toml` in the working directory by default, or set `--config` / `SIPORA_CONFIG` to another stem (e.g. `prod` for `prod.toml`) or a path to a `.toml` file. Override fields with `SIPORA__*` variables (see [docs/configuration.md](docs/configuration.md)).

## Database migrations

SQL migrations are in `migrations/` (PostgreSQL). Apply them with the **`sipora-migrate`** tool (SQLx-embedded, same files CI uses):

```sh
cargo run -p sipora-migrate -- --database-url "$DATABASE_URL"
```

`--database-url` or `DATABASE_URL` overrides `postgres.url` from config; otherwise configure `postgres.url` or `SIPORA__POSTGRES__URL`. For broader checks with Postgres and Redis, see [docs/qualification.md](docs/qualification.md).

## Observability

- OpenTelemetry: binaries call `sipora_core::telemetry::init_telemetry` with OTLP endpoint and sampling from config (`telemetry` section).
- `tests/docker-compose.yml` wires Grafana Alloy to Mimir, Tempo, and Loki for local stacks; dashboards and alerting rules are under `deploy/grafana/`.

## Deployment

- **Helm**: `deploy/helm/` (chart `sipora`, values in `values.yaml`, `values-dev.yaml`, `values-prod.yaml`). Templates set `SIPORA__*` environment variables and mount database URLs from secrets where applicable.
- **Docker**: `deploy/docker/Dockerfile.<binary>` for each published binary; CI builds these images without pushing.

## License

Apache-2.0 (see workspace `Cargo.toml`).
