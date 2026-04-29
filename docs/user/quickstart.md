# Quickstart

## Prerequisites

- **Rust** toolchain matching the workspace (edition 2024; use the lockfile with stable Rust).
- **PostgreSQL 18** and **Valkey 9** when running with real stores (API with `SIPORA_API_MOCK_STORE=false`, proxy/edge with Redis, migrated schema for digest users).
- Optional: **Docker** for compose-based Postgres, Valkey, and Grafana-related stacks under `tests/`.

## Clone and build

```sh
git clone <repository-url>
cd sipora
cargo build --workspace
```

Run the same checks CI uses before pushing changes:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Configuration

See [configuration files](/user/configuration-files) for example TOML names and how `sipora.toml` / `SIPORA_CONFIG` / `SIPORA__` overrides work. Full field reference: [configuration](/configuration).

## Run the HTTP API locally

The API listens on `0.0.0.0` and port from `--port` or `SIPORA_API_PORT` (default `8080`). With the default in-memory mock store you can start without Postgres:

```sh
cargo run -p sipora-api --
```

Set `SIPORA__AUTH__API_BEARER_TOKEN` when calling `/api/*` routes that require a bearer token; if `auth.api_bearer_token` is configured in merged config and you omit `Authorization`, those routes return 403. `/health` stays unauthenticated. More detail: [services and binaries](/user/services-and-binaries).

## Apply database migrations

When using Postgres:

```sh
export DATABASE_URL="postgres://USER:PASS@HOST:5432/DBNAME"
cargo run -p sipora-migrate -- --database-url "$DATABASE_URL"
```

Alternatively set `postgres.url` or `SIPORA__POSTGRES__URL` and omit `--database-url` when it matches your target database. Ongoing schema policy: [database](/user/database).

## Next steps

- Align ports and domains with [configuration](/configuration).
- Exercise SIP paths with [qualification](/qualification) and SIPp assets under `tests/sipp/`.
- Plan installs with [deployment](/user/deployment) (Helm under `deploy/helm/`, Dockerfiles under `deploy/docker/`).
