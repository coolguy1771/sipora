# Integration qualification

CI runs `cargo test --workspace` without external services. Use this checklist for Postgres, Valkey (Redis-compatible), and SIP exercises before calling a release production-ready.

## 1. Local stack

From the repository root:

```sh
docker compose -f tests/docker-compose.yml up -d postgres valkey
```

Wait for health checks, then apply SQL migrations in lexical order:

```sh
export DATABASE_URL="postgres://sipora:test_only_not_production@127.0.0.1:5432/sipora_test"
cargo run -p sipora-migrate -- --database-url "$DATABASE_URL"
```

Use the same `DATABASE_URL` pattern in `SIPORA__POSTGRES__URL` (or your config) for binaries that talk to PostgreSQL. Point `redis.nodes` at `redis://127.0.0.1:6379/0` (or the cluster URL your `sipora.toml` expects); Valkey speaks the Redis protocol, so `redis://` URLs remain correct.

## 2. Binaries

- **sipora-api**: confirm `GET /health` and authenticated `/api/v1/*` routes against the migrated schema.
- **sipora-proxy** / **sipora-edge** / **sipora-lb**: run with a valid `sipora.toml` and exercise with a SIP client or [SIPp](https://sipp.sourceforge.net/) scenarios under `tests/sipp/` (see scripts there).
- **sipora-b2bua**: set `[b2bua].downstream` to a reachable `host:port`, then send INVITE to `sip_udp_port`; downstream must echo responses so the relay can map by `Call-ID` (same constraint as the load balancer).

## 3. Automated integration job

GitHub Actions workflow `.github/workflows/integration.yml` starts PostgreSQL 18 and Valkey 9 service containers, applies `migrations/*.sql`, and runs `cargo test --workspace`. It does not replace full SIP interop testing.
