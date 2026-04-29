# Services and binaries

Every runnable binary uses the same configuration type: `sipora_core::config::SiporaConfig`. Field-level documentation is in the [configuration](/configuration) reference.

## Runnable binaries (behavior today)

| Binary | Purpose |
|--------|---------|
| `sipora-api` | Axum HTTP server: `GET /health`, `GET` and `POST /api/v1/users`, `GET /api/v1/users/{id}`, `GET /api/v1/cdrs`, plus OpenAPI/Swagger routes as implemented in-tree. |
| `sipora-b2bua` | UDP SIP on `sip_udp_port` toward `[b2bua].downstream`; INVITE applies codec policy to SDP; optional CDR export; health on `health_port`. |
| `sipora-edge` | SIP over TLS/TCP on `sips_port` with firewall and Redis rate limits; health on `health_port`. |
| `sipora-lb` | UDP SIP load balancer to upstream proxies; health on `health_port`. |
| `sipora-migrate` | Applies SQL in `migrations/` to Postgres (`--database-url` or merged `postgres.url`). |
| `sipora-proxy` | UDP SIP on `sip_udp_port`, Redis-backed registrar/redirect; health on `health_port`. |

### `sipora-api` HTTP details

- Listens on `0.0.0.0` and port from `--port` or `SIPORA_API_PORT` (default **8080**). This port is separate from `general.health_port` in shared config when both appear in docs.
- **Mock store:** `--mock-store` / `SIPORA_API_MOCK_STORE` defaults to **true** so the API starts without Postgres. Set `SIPORA_API_MOCK_STORE=false` when Postgres is up and migrated. The CLI flag enables the mock store; it does not take `false` as an argument (use the environment variable to disable the mock).
- **Auth:** Provisioning routes under `/api/*` require `Authorization: Bearer <token>` when `auth.api_bearer_token` is set in merged configuration. If it is unset, `/api/*` returns **403** (fail closed). `/health` (and readiness/OpenAPI routes as implemented) stay available without that bearer.

### SIP path expectations

For REGISTER, location, OPTIONS, and the current UDP proxy INVITE behavior versus full stateful INVITE and response relay, see [architecture](/developer/architecture) and [qualification](/qualification).

## Repository paths (`bins/`)

| Path | Role |
|------|------|
| `bins/sipora-api` | HTTP REST API for provisioning-style endpoints |
| `bins/sipora-b2bua` | UDP B2BUA toward `[b2bua].downstream`; INVITE SDP codec filter; optional CDR export; see [stability](/stability) for GA intent |
| `bins/sipora-edge` | Edge-oriented entrypoint (TLS, rate limiting, firewall primitives) |
| `bins/sipora-lb` | SIP-aware load balancer warm-up and selection logic |
| `bins/sipora-migrate` | Applies embedded PostgreSQL migrations from `migrations/` |
| `bins/sipora-proxy` | SIP proxy, registrar, and redirect-oriented logic |
