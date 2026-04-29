# Configuration

Authoritative reference for the shared **`SiporaConfig`** shape loaded by every binary (implementation: `crates/sipora-core/src/config.rs`).

All Sipora binaries deserialize the same structure, `SiporaConfig`, from that module.

## Sources and precedence

1. **File**: the `config` crate loads optional TOML/YAML. The path is chosen by `--config` / `SIPORA_CONFIG` (see [CLI flags](#cli-flags)): default stem `sipora`, another stem like `prod`, or an explicit file path.
2. **Environment**: variables with prefix `SIPORA` and nested segments separated by `__`, matching the serde field path (for example `SIPORA__POSTGRES__URL`, `SIPORA__AUTH__API_BEARER_TOKEN`).

Later sources override earlier ones per the `config` crate rules.

### Defaults with no `sipora.toml`

If no config file is present (and you rely only on defaults plus optional `SIPORA__*` overrides), deserialization still succeeds. Built-in defaults include:

- **`redis.nodes`**: `["redis://127.0.0.1:6379"]`
- **`postgres.url`**: `postgres://127.0.0.1:5432/sipora`
- **`b2bua.downstream`**: `127.0.0.1:5060` (lab-oriented; override in production)

Services must still be reachable where a binary connects (Redis for edge/proxy, Postgres for API when not using the mock store, etc.).

## CLI flags

Each binary accepts:

- `--config` / `SIPORA_CONFIG` (default `sipora`): passed to `SiporaConfig::load_from_config_input`. Use a **stem** (e.g. `prod` loads `prod.toml` / `prod.yaml` via the `config` crate) or a **path** to a specific file (e.g. `./configs/sipora.toml`, or any path containing `/`, `\\`, or ending in `.toml`/`.yaml`/`.yml`). Environment `SIPORA__*` still merges on top.

`sipora-api` also accepts:

- `--port` / `SIPORA_API_PORT` (default `8080`): HTTP listen port. This is separate from `general.health_port` in `SiporaConfig`.
- `--mock-store` / `SIPORA_API_MOCK_STORE` (default **true**): in-memory store so the API starts without Postgres; set `SIPORA_API_MOCK_STORE=false` when the database is up and migrated (the CLI flag does not take a `false` argument).

`sipora-migrate` also accepts:

- `--database-url` / `DATABASE_URL`: PostgreSQL URL. If unset, uses merged `postgres.url` (set `SIPORA__POSTGRES__URL` or `postgres.url` in a config file).

## Sections

### `general`

| Field | Meaning |
|-------|---------|
| `domain` | SIP domain / tenant identity (default `example.com`) |
| `sip_udp_port` | Plain SIP UDP port (default `5060`) |
| `sips_port` | SIPS port (default `5061`) |
| `wss_port` | WSS port (default `443`) |
| `outbound_port` | Outbound signaling port (default `5065`) |
| `health_port` | Health/metrics-style port in config (default `8080`; not always the process listen port) |

### `tls`

TLS policy hints: minimum version, mTLS for trunks, OCSP stapling, certificate renewal threshold, ACME provider name.

### `rate_limit`

Per-method style limits and block thresholds (registrations, invites, dialogs, block window and cooldown).

### `registrar`

Registration timers: min/max/default expires, nonce TTL.

### `proxy`

SIP proxy behavior: `max_forwards`, forking, trace header name, location lookup timeout.

### `b2bua`

Used by `sipora-b2bua` only:

| Field | Meaning |
|-------|---------|
| `downstream` | `host:port` of the downstream SIP peer (B-leg); defaults to `127.0.0.1:5060` if unset. |

### `auth`

Digest and HTTP/JWT-oriented settings: nonce TTL and length, optional `jwks_url`, auth timeout, optional `jwt_expected_issuer` and `jwt_expected_audience`, and optional `api_bearer_token` for `sipora-api` provisioning routes.

Do **not** commit real bearer tokens. Set `SIPORA__AUTH__API_BEARER_TOKEN` in production.

### `redis`

| Field | Meaning |
|-------|---------|
| `nodes` | Redis URLs (defaults to `redis://127.0.0.1:6379` if omitted) |
| `cluster_mode` | Cluster vs single-node |
| `max_call_s` | Call duration cap for session state |

### `upstreams`

| Field | Meaning |
|-------|---------|
| `lb_sip_proxies` | UDP `host:port` list for `sipora-lb` backend SIP proxies (empty by default) |

### `postgres`

| Field | Meaning |
|-------|---------|
| `url` | PostgreSQL connection URL (defaults to `postgres://127.0.0.1:5432/sipora` if omitted) |
| `max_pool_size` | Pool size |
| `cdr_retention_months` | CDR retention policy (months) |

Prefer supplying credentials via `SIPORA__POSTGRES__URL` rather than checked-in files.

### `telemetry`

OpenTelemetry OTLP endpoint, service name, metrics interval, success trace sample rate.

### `media`

RTPengine host, allowed codec names, SRTP requirement, RTP timeout.

## Example files

See `examples/config/*.example.toml` for full TOML examples per binary.
