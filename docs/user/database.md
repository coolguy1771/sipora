# Database and migrations

Sipora uses **PostgreSQL** for persistent data (users, digest HA1, CDRs where enabled, and related tables). Schema changes ship as SQL files under the repository directory **`migrations/`**.

## Applying migrations

Use the **`sipora-migrate`** binary (SQLx-embedded; same files CI applies):

```sh
cargo run -p sipora-migrate -- --database-url "$DATABASE_URL"
```

`--database-url` or **`DATABASE_URL`** overrides merged `postgres.url`. Otherwise set `postgres.url` in config or `SIPORA__POSTGRES__URL`.

## Qualification

For a full local stack (Postgres, Valkey, SIP checks) before production, follow [qualification](/qualification).
