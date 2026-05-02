# Secrets

These files are read by Docker Compose as Docker secrets (`/run/secrets/<name>` inside containers).

**Create each file before starting the stack:**

```sh
# Strong random password for PostgreSQL
openssl rand -base64 32 > postgres_password

# Strong random password for Valkey
openssl rand -base64 32 > valkey_password

# Bearer token for sipora-api provisioning endpoints
openssl rand -base64 48 > api_bearer_token

# Full PostgreSQL connection URL (used by sipora-migrate)
# Format: postgres://user:password@postgres:5432/dbname?sslmode=disable
echo "postgres://sipora:$(cat postgres_password)@postgres:5432/sipora?sslmode=disable" > db_url

# Grafana admin password (observability overlay only)
openssl rand -base64 24 > grafana_admin_password
```

Files in this directory are excluded from git (see `.gitignore`).
In CI/CD, inject secrets via your secrets manager (Vault, AWS SM, GitHub Secrets) rather than committing files.
