use anyhow::{Context, Result};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;

#[derive(Parser)]
#[command(
    name = "sipora-migrate",
    about = "Apply embedded PostgreSQL migrations (see /migrations in the repository root)"
)]
struct Cli {
    #[arg(long, env = "SIPORA_CONFIG", default_value = "sipora")]
    config: String,
    /// Postgres URL. Defaults to `postgres.url` from the merged Sipora config.
    #[arg(long, env = "DATABASE_URL")]
    database_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = sipora_core::config::SiporaConfig::load_from_config_input(&cli.config)
        .map_err(|e| anyhow::anyhow!("config: {e}"))?;
    let url = cli.database_url.unwrap_or(cfg.postgres.url);
    if url.is_empty() {
        anyhow::bail!(
            "no database URL: set --database-url, DATABASE_URL, or SIPORA__POSTGRES__URL, or postgres.url in config"
        );
    }

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .with_context(|| "connect postgres")?;

    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .context("run migrations")?;

    println!("sipora-migrate: migrations applied successfully");
    Ok(())
}
