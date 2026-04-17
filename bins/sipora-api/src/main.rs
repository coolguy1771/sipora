mod auth;
mod openapi;
mod routes;
mod store;

use anyhow::Result;
use axum::Router;
use axum::middleware;
use axum::routing::get;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(Parser)]
#[command(name = "sipora-api", about = "SIP platform REST provisioning API")]
struct Cli {
    #[arg(long, env = "SIPORA_CONFIG", default_value = "sipora")]
    config: String,
    #[arg(long, env = "SIPORA_API_PORT", default_value = "8080")]
    port: u16,
    /// Use an in-memory store (default: true so the API starts without Postgres). Set false when DB is up.
    #[arg(long, env = "SIPORA_API_MOCK_STORE", default_value_t = true)]
    mock_store: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let config = sipora_core::config::SiporaConfig::load_from_config_input(&cli.config)?;

    let _telemetry = sipora_core::telemetry::init_telemetry(
        "sipora-api",
        &config.telemetry.otlp_endpoint,
        config.telemetry.metrics_interval_s,
        config.telemetry.success_sample_rate,
    )?;

    let state = if cli.mock_store {
        tracing::warn!(
            "sipora-api: SIPORA_API_MOCK_STORE enabled; using ephemeral in-memory data (not for production)"
        );
        Arc::new(store::AppState {
            domain: config.general.domain.clone(),
            api_bearer_token: config.auth.api_bearer_token.clone(),
            store: store::new_mock_store(),
            store_kind: store::DataStoreKind::Mock,
        })
    } else {
        let pool = sipora_data::pg::connect_pool(&config.postgres)
            .await
            .map_err(|e| anyhow::anyhow!("postgres: {e}"))?;
        sipora_data::pg::verify_provisioning_schema(&pool)
            .await
            .map_err(|e| anyhow::anyhow!("postgres schema: {e}"))?;
        Arc::new(store::AppState {
            domain: config.general.domain.clone(),
            api_bearer_token: config.auth.api_bearer_token.clone(),
            store: store::ApiStore::Postgres(pool),
            store_kind: store::DataStoreKind::Postgres,
        })
    };

    if state.api_bearer_token.is_none() {
        tracing::warn!(
            "sipora-api: no auth.api_bearer_token set; /api/* returns 403 until configured"
        );
    }

    const BODY_LIMIT: usize = 256 * 1024;

    let app = Router::new()
        .route("/health", get(routes::health))
        .route("/ready", get(routes::ready))
        .route(
            "/api/v1/users",
            get(routes::list_users).post(routes::create_user),
        )
        .route("/api/v1/users/{id}", get(routes::get_user))
        .route("/api/v1/cdrs", get(routes::query_cdrs))
        .merge(
            SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi::ApiDoc::openapi()),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_provisioning_auth,
        ))
        .layer(RequestBodyLimitLayer::new(BODY_LIMIT))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_CONTENT_TYPE_OPTIONS,
            axum::http::HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::X_FRAME_OPTIONS,
            axum::http::HeaderValue::from_static("DENY"),
        ))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    tracing::info!(%addr, "sipora-api listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
