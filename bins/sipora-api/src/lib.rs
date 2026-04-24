//! HTTP API for Sipora provisioning. The library entrypoint exists so
//! integration tests can exercise the Axum [`Router`] without a subprocess.

mod auth;
mod openapi;
mod routes;
pub mod store;

use axum::Router;
use axum::middleware;
use axum::routing::get;
use std::sync::Arc;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

pub use store::{ApiStore, AppState, DataStoreKind, new_mock_store};

/// Build the full HTTP service graph (routes, auth middleware, Swagger UI).
pub fn router(state: Arc<AppState>) -> Router {
    const BODY_LIMIT: usize = 256 * 1024;

    Router::new()
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
        .with_state(state)
}
