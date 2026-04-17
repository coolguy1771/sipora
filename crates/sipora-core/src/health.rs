use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

pub trait HealthCheck: Send + Sync + 'static {
    fn is_ready(&self) -> impl Future<Output = bool> + Send;
}

struct HealthState<H: HealthCheck> {
    checker: H,
}

pub async fn serve_health<H: HealthCheck>(
    addr: SocketAddr,
    checker: H,
    shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let state = Arc::new(HealthState { checker });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler::<H>))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "health server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await
}

async fn health_handler() -> impl IntoResponse {
    StatusCode::OK
}

async fn ready_handler<H: HealthCheck>(
    state: axum::extract::State<Arc<HealthState<H>>>,
) -> impl IntoResponse {
    if state.checker.is_ready().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn shutdown_signal(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}
